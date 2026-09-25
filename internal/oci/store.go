package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"io"
	"niflhel/internal/api"
	"niflhel/internal/fsutil"
	"os"
	"path/filepath"
	"sync"
)

const MaxBlob int64 = 8 << 30
const MaxImage int64 = 16 << 30

type Descriptor struct {
	Digest    string
	Size      int64
	MediaType string
}
type Image struct {
	Ref      string
	Digest   string
	Config   api.ImageConfig
	Layers   []Descriptor
	DiffIDs  []string
	Manifest json.RawMessage
}
type Store struct {
	Root string
	mu   sync.Mutex
}

func New(root string) *Store { return &Store{Root: root} }
func (s *Store) Blob(d string) (string, error) {
	h, e := fsutil.HexDigest(d)
	return filepath.Join(s.Root, "blobs", "sha256", h), e
}
func (s *Store) record(ref string) string {
	return filepath.Join(s.Root, "refs", fsutil.Digest([]byte(ref))[7:]+".json")
}
func (s *Store) Get(ref string) (Image, error) {
	var v Image
	e := fsutil.ReadJSON(s.record(ref), &v)
	if e != nil {
		return v, e
	}
	for _, d := range v.Layers {
		p, e := s.Blob(d.Digest)
		if e != nil {
			return v, e
		}
		actual, n, e := fsutil.DigestFile(p)
		if e != nil || actual != d.Digest || n != d.Size {
			return v, fmt.Errorf("cached blob is missing or corrupt: %s", d.Digest)
		}
	}
	return v, nil
}
func (s *Store) Pull(ctx context.Context, ref, policy string, auth *authn.AuthConfig) (Image, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if policy != "always" {
		v, e := s.Get(ref)
		if e == nil {
			return v, nil
		}
		if policy == "never" {
			return v, fmt.Errorf("offline image unavailable: %w", e)
		}
	}
	n, e := name.ParseReference(ref)
	if e != nil {
		return Image{}, e
	}
	metadata := NewMetadataTransport(remote.DefaultTransport, MaxMetadata, 8*MaxMetadata)
	opts := []remote.Option{remote.WithContext(ctx), remote.WithPlatform(v1.Platform{OS: "linux", Architecture: "amd64"}), remote.WithJobs(2), remote.WithTransport(metadata)}
	if auth != nil {
		opts = append(opts, remote.WithAuth(authn.FromConfig(*auth)))
	}
	stopMetadata := metadata.Limit()
	img, e := remote.Image(n, opts...)
	stopMetadata()
	if e != nil {
		return Image{}, e
	}
	return s.importImage(ctx, ref, img, metadata)
}
func (s *Store) Import(ctx context.Context, ref string, img v1.Image) (Image, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.importImage(ctx, ref, img, nil)
}
func (s *Store) importImage(ctx context.Context, ref string, img v1.Image, metadata *MetadataTransport) (Image, error) {
	var out Image
	out.Ref = ref
	limit := func() func() { return func() {} }
	if metadata != nil {
		limit = metadata.Limit
	}
	stopMetadata := limit()
	raw, e := img.RawManifest()
	stopMetadata()
	if e != nil {
		return out, e
	}
	if int64(len(raw)) > MaxMetadata {
		return out, fmt.Errorf("invalid image manifest")
	}
	var manifest v1.Manifest
	if e = decodeMetadata(raw, &manifest); e != nil {
		return out, e
	}
	if manifest.Config.Size < 0 || manifest.Config.Size > MaxMetadata {
		return out, fmt.Errorf("image config descriptor size limit exceeded")
	}
	if _, e = fsutil.HexDigest(manifest.Config.Digest.String()); e != nil {
		return out, e
	}
	stopMetadata = limit()
	configRaw, e := img.RawConfigFile()
	stopMetadata()
	if e != nil {
		return out, e
	}
	if int64(len(configRaw)) != manifest.Config.Size || fsutil.Digest(configRaw) != manifest.Config.Digest.String() {
		return out, fmt.Errorf("image config descriptor integrity failure")
	}
	var cfg v1.ConfigFile
	if e = decodeMetadata(configRaw, &cfg); e != nil {
		return out, e
	}
	if cfg.OS != "linux" || cfg.Architecture != "amd64" {
		return out, fmt.Errorf("unsupported image platform %s/%s", cfg.OS, cfg.Architecture)
	}
	out.Config = api.ImageConfig{Entrypoint: cfg.Config.Entrypoint, Cmd: cfg.Config.Cmd, Env: cfg.Config.Env, WorkingDir: cfg.Config.WorkingDir, User: cfg.Config.User, StopSignal: cfg.Config.StopSignal, Healthcheck: cfg.Config.Healthcheck != nil}
	for path := range cfg.Config.Volumes {
		out.Config.Volumes = append(out.Config.Volumes, path)
	}
	digest, e := img.Digest()
	if e != nil {
		return out, e
	}
	out.Digest = digest.String()
	if fsutil.Digest(raw) != out.Digest {
		return out, fmt.Errorf("invalid image manifest")
	}
	out.Manifest = raw
	layers, e := img.Layers()
	if e != nil {
		return out, e
	}
	if len(layers) > 256 || len(layers) != len(cfg.RootFS.DiffIDs) {
		return out, fmt.Errorf("invalid layer count")
	}
	var total int64
	for i, l := range layers {
		if e = ctx.Err(); e != nil {
			return out, e
		}
		d, e := l.Digest()
		if e != nil {
			return out, e
		}
		size, e := l.Size()
		if e != nil {
			return out, e
		}
		if size < 0 || size > MaxBlob || total > MaxImage-size {
			return out, fmt.Errorf("image download size limit exceeded")
		}
		total += size
		mt, e := l.MediaType()
		if e != nil {
			return out, e
		}
		desc := Descriptor{Digest: d.String(), Size: size, MediaType: string(mt)}
		p, e := s.Blob(desc.Digest)
		if e != nil {
			return out, e
		}
		existing, n, err := fsutil.DigestFile(p)
		if err != nil || existing != desc.Digest || n != size {
			r, e := l.Compressed()
			if e != nil {
				return out, e
			}
			e = WriteVerified(p, r, desc)
			r.Close()
			if e != nil {
				return out, e
			}
		}
		out.Layers = append(out.Layers, desc)
		out.DiffIDs = append(out.DiffIDs, cfg.RootFS.DiffIDs[i].String())
	}
	if e = fsutil.JSON(s.record(out.Digest), out); e != nil {
		return out, e
	}
	e = fsutil.JSON(s.record(ref), out)
	return out, e
}
func WriteVerified(p string, r io.Reader, d Descriptor) error {
	if _, e := fsutil.HexDigest(d.Digest); e != nil {
		return e
	}
	if d.Size < 0 || d.Size > MaxBlob {
		return fmt.Errorf("blob too large")
	}
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(p), ".download-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	n, e := io.Copy(f, io.LimitReader(r, d.Size+1))
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	h, _, e := fsutil.DigestFile(tmp)
	if e != nil {
		return e
	}
	if n != d.Size || h != d.Digest {
		return fmt.Errorf("blob digest/size mismatch")
	}
	return os.Rename(tmp, p)
}
func (s *Store) List() ([]Image, error) {
	out := []Image{}
	entries, e := os.ReadDir(filepath.Join(s.Root, "refs"))
	if os.IsNotExist(e) {
		return out, nil
	}
	if e != nil {
		return nil, e
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		var v Image
		if e = fsutil.ReadJSON(filepath.Join(s.Root, "refs", entry.Name()), &v); e != nil {
			return nil, e
		}
		if !seen[v.Ref] {
			seen[v.Ref] = true
			out = append(out, v)
		}
	}
	return out, nil
}
func (s *Store) Remove(ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	image, e := s.Get(ref)
	if e != nil {
		return e
	}
	entries, e := os.ReadDir(filepath.Join(s.Root, "refs"))
	if e != nil {
		return e
	}
	used := map[string]bool{}
	for _, entry := range entries {
		p := filepath.Join(s.Root, "refs", entry.Name())
		var other Image
		if e = fsutil.ReadJSON(p, &other); e != nil {
			return e
		}
		if other.Digest == image.Digest {
			if e = os.Remove(p); e != nil {
				return e
			}
		} else {
			for _, layer := range other.Layers {
				used[layer.Digest] = true
			}
		}
	}
	for _, layer := range image.Layers {
		if !used[layer.Digest] {
			p, e := s.Blob(layer.Digest)
			if e != nil {
				return e
			}
			if e = os.Remove(p); e != nil && !os.IsNotExist(e) {
				return e
			}
		}
	}
	return nil
}
func (s *Store) Carrier(dir string, img Image) error {
	if e := os.MkdirAll(filepath.Join(dir, "blobs"), 0700); e != nil {
		return e
	}
	if e := fsutil.JSON(filepath.Join(dir, "image.json"), img); e != nil {
		return e
	}
	for _, d := range img.Layers {
		p, e := s.Blob(d.Digest)
		if e != nil {
			return e
		}
		target := filepath.Join(dir, "blobs", d.Digest[7:])
		if e = os.Link(p, target); e != nil {
			return e
		}
	}
	return nil
}
