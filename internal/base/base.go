// Package base verifies signed infrastructure bundles before they can boot.
package base

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"io"
	"niflhel/internal/api"
	"niflhel/internal/fsutil"
	"niflhel/internal/oci"
	"os"
	"path/filepath"
)

const ArtifactType = "application/vnd.niflhel.base.v1"

type Config struct {
	SchemaVersion       int
	OS                  string
	Architecture        string
	AgentProtocol       int
	InitPath            string
	Runtime             string
	GuestReserveMiB     int64
	FirecrackerVersions []string
	Kernel              oci.Descriptor
	RootFS              oci.Descriptor
}
type Signed struct {
	Config    Config
	KeyID     string
	Signature string
}
type Bundle struct {
	Ref        string
	Digest     string
	Signed     Signed
	KernelPath string
	RootFSPath string
}
type Store struct {
	Root  string
	Trust map[string]string
}

func Validate(c Config) error {
	if c.SchemaVersion != 1 || c.OS != "linux" || c.Architecture != "amd64" || c.AgentProtocol != api.Protocol {
		return fmt.Errorf("incompatible base schema/platform/protocol")
	}
	if c.InitPath != "/sbin/niflhel-init" || c.Runtime != "runc" {
		return fmt.Errorf("unsupported base init/runtime")
	}
	if c.GuestReserveMiB < 64 || c.GuestReserveMiB > 4096 {
		return fmt.Errorf("invalid guest memory reserve")
	}
	if len(c.FirecrackerVersions) == 0 {
		return fmt.Errorf("base must declare qualified Firecracker versions")
	}
	for _, d := range []oci.Descriptor{c.Kernel, c.RootFS} {
		if _, e := fsutil.HexDigest(d.Digest); e != nil {
			return e
		}
		if d.Size <= 0 || d.Size > oci.MaxBlob {
			return fmt.Errorf("invalid base artifact size")
		}
	}
	return nil
}
func Sign(c Config, keyID string, key ed25519.PrivateKey) (Signed, error) {
	if e := Validate(c); e != nil {
		return Signed{}, e
	}
	if len(key) != ed25519.PrivateKeySize {
		return Signed{}, fmt.Errorf("invalid Ed25519 key")
	}
	b, e := json.Marshal(c)
	if e != nil {
		return Signed{}, e
	}
	return Signed{Config: c, KeyID: keyID, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))}, nil
}
func (s Store) Verify(v Signed) error {
	if e := Validate(v.Config); e != nil {
		return e
	}
	pub, e := base64.StdEncoding.DecodeString(s.Trust[v.KeyID])
	if e != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("untrusted base publisher %q", v.KeyID)
	}
	sig, e := base64.StdEncoding.DecodeString(v.Signature)
	if e != nil {
		return e
	}
	b, _ := json.Marshal(v.Config)
	if !ed25519.Verify(ed25519.PublicKey(pub), b, sig) {
		return fmt.Errorf("invalid base signature")
	}
	return nil
}
func (s Store) record(ref string) string {
	return filepath.Join(s.Root, "refs", fsutil.Digest([]byte(ref))[7:]+".json")
}
func (s Store) Get(ref string) (Bundle, error) {
	var b Bundle
	if e := fsutil.ReadJSON(s.record(ref), &b); e != nil {
		return b, e
	}
	if e := s.Verify(b.Signed); e != nil {
		return b, e
	}
	for i, d := range []oci.Descriptor{b.Signed.Config.Kernel, b.Signed.Config.RootFS} {
		p := b.KernelPath
		if i == 1 {
			p = b.RootFSPath
		}
		actual, n, e := fsutil.DigestFile(p)
		if e != nil || actual != d.Digest || n != d.Size {
			return b, fmt.Errorf("corrupt base component %s", d.Digest)
		}
	}
	return b, nil
}
func (s Store) Import(ref string, v Signed, kernel, rootfs string) (Bundle, error) {
	var b Bundle
	if e := s.Verify(v); e != nil {
		return b, e
	}
	b.Ref = ref
	b.Signed = v
	raw, _ := json.Marshal(v)
	b.Digest = fsutil.Digest(raw)
	for i, source := range []string{kernel, rootfs} {
		d := v.Config.Kernel
		if i == 1 {
			d = v.Config.RootFS
		}
		target := filepath.Join(s.Root, "blobs", d.Digest[7:])
		f, e := os.Open(source)
		if e != nil {
			return b, e
		}
		e = oci.WriteVerified(target, f, d)
		f.Close()
		if e != nil {
			return b, e
		}
		if i == 0 {
			b.KernelPath = target
		} else {
			b.RootFSPath = target
		}
	}
	if e := checkKernel(b.KernelPath); e != nil {
		return b, e
	}
	if e := fsutil.JSON(s.record(b.Digest), b); e != nil {
		return b, e
	}
	return b, fsutil.JSON(s.record(ref), b)
}
func checkKernel(p string) error {
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	defer f.Close()
	b := make([]byte, 20)
	if _, e = io.ReadFull(f, b); e != nil {
		return e
	}
	if string(b[:4]) != "\x7fELF" || b[4] != 2 || b[5] != 1 || b[18] != 62 || b[19] != 0 {
		return fmt.Errorf("kernel must be an amd64 ELF vmlinux")
	}
	return nil
}

type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	ArtifactType  string       `json:"artifactType"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}
type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

func (s Store) Pull(ctx context.Context, ref, policy string, auth *authn.AuthConfig) (Bundle, error) {
	if policy != "always" {
		b, e := s.Get(ref)
		if e == nil {
			return b, nil
		}
		if policy == "never" {
			return b, e
		}
	}
	n, e := name.ParseReference(ref)
	if e != nil {
		return Bundle{}, e
	}
	opts := []remote.Option{remote.WithContext(ctx)}
	if auth != nil {
		opts = append(opts, remote.WithAuth(authn.FromConfig(*auth)))
	}
	desc, e := remote.Get(n, opts...)
	if e != nil {
		return Bundle{}, e
	}
	if len(desc.Manifest) > 1<<20 {
		return Bundle{}, fmt.Errorf("manifest too large")
	}
	var m manifest
	if e = json.Unmarshal(desc.Manifest, &m); e != nil {
		return Bundle{}, e
	}
	if m.ArtifactType != ArtifactType || m.SchemaVersion != 2 || len(m.Layers) != 2 {
		return Bundle{}, fmt.Errorf("not a niflhel base artifact")
	}
	if m.Config.Size <= 0 || m.Config.Size > 1<<20 {
		return Bundle{}, fmt.Errorf("invalid base config size")
	}
	readBlob := func(d descriptor) (io.ReadCloser, error) {
		if _, e := fsutil.HexDigest(d.Digest); e != nil {
			return nil, e
		}
		l, e := remote.Layer(n.Context().Digest(d.Digest), opts...)
		if e != nil {
			return nil, e
		}
		return l.Compressed()
	}
	r, e := readBlob(m.Config)
	if e != nil {
		return Bundle{}, e
	}
	raw, e := io.ReadAll(io.LimitReader(r, m.Config.Size+1))
	r.Close()
	if e != nil {
		return Bundle{}, e
	}
	if int64(len(raw)) != m.Config.Size || fsutil.Digest(raw) != m.Config.Digest {
		return Bundle{}, fmt.Errorf("base config integrity failure")
	}
	var signed Signed
	if e = json.Unmarshal(raw, &signed); e != nil {
		return Bundle{}, e
	}
	if e = s.Verify(signed); e != nil {
		return Bundle{}, e
	}
	os.MkdirAll(s.Root, 0700)
	tmp, e := os.MkdirTemp(s.Root, "pull-")
	if e != nil {
		return Bundle{}, e
	}
	defer os.RemoveAll(tmp)
	paths := []string{}
	for i, d := range []oci.Descriptor{signed.Config.Kernel, signed.Config.RootFS} {
		if m.Layers[i].Digest != d.Digest || m.Layers[i].Size != d.Size {
			return Bundle{}, fmt.Errorf("signed base descriptors do not match manifest")
		}
		r, e := readBlob(m.Layers[i])
		if e != nil {
			return Bundle{}, e
		}
		p := filepath.Join(tmp, fmt.Sprint(i))
		e = oci.WriteVerified(p, r, d)
		r.Close()
		if e != nil {
			return Bundle{}, e
		}
		paths = append(paths, p)
	}
	return s.Import(ref, signed, paths[0], paths[1])
}

type rawManifest []byte

func (r rawManifest) RawManifest() ([]byte, error)        { return r, nil }
func (r rawManifest) MediaType() (types.MediaType, error) { return types.OCIManifestSchema1, nil }

type fileLayer struct {
	path string
	d    oci.Descriptor
}

func (f fileLayer) Digest() (v1.Hash, error)             { return v1.NewHash(f.d.Digest) }
func (f fileLayer) DiffID() (v1.Hash, error)             { return f.Digest() }
func (f fileLayer) Size() (int64, error)                 { return f.d.Size, nil }
func (f fileLayer) MediaType() (types.MediaType, error)  { return types.MediaType(f.d.MediaType), nil }
func (f fileLayer) Compressed() (io.ReadCloser, error)   { return os.Open(f.path) }
func (f fileLayer) Uncompressed() (io.ReadCloser, error) { return os.Open(f.path) }
func (s Store) Push(ctx context.Context, ref string, auth *authn.AuthConfig) error {
	b, e := s.Get(ref)
	if e != nil {
		return e
	}
	n, e := name.ParseReference(ref)
	if e != nil {
		return e
	}
	opts := []remote.Option{remote.WithContext(ctx)}
	if auth != nil {
		opts = append(opts, remote.WithAuth(authn.FromConfig(*auth)))
	}
	raw, _ := json.Marshal(b.Signed)
	cfg := static.NewLayer(raw, types.MediaType(ArtifactType+".config+json"))
	if e = remote.WriteLayer(n.Context(), cfg, opts...); e != nil {
		return e
	}
	m := manifest{SchemaVersion: 2, MediaType: string(types.OCIManifestSchema1), ArtifactType: ArtifactType, Config: descriptor{ArtifactType + ".config+json", fsutil.Digest(raw), int64(len(raw))}}
	for i, d := range []oci.Descriptor{b.Signed.Config.Kernel, b.Signed.Config.RootFS} {
		p := b.KernelPath
		if i == 1 {
			p = b.RootFSPath
		}
		if e = remote.WriteLayer(n.Context(), fileLayer{p, d}, opts...); e != nil {
			return e
		}
		m.Layers = append(m.Layers, descriptor{d.MediaType, d.Digest, d.Size})
	}
	raw, _ = json.Marshal(m)
	return remote.Put(n, rawManifest(raw), opts...)
}
func (s Store) List() ([]Bundle, error) {
	out := []Bundle{}
	entries, e := os.ReadDir(filepath.Join(s.Root, "refs"))
	if os.IsNotExist(e) {
		return out, nil
	}
	if e != nil {
		return nil, e
	}
	seen := map[string]bool{}
	for _, p := range entries {
		var b Bundle
		if e = fsutil.ReadJSON(filepath.Join(s.Root, "refs", p.Name()), &b); e != nil {
			return nil, e
		}
		if !seen[b.Ref] {
			seen[b.Ref] = true
			out = append(out, b)
		}
	}
	return out, nil
}
func (s Store) Remove(ref string) error {
	b, e := s.Get(ref)
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
		var other Bundle
		if e = fsutil.ReadJSON(p, &other); e != nil {
			return e
		}
		if other.Digest == b.Digest {
			if e = os.Remove(p); e != nil {
				return e
			}
		} else {
			used[other.KernelPath] = true
			used[other.RootFSPath] = true
		}
	}
	for _, p := range []string{b.KernelPath, b.RootFSPath} {
		if !used[p] {
			if e = os.Remove(p); e != nil && !os.IsNotExist(e) {
				return e
			}
		}
	}
	return nil
}
