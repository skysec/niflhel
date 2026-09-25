package oci

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"io"
	"net/http"
	"net/http/httptest"
	"niflhel/internal/fsutil"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestVerifiedAtomic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "blob")
	b := []byte("contents")
	d := Descriptor{Digest: fsutil.Digest(b), Size: int64(len(b))}
	if e := WriteVerified(p, bytes.NewReader([]byte("bad")), d); e == nil {
		t.Fatal("accepted corrupt blob")
	}
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("partial blob published")
	}
	if e := WriteVerified(p, bytes.NewReader(b), d); e != nil {
		t.Fatal(e)
	}
	if e := WriteVerified(p, bytes.NewReader(append(b, 'x')), d); e == nil {
		t.Fatal("oversize accepted")
	}
	actual, _ := os.ReadFile(p)
	if !bytes.Equal(actual, b) {
		t.Fatal("valid blob replaced by invalid download")
	}
}
func TestImportAndOffline(t *testing.T) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	tw.WriteHeader(&tar.Header{Name: "hello", Mode: 0644, Size: 2})
	tw.Write([]byte("hi"))
	tw.Close()
	layer, e := tarball.LayerFromReader(&b)
	if e != nil {
		t.Fatal(e)
	}
	image, e := mutate.AppendLayers(empty.Image, layer)
	if e != nil {
		t.Fatal(e)
	}
	cfg := &v1.ConfigFile{OS: "linux", Architecture: "amd64", RootFS: v1.RootFS{Type: "layers"}, Config: v1.Config{Cmd: []string{"echo", "ok"}}}
	hash, _ := layer.DiffID()
	cfg.RootFS.DiffIDs = []v1.Hash{hash}
	image, e = mutate.ConfigFile(image, cfg)
	if e != nil {
		t.Fatal(e)
	}
	s := New(t.TempDir())
	got, e := s.Import(context.Background(), "local:test", image)
	if e != nil {
		t.Fatal(e)
	}
	cached, e := s.Pull(context.Background(), "local:test", "never", nil)
	if e != nil || cached.Digest != got.Digest {
		t.Fatal(cached, e)
	}
	p, _ := s.Blob(got.Layers[0].Digest)
	os.WriteFile(p, []byte("corrupt"), 0600)
	if _, e = s.Pull(context.Background(), "local:test", "never", nil); e == nil {
		t.Fatal("corrupt cache accepted")
	}
}

func TestMetadataTransportBoundsChunkedBodies(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 17)
	base := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, ContentLength: -1, Body: io.NopCloser(bytes.NewReader(body))}, nil
	})
	transport := NewMetadataTransport(base, 8, 12)
	req, _ := http.NewRequest(http.MethodGet, "http://registry.test/v2/", nil)
	stop := transport.Limit()
	resp, e := transport.RoundTrip(req)
	if e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(resp.Body)
	resp.Body.Close()
	stop()
	if e == nil || len(got) > 9 {
		t.Fatalf("unbounded metadata body: bytes=%d error=%v", len(got), e)
	}
	resp, e = transport.RoundTrip(req)
	if e != nil {
		t.Fatal(e)
	}
	got, e = io.ReadAll(resp.Body)
	resp.Body.Close()
	if e != nil || !bytes.Equal(got, body) {
		t.Fatal(len(got), e)
	}
}

func TestPullRejectsOversizedConfigBeforeFetch(t *testing.T) {
	configHash, _ := v1.NewHash("sha256:" + strings.Repeat("a", 64))
	manifestRaw, _ := json.Marshal(v1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		Config:        v1.Descriptor{MediaType: types.OCIConfigJSON, Digest: configHash, Size: MaxMetadata + 1},
	})
	var configRequests atomic.Int64
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", string(types.OCIManifestSchema1))
			w.Header().Set("Docker-Content-Digest", fsutil.Digest(manifestRaw))
			w.Write(manifestRaw)
		case strings.Contains(r.URL.Path, "/blobs/"):
			configRequests.Add(1)
			w.Write(bytes.Repeat([]byte("x"), int(MaxMetadata)+1))
		default:
			http.NotFound(w, r)
		}
	}))
	defer registry.Close()
	ref := strings.TrimPrefix(registry.URL, "http://") + "/test/image:latest"
	if _, e := New(t.TempDir()).Pull(context.Background(), ref, "always", nil); e == nil {
		t.Fatal("oversized config descriptor accepted")
	}
	if configRequests.Load() != 0 {
		t.Fatal("oversized config was fetched before descriptor admission")
	}
}

func TestLayoutMetadataUsesBoundedDigestBlob(t *testing.T) {
	root := t.TempDir()
	if e := os.WriteFile(filepath.Join(root, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0600); e != nil {
		t.Fatal(e)
	}
	manifestRaw, _ := empty.Image.RawManifest()
	manifestHash, _ := v1.NewHash(fsutil.Digest(manifestRaw))
	indexRaw, _ := json.Marshal(v1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests: []v1.Descriptor{{
			MediaType: types.OCIManifestSchema1,
			Digest:    manifestHash,
			Size:      int64(len(manifestRaw)),
			Data:      manifestRaw,
		}},
	})
	if e := os.WriteFile(filepath.Join(root, "index.json"), indexRaw, 0600); e != nil {
		t.Fatal(e)
	}
	blobDir := filepath.Join(root, "blobs", "sha256")
	if e := os.MkdirAll(blobDir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(blobDir, manifestHash.Hex), bytes.Repeat([]byte("x"), int(MaxMetadata)+1), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadLayoutImage(root); e == nil {
		t.Fatal("inline metadata bypassed the on-disk blob bound")
	}
	if e := os.WriteFile(filepath.Join(root, "index.json"), bytes.Repeat([]byte(" "), int(MaxMetadata)+1), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadLayoutImage(root); e == nil {
		t.Fatal("oversized layout index accepted")
	}
}

func TestLoadLayoutImageControl(t *testing.T) {
	root := t.TempDir()
	if e := os.WriteFile(filepath.Join(root, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0600); e != nil {
		t.Fatal(e)
	}
	fixture, e := mutate.ConfigFile(empty.Image, &v1.ConfigFile{OS: "linux", Architecture: "amd64", RootFS: v1.RootFS{Type: "layers"}})
	if e != nil {
		t.Fatal(e)
	}
	manifestRaw, e := fixture.RawManifest()
	if e != nil {
		t.Fatal(e)
	}
	configRaw, e := fixture.RawConfigFile()
	if e != nil {
		t.Fatal(e)
	}
	manifestHash, _ := v1.NewHash(fsutil.Digest(manifestRaw))
	configHash, _ := v1.NewHash(fsutil.Digest(configRaw))
	blobDir := filepath.Join(root, "blobs", "sha256")
	if e = os.MkdirAll(blobDir, 0700); e != nil {
		t.Fatal(e)
	}
	for _, blob := range []struct {
		hash v1.Hash
		raw  []byte
	}{{manifestHash, manifestRaw}, {configHash, configRaw}} {
		if e = os.WriteFile(filepath.Join(blobDir, blob.hash.Hex), blob.raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	indexRaw, _ := json.Marshal(v1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests: []v1.Descriptor{{
			MediaType: types.OCIManifestSchema1,
			Digest:    manifestHash,
			Size:      int64(len(manifestRaw)),
		}},
	})
	if e = os.WriteFile(filepath.Join(root, "index.json"), indexRaw, 0600); e != nil {
		t.Fatal(e)
	}
	image, e := LoadLayoutImage(root)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = New(t.TempDir()).Import(context.Background(), "layout:test", image); e != nil {
		t.Fatal(e)
	}
}

func TestImportRejectsOversizedDecodedConfig(t *testing.T) {
	cfg := &v1.ConfigFile{OS: "linux", Architecture: "amd64", RootFS: v1.RootFS{Type: "layers"}, Config: v1.Config{Env: []string{"VALUE=" + strings.Repeat("x", int(MaxMetadata))}}}
	image, e := mutate.ConfigFile(empty.Image, cfg)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = New(t.TempDir()).Import(context.Background(), "oversized:test", image); e == nil {
		t.Fatal("oversized decoded config accepted")
	}
}
