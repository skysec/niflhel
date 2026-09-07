package oci

import (
	"archive/tar"
	"bytes"
	"context"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"niflhel/internal/fsutil"
	"os"
	"path/filepath"
	"testing"
)

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
