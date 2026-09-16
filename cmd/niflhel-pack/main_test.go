package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"niflhel/internal/oci"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestKernelImageMetadataBound(t *testing.T) {
	body := bytes.Repeat([]byte(" "), int(oci.MaxMetadata)+1)
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", string(types.OCIManifestSchema1))
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer registry.Close()
	ref := strings.TrimPrefix(registry.URL, "http://") + "/test/kernel@sha256:" + strings.Repeat("a", 64)
	e := writeKernelFromImage(context.Background(), ref, filepath.Join(t.TempDir(), "kernel"))
	if e == nil || !strings.Contains(e.Error(), "OCI metadata response limit exceeded") {
		t.Fatalf("oversized kernel metadata was not rejected by the packager limit: %v", e)
	}
}

func TestKernelImageDeadlineCancelsSlowRegistry(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer registry.Close()
	ref := strings.TrimPrefix(registry.URL, "http://") + "/test/kernel@sha256:" + strings.Repeat("a", 64)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	e := writeKernelFromImage(ctx, ref, filepath.Join(t.TempDir(), "kernel"))
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("slow kernel registry was not canceled at the operation deadline: %v", e)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("slow kernel registry cancellation took %s", elapsed)
	}
}

func TestKernelImageAllowsLargeLayer(t *testing.T) {
	payload := make([]byte, int(oci.MaxMetadata)+(64<<10))
	if _, e := rand.Read(payload); e != nil {
		t.Fatal(e)
	}
	var layerBlob bytes.Buffer
	zw := gzip.NewWriter(&layerBlob)
	tw := tar.NewWriter(zw)
	if e := tw.WriteHeader(&tar.Header{Name: "boot/vmlinux", Mode: 0600, Size: int64(len(payload)), Typeflag: tar.TypeReg}); e != nil {
		t.Fatal(e)
	}
	if _, e := tw.Write(payload); e != nil {
		t.Fatal(e)
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	if e := zw.Close(); e != nil {
		t.Fatal(e)
	}
	layer, e := tarball.LayerFromReader(&layerBlob)
	if e != nil {
		t.Fatal(e)
	}
	layerSize, e := layer.Size()
	if e != nil {
		t.Fatal(e)
	}
	if layerSize <= oci.MaxMetadata {
		t.Fatalf("test layer is not larger than the metadata limit: %d", layerSize)
	}
	image, e := mutate.AppendLayers(empty.Image, layer)
	if e != nil {
		t.Fatal(e)
	}
	registry := httptest.NewServer(registry.New())
	defer registry.Close()
	tag, e := name.NewTag(strings.TrimPrefix(registry.URL, "http://") + "/test/kernel:latest")
	if e != nil {
		t.Fatal(e)
	}
	if e = remote.Write(tag, image); e != nil {
		t.Fatal(e)
	}
	digest, e := image.Digest()
	if e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(t.TempDir(), "kernel")
	if e = writeKernelFromImage(context.Background(), tag.Context().Digest(digest.String()).String(), out); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(out)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("kernel payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}
