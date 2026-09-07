package guest

import (
	"archive/tar"
	"bytes"
	"context"
	"niflhel/internal/fsutil"
	"niflhel/internal/oci"
	"os"
	"path/filepath"
	"testing"
)

func carrier(t *testing.T, layers [][]byte) string {
	t.Helper()
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "blobs"), 0700)
	img := oci.Image{}
	for _, b := range layers {
		d := fsutil.Digest(b)
		os.WriteFile(filepath.Join(dir, "blobs", d[7:]), b, 0600)
		img.Layers = append(img.Layers, oci.Descriptor{Digest: d, Size: int64(len(b)), MediaType: "application/vnd.oci.image.layer.v1.tar"})
		img.DiffIDs = append(img.DiffIDs, d)
	}
	fsutil.JSON(filepath.Join(dir, "image.json"), img)
	return dir
}
func layer(name, data string) []byte {
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	w.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))})
	w.Write([]byte(data))
	w.Close()
	return b.Bytes()
}
func TestLayerWhiteoutAndTraversal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	os.Mkdir(root, 0700)
	if e := Unpack(context.Background(), carrier(t, [][]byte{layer("file", "hi"), layer(".wh.file", "")}), root, 1<<20); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(root, "file")); !os.IsNotExist(e) {
		t.Fatal("whiteout not applied")
	}
	if e := Unpack(context.Background(), carrier(t, [][]byte{layer("../escape", "bad")}), root, 1<<20); e == nil {
		t.Fatal("traversal accepted")
	}
	if e := Unpack(context.Background(), carrier(t, [][]byte{layer("file", "big")}), root, 10); e == nil {
		t.Fatal("expansion limit ignored")
	}
}
