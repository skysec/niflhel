package filecopy

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCopyAndEscape(t *testing.T) {
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "hello"), []byte("world"), 0644)
	var b bytes.Buffer
	if e := Archive(src, ".", &b); e != nil {
		t.Fatal(e)
	}
	dst := t.TempDir()
	if e := Extract(dst, ".", &b); e != nil {
		t.Fatal(e)
	}
	v, _ := os.ReadFile(filepath.Join(dst, "hello"))
	if string(v) != "world" {
		t.Fatal(string(v))
	}
	outside := t.TempDir()
	os.Symlink(outside, filepath.Join(dst, "link"))
	b.Reset()
	tw := tar.NewWriter(&b)
	tw.WriteHeader(&tar.Header{Name: "link/escape", Mode: 0644, Size: 1})
	tw.Write([]byte("x"))
	tw.Close()
	if e := Extract(dst, ".", &b); e == nil {
		t.Fatal("symlink parent followed")
	}
	if _, e := os.Stat(filepath.Join(outside, "escape")); !os.IsNotExist(e) {
		t.Fatal("escaped root")
	}
	b.Reset()
	tw = tar.NewWriter(&b)
	tw.WriteHeader(&tar.Header{Name: "../escape", Mode: 0644})
	tw.Close()
	if e := Extract(dst, ".", &b); e == nil {
		t.Fatal("traversal accepted")
	}
}

func TestExtractConsumesTransportPadding(t *testing.T) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	b.Write(make([]byte, 8192))
	if err := Extract(t.TempDir(), ".", &b); err != nil {
		t.Fatal(err)
	}
	if b.Len() != 0 {
		t.Fatalf("left %d bytes unread", b.Len())
	}
}
