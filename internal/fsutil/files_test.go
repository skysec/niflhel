package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicAndConfinedOpen(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "dir", "file")
	if e := Atomic(p, []byte("one"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := Atomic(p, []byte("two"), 0600); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(p)
	if e != nil || string(b) != "two" {
		t.Fatal(string(b), e)
	}
	os.Symlink("/dir/file", filepath.Join(root, "inside"))
	f, e := OpenRootPath(root, "inside")
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	outside := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(outside, []byte("outside"), 0600)
	os.Symlink(outside, filepath.Join(root, "escape"))
	if f, e := OpenRootPath(root, "escape"); e == nil {
		f.Close()
		t.Fatal("absolute symlink escaped container root")
	}
}
