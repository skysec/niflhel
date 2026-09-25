package fsutil

import (
	"os"
	"path/filepath"
	"strings"
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

func TestMetadataFileAndJSONLimits(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "metadata.json")
	if e := os.WriteFile(p, []byte(`{"ok":true}`), 0600); e != nil {
		t.Fatal(e)
	}
	if b, e := ReadFileLimit(p, 11); e != nil || string(b) != `{"ok":true}` {
		t.Fatal(string(b), e)
	}
	if _, e := ReadFileLimit(p, 10); e == nil {
		t.Fatal("oversized metadata accepted")
	}
	if _, e := ReadFileLimit(root, 100); e == nil {
		t.Fatal("directory accepted as metadata")
	}
	if e := ValidateJSONComplexity([]byte(`{"values":["one","two"]}`), 16, 4, 16); e != nil {
		t.Fatal(e)
	}
	if e := ValidateJSONComplexity([]byte(strings.Repeat("[", 5)+strings.Repeat("]", 5)), 16, 4, 16); e == nil {
		t.Fatal("deep JSON accepted")
	}
	if e := ValidateJSONComplexity([]byte(`{} {}`), 16, 4, 16); e == nil {
		t.Fatal("multiple JSON values accepted")
	}
}
