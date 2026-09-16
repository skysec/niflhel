package filecopy

import (
	"archive/tar"
	"bytes"
	"io"
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

func TestArchiveRejectsSymlinkPaths(t *testing.T) {
	root := t.TempDir()
	targetDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(targetDir, "secret"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(root, "dir-link")
	if err := os.Symlink(targetDir, dirLink); err != nil {
		t.Fatal(err)
	}
	if source, err := OpenArchiveSource(dirLink); err == nil {
		source.Close()
		t.Fatal("top-level directory symlink accepted")
	}
	if err := Archive(dirLink, ".", io.Discard); err == nil {
		t.Fatal("archive root symlink accepted")
	}

	targetFile := filepath.Join(root, "target")
	if err := os.WriteFile(targetFile, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	fileLink := filepath.Join(root, "file-link")
	if err := os.Symlink(targetFile, fileLink); err != nil {
		t.Fatal(err)
	}
	if source, err := OpenArchiveSource(fileLink); err == nil {
		source.Close()
		t.Fatal("top-level regular-file symlink accepted")
	}
	if err := Archive(root, "file-link", io.Discard); err == nil {
		t.Fatal("archive source symlink accepted")
	}

	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	if err := tw.WriteHeader(&tar.Header{Name: "written", Mode: 0600, Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Extract(dirLink, ".", &b); err == nil {
		t.Fatal("extract root symlink accepted")
	}
	if _, err := os.Stat(filepath.Join(targetDir, "written")); !os.IsNotExist(err) {
		t.Fatal("extract wrote through a root symlink")
	}
}

func TestOpenArchiveSourcePinsDirectory(t *testing.T) {
	parent := t.TempDir()
	selected := filepath.Join(parent, "selected")
	if err := os.Mkdir(selected, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(selected, "original"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := OpenArchiveSource(selected)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := os.Rename(selected, filepath.Join(parent, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(selected, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(selected, "replacement"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	if err := source.ArchiveTo(&b); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(&b)
	entries := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			entries[h.Name] = string(data)
		}
	}
	if entries["original"] != "original" {
		t.Fatalf("pinned source missing original entry: %#v", entries)
	}
	if _, ok := entries["replacement"]; ok {
		t.Fatalf("archive followed replacement path: %#v", entries)
	}
}

func TestOpenDestinationRootRejectsSymlinkAncestor(t *testing.T) {
	parent := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(parent, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	root, err := OpenDestinationRoot(filepath.Join(link, "new"))
	if err == nil {
		root.Close()
		t.Fatal("destination symlink accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "new")); !os.IsNotExist(err) {
		t.Fatal("destination directory created through symlink")
	}

	dest := filepath.Join(parent, "ordinary", "nested")
	root, err = OpenDestinationRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	if err := tw.WriteHeader(&tar.Header{Name: "written", Mode: 0600, Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ExtractRoot(root, ".", &b); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dest, "written"))
	if err != nil || string(data) != "x" {
		t.Fatalf("ordinary destination failed: %q %v", data, err)
	}
}

func TestExplicitRootDescriptorPreservesGuestMagicLink(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("content"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Archive("/proc/self/root", source, io.Discard); err == nil {
		t.Fatal("path-based archive accepted procfs magic-link root")
	}
	root, err := os.Open("/proc/self/root")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var b bytes.Buffer
	if err := ArchiveRoot(root, source, &b); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(&b)
	h, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(tr)
	if err != nil {
		t.Fatal(err)
	}
	if h.Name != "source" || string(data) != "content" {
		t.Fatalf("unexpected descriptor archive %q %q", h.Name, data)
	}
}
