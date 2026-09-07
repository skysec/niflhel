package fsutil

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func Atomic(path string, data []byte, mode os.FileMode) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".pending-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(data)
	}
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
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func JSON(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return Atomic(path, b, 0600)
}
func ReadJSON(path string, v any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func Digest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func DigestFile(path string) (string, int64, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, f)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), n, e
}
func HexDigest(s string) (string, error) {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return "", fmt.Errorf("invalid sha256 digest")
	}
	_, e := hex.DecodeString(s[7:])
	if e != nil {
		return "", e
	}
	return s[7:], nil
}
func Within(root, name string) (string, error) {
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("NUL in path")
	}
	clean := filepath.Clean(name)
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes root")
	}
	full := filepath.Join(root, clean)
	parent := filepath.Dir(full)
	for p := parent; p != root && p != filepath.Dir(p); p = filepath.Dir(p) {
		fi, e := os.Lstat(p)
		if e == nil && fi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink in parent path")
		}
		if e != nil && !os.IsNotExist(e) {
			return "", e
		}
	}
	return full, nil
}

// OpenRootPath follows container symlinks relative to its pinned root, never
// relative to the guest/host process root.
func OpenRootPath(root, name string) (*os.File, error) {
	fd, e := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	defer unix.Close(fd)
	child, e := unix.Openat2(fd, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS})
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(child), name), nil
}
