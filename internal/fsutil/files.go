package fsutil

import (
	"bytes"
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

// ReadFileLimit bounds files before callers retain or parse attacker-controlled
// metadata. The post-read check also covers a file that grows after Stat.
func ReadFileLimit(path string, max int64) ([]byte, error) {
	if max < 0 {
		return nil, fmt.Errorf("invalid file size limit")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("metadata must be a regular file")
	}
	if st.Size() > max {
		return nil, fmt.Errorf("metadata size limit exceeded")
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("metadata size limit exceeded")
	}
	return b, nil
}

// ValidateJSONComplexity performs a non-retaining token pass before semantic
// decoding, bounding object/array amplification and nesting independently of
// the raw byte limit.
func ValidateJSONComplexity(b []byte, maxTokens, maxDepth int, maxStringBytes int64) error {
	if maxTokens <= 0 || maxDepth <= 0 || maxStringBytes < 0 {
		return fmt.Errorf("invalid JSON complexity limit")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	tokens, depth := 0, 0
	var stringBytes int64
	started, complete := false, false
	for {
		tok, e := dec.Token()
		if e == io.EOF {
			if !started || !complete || depth != 0 {
				return fmt.Errorf("invalid JSON value")
			}
			return nil
		}
		if e != nil {
			return e
		}
		if complete {
			return fmt.Errorf("multiple JSON values")
		}
		started = true
		tokens++
		if tokens > maxTokens {
			return fmt.Errorf("JSON token limit exceeded")
		}
		if s, ok := tok.(string); ok {
			if int64(len(s)) > maxStringBytes-stringBytes {
				return fmt.Errorf("JSON string limit exceeded")
			}
			stringBytes += int64(len(s))
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
				if depth > maxDepth {
					return fmt.Errorf("JSON depth limit exceeded")
				}
			case '}', ']':
				depth--
				if depth < 0 {
					return fmt.Errorf("invalid JSON nesting")
				}
				if depth == 0 {
					complete = true
				}
			}
		} else if depth == 0 {
			complete = true
		}
	}
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
