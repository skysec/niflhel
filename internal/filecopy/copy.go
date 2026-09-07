// Package filecopy transfers regular files/directories without following symlinks.
// All destinations are resolved relative to an open root directory descriptor.
package filecopy

import (
	"archive/tar"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path"
	"strings"
)

const MaxBytes int64 = 512 << 20

func clean(s string) (string, error) {
	s = strings.TrimPrefix(s, "/")
	s = path.Clean(s)
	if s == ".." || strings.HasPrefix(s, "../") || strings.ContainsRune(s, 0) {
		return "", fmt.Errorf("copy path escapes root")
	}
	return s, nil
}
func rootFD(root string) (int, error) {
	return unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}
func open(root int, p string, flags int, mode uint32) (*os.File, error) {
	fd, e := unix.Openat2(root, p, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC), Mode: uint64(mode), Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), p), nil
}
func mkdir(root int, p string) error {
	if p == "." || p == "" {
		return nil
	}
	parts := strings.Split(p, "/")
	current := root
	owned := -1
	defer func() {
		if owned >= 0 {
			unix.Close(owned)
		}
	}()
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return fmt.Errorf("parent traversal")
		}
		e := unix.Mkdirat(current, part, 0755)
		if e != nil && e != unix.EEXIST {
			return e
		}
		next, e := unix.Openat(current, part, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return e
		}
		if owned >= 0 {
			unix.Close(owned)
		}
		owned = next
		current = next
	}
	return nil
}
func Extract(root, dest string, r io.Reader) error {
	fd, e := rootFD(root)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	dest, e = clean(dest)
	if e != nil {
		return e
	}
	limited := &io.LimitedReader{R: r, N: MaxBytes + (16 << 20) + 1}
	tr := tar.NewReader(limited)
	var total int64
	count := 0
	for {
		h, e := tr.Next()
		if e == io.EOF {
			// Consume transport EOF, including tar padding, before acknowledging upload.
			if _, e = io.Copy(io.Discard, limited); e != nil {
				return e
			}
			if limited.N == 0 {
				return fmt.Errorf("archive size limit")
			}
			return nil
		}
		if e != nil {
			return e
		}
		count++
		if count > 10000 {
			return fmt.Errorf("copy file count limit")
		}
		n, e := clean(h.Name)
		if e != nil || strings.HasPrefix(h.Name, "/") {
			return fmt.Errorf("unsafe archive path")
		}
		p := path.Join(dest, n)
		switch h.Typeflag {
		case tar.TypeDir:
			if e = mkdir(fd, p); e != nil {
				return e
			}
		case tar.TypeReg, tar.TypeRegA:
			if h.Size < 0 || h.Size > MaxBytes-total {
				return fmt.Errorf("copy size limit")
			}
			total += h.Size
			if e = mkdir(fd, path.Dir(p)); e != nil {
				return e
			}
			f, e := open(fd, p, unix.O_CREAT|unix.O_TRUNC|unix.O_WRONLY, uint32(h.Mode)&0777)
			if e != nil {
				return e
			}
			_, e = io.CopyN(f, tr, h.Size)
			ce := f.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return ce
			}
		default:
			return fmt.Errorf("copy supports regular files and directories only")
		}
	}
}
func Archive(root, src string, w io.Writer) error {
	fd, e := rootFD(root)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	src, e = clean(src)
	if e != nil {
		return e
	}
	tw := tar.NewWriter(w)
	defer tw.Close()
	var total int64
	count := 0
	var walk func(string, string) error
	walk = func(p, name string) error {
		count++
		if count > 10000 {
			return fmt.Errorf("copy file count limit")
		}
		f, e := open(fd, p, unix.O_RDONLY, 0)
		if e != nil {
			return e
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil {
			return e
		}
		if !st.IsDir() && !st.Mode().IsRegular() {
			return fmt.Errorf("copy supports regular files/directories only")
		}
		h, e := tar.FileInfoHeader(st, "")
		if e != nil {
			return e
		}
		h.Name = name
		h.Uid = 0
		h.Gid = 0
		if e = tw.WriteHeader(h); e != nil {
			return e
		}
		if st.IsDir() {
			entries, e := f.ReadDir(-1)
			if e != nil {
				return e
			}
			for _, v := range entries {
				if e = walk(path.Join(p, v.Name()), path.Join(name, v.Name())); e != nil {
					return e
				}
			}
			return nil
		}
		if st.Size() > MaxBytes-total {
			return fmt.Errorf("copy size limit")
		}
		total += st.Size()
		_, e = io.CopyN(tw, f, st.Size())
		return e
	}
	f, e := open(fd, src, unix.O_RDONLY, 0)
	if e != nil {
		return e
	}
	st, e := f.Stat()
	f.Close()
	if e != nil {
		return e
	}
	if st.IsDir() {
		e = walk(src, ".")
	} else {
		e = walk(src, path.Base(src))
	}
	if e != nil {
		return e
	}
	return tw.Close()
}
