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
	"path/filepath"
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

func pathFD(name string, flags int) (int, error) {
	rel, e := rootRelative(name)
	if e != nil {
		return -1, e
	}
	root, e := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	defer unix.Close(root)
	return unix.Openat2(root, rel, &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
}

func rootRelative(name string) (string, error) {
	abs, e := filepath.Abs(name)
	if e != nil {
		return "", e
	}
	rel := strings.TrimPrefix(filepath.ToSlash(abs), "/")
	if rel == "" {
		rel = "."
	}
	return rel, nil
}

func rootFD(root string) (int, error) {
	return pathFD(root, unix.O_PATH|unix.O_DIRECTORY)
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
	return extract(fd, dest, r)
}

// ExtractRoot extracts relative to an already-open directory. The guest uses
// this for the intentionally followed /proc/PID/root magic link.
func ExtractRoot(root *os.File, dest string, r io.Reader) error {
	fd, e := directoryFD(root)
	if e != nil {
		return e
	}
	return extract(fd, dest, r)
}

// OpenDestinationRoot creates and pins a destination directory without
// following symlinks in any path component.
func OpenDestinationRoot(name string) (*os.File, error) {
	rel, e := rootRelative(name)
	if e != nil {
		return nil, e
	}
	root, e := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	defer unix.Close(root)
	if e = mkdir(root, rel); e != nil {
		return nil, e
	}
	return open(root, rel, unix.O_PATH|unix.O_DIRECTORY, 0)
}

func extract(fd int, dest string, r io.Reader) error {
	var e error
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

// ArchiveSource pins a regular file or directory selected for archiving.
// ArchiveTo uses this descriptor instead of resolving the source path again.
type ArchiveSource struct {
	file *os.File
	name string
}

// OpenArchiveSource atomically rejects symlinks and magic links in the source
// path and derives the archive layout from the opened object.
func OpenArchiveSource(source string) (*ArchiveSource, error) {
	fd, e := pathFD(source, unix.O_RDONLY|unix.O_NONBLOCK)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), source)
	st, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	if !st.IsDir() && !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("copy supports regular files/directories only")
	}
	name := filepath.Base(source)
	if st.IsDir() {
		name = "."
	}
	return &ArchiveSource{file: f, name: name}, nil
}

func (s *ArchiveSource) Close() error {
	if s == nil || s.file == nil {
		return nil
	}
	return s.file.Close()
}

func (s *ArchiveSource) ArchiveTo(w io.Writer) error {
	if s == nil || s.file == nil {
		return fmt.Errorf("invalid archive source")
	}
	return archiveFile(s.file, s.name, w)
}

func directoryFD(root *os.File) (int, error) {
	if root == nil {
		return -1, fmt.Errorf("invalid copy root")
	}
	st, e := root.Stat()
	if e != nil {
		return -1, e
	}
	if !st.IsDir() {
		return -1, fmt.Errorf("copy root must be a directory")
	}
	return int(root.Fd()), nil
}

func archiveAt(fd int, src string, w io.Writer) error {
	var e error
	src, e = clean(src)
	if e != nil {
		return e
	}
	f, e := open(fd, src, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	name := path.Base(src)
	if st.IsDir() {
		name = "."
	}
	return archiveFile(f, name, w)
}

func Archive(root, src string, w io.Writer) error {
	fd, e := rootFD(root)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	return archiveAt(fd, src, w)
}

// ArchiveRoot archives relative to an already-open directory. The guest uses
// this for the intentionally followed /proc/PID/root magic link.
func ArchiveRoot(root *os.File, src string, w io.Writer) error {
	fd, e := directoryFD(root)
	if e != nil {
		return e
	}
	return archiveAt(fd, src, w)
}

func archiveFile(source *os.File, sourceName string, w io.Writer) error {
	tw := tar.NewWriter(w)
	defer tw.Close()
	var total int64
	count := 0
	var walk func(*os.File, string) error
	walk = func(f *os.File, name string) error {
		count++
		if count > 10000 {
			return fmt.Errorf("copy file count limit")
		}
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
				child, e := open(int(f.Fd()), v.Name(), unix.O_RDONLY|unix.O_NONBLOCK, 0)
				if e != nil {
					return e
				}
				e = walk(child, path.Join(name, v.Name()))
				ce := child.Close()
				if e != nil {
					return e
				}
				if ce != nil {
					return ce
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
	if e := walk(source, sourceName); e != nil {
		return e
	}
	return tw.Close()
}
