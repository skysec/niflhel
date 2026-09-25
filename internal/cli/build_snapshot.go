package cli

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"niflhel/internal/filecopy"
)

// Ignore TMPDIR for publisher builds: its ancestors may belong to a workspace
// collaborator. Only root may replace /tmp; its sticky bit protects our 0700
// temporary directory from other users for the entire buildctl session.
func privateBuildTemp() (string, error) {
	var st unix.Stat_t
	if err := unix.Lstat("/tmp", &st); err != nil {
		return "", err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || (st.Mode&0022 != 0 && st.Mode&unix.S_ISVTX == 0) {
		return "", fmt.Errorf("base build requires root-owned /tmp with sticky-bit protection when writable by others")
	}
	return os.MkdirTemp("/tmp", "niflhel-build-")
}

// Copied directories may be read-only. Restore owner access in our protected
// tree before removal; WalkDir does not follow symlinks into other trees.
func removeBuildTemp(root string) error {
	if err := filepath.WalkDir(root, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(name, 0700)
		}
		return nil
	}); err != nil {
		return err
	}
	return os.RemoveAll(root)
}

// prepareBaseBuild exports fresh copies, never the mutable input pathnames.
// The signing key stays open until every source file has been checked against
// that same inode. Checking the copies afterwards would lose hard-link identity.
// The caller must supply a private directory with protected ancestors, and keep
// it alive until buildctl has finished.
func prepareBaseBuild(keyPath, stage string, roots ...string) (ed25519.PrivateKey, []string, error) {
	keyPath, err := filepath.Abs(keyPath)
	if err != nil {
		return nil, nil, err
	}
	resolvedKey, err := filepath.EvalSymlinks(keyPath)
	if err != nil {
		return nil, nil, err
	}
	fd, err := unix.Open(resolvedKey, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	keyFile := os.NewFile(uintptr(fd), resolvedKey)
	defer keyFile.Close()
	keyInfo, err := keyFile.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !keyInfo.Mode().IsRegular() || keyInfo.Size() > 4096 {
		return nil, nil, fmt.Errorf("publisher signing key must be a regular file of at most 4096 bytes")
	}
	stageInfo, err := os.Stat(stage)
	if err != nil {
		return nil, nil, err
	}
	var snapshots []string
	for i, root := range roots {
		root, err = filepath.Abs(root)
		if err != nil {
			return nil, nil, err
		}
		resolvedRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			return nil, nil, err
		}
		if withinExportedRoot(root, keyPath) || withinExportedRoot(resolvedRoot, resolvedKey) {
			return nil, nil, fmt.Errorf("publisher signing key must be outside BuildKit local roots")
		}
		// Root rebinding here is safe: we check every actual opened file, and
		// never follow symlinks while copying from this pinned directory.
		fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, nil, err
		}
		source := os.NewFile(uintptr(fd), root)
		dest := filepath.Join(stage, fmt.Sprintf("local-%d", i))
		err = os.Mkdir(dest, 0700)
		if err == nil {
			s := buildSnapshot{key: keyInfo, stage: stageInfo}
			err = s.copyDir(source, dest, 0)
			if err == nil {
				err = s.validateLinks(dest)
			}
		}
		source.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("stage BuildKit local root: %w", err)
		}
		snapshots = append(snapshots, dest)
	}
	// Reopen the pinned regular file, not the publisher's mutable pathname.
	reader, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", keyFile.Fd()))
	if err != nil {
		return nil, nil, err
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, 4097))
	if err != nil {
		return nil, nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if len(raw) > 4096 || err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("invalid Ed25519 publisher signing key")
	}
	return ed25519.PrivateKey(key), snapshots, nil
}

type buildSnapshot struct {
	key, stage os.FileInfo
	bytes      int64
	entries    int
	links      []string
}

func (s *buildSnapshot) copyDir(source *os.File, dest string, depth int) error {
	if depth > 128 {
		return fmt.Errorf("base build local exceeds 128 directory levels")
	}
	st, err := source.Stat()
	if err != nil {
		return err
	}
	if os.SameFile(st, s.stage) {
		return fmt.Errorf("base build staging directory must be outside local roots")
	}
	for {
		entries, err := source.ReadDir(128)
		if err != nil && err != io.EOF {
			return err
		}
		for _, entry := range entries {
			s.entries++
			if s.entries > 10000 {
				return fmt.Errorf("base build local exceeds 10,000 entries")
			}
			if err := s.copyEntry(source, entry.Name(), filepath.Join(dest, entry.Name()), depth); err != nil {
				return err
			}
		}
		if err == io.EOF {
			return os.Chmod(dest, st.Mode().Perm())
		}
	}
}

func (s *buildSnapshot) copyEntry(parent *os.File, name, dest string, depth int) error {
	// O_PATH avoids opening a raced-in device or blocking on a FIFO. fstat,
	// readlinkat and the subsequent read all refer to this exact object.
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if os.SameFile(st, s.key) {
		return fmt.Errorf("publisher signing key has an alias in a BuildKit local root")
	}
	if st.Mode()&os.ModeSymlink != 0 {
		buf := make([]byte, 4096)
		n, err := unix.Readlinkat(fd, "", buf)
		if err != nil {
			return err
		}
		if n == len(buf) || filepath.IsAbs(string(buf[:n])) {
			return fmt.Errorf("base build symlinks must be relative and confined to their local root")
		}
		if err := os.Symlink(string(buf[:n]), dest); err != nil {
			return err
		}
		s.links = append(s.links, dest)
		return nil
	}
	if !st.IsDir() && !st.Mode().IsRegular() {
		return fmt.Errorf("base build locals support only regular files, directories and confined relative symlinks")
	}
	reader, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return err
	}
	defer reader.Close()
	if st.IsDir() {
		if err := os.Mkdir(dest, 0700); err != nil {
			return err
		}
		return s.copyDir(reader, dest, depth+1)
	}
	remaining := filecopy.MaxBytes - s.bytes
	if st.Size() > remaining {
		return fmt.Errorf("base build local exceeds 512 MiB")
	}
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(reader, remaining+1))
	s.bytes += n
	if err == nil && n > remaining {
		err = fmt.Errorf("base build local exceeds 512 MiB")
	}
	if err == nil {
		err = out.Chmod(st.Mode().Perm())
	}
	closeErr := out.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// Validate links only after the private tree is complete. BuildKit receives
// symlink metadata, never a link that can name a publisher file outside it.
func (s *buildSnapshot) validateLinks(root string) error {
	f, err := os.Open(root)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, link := range s.links {
		rel, err := filepath.Rel(root, link)
		if err != nil {
			return err
		}
		fd, err := unix.Openat2(int(f.Fd()), rel, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil {
			return fmt.Errorf("base build symlink must resolve within its local root: %w", err)
		}
		unix.Close(fd)
	}
	return nil
}
