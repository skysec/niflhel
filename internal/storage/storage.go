package storage

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"niflhel/internal/api"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

type Runner interface {
	Run(context.Context, string, ...string) error
}
type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, name string, args ...string) error {
	b, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		return fmt.Errorf("%s: %w: %s", name, e, b)
	}
	return nil
}

type Manager struct {
	Root   string
	Runner Runner
}

func (m Manager) Disk(ctx context.Context, p string, size int64, source string) error {
	if size < 64*api.MiB || size > 1024*api.GiB {
		return fmt.Errorf("invalid disk size")
	}
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	e = f.Truncate(size)
	if e == nil && source == "" {
		e = unix.Fallocate(int(f.Fd()), 0, 0, size)
	}
	f.Close()
	if e != nil {
		os.Remove(p)
		return e
	}
	args := []string{"-q", "-F", "-t", "ext4", "-E", "lazy_itable_init=0,lazy_journal_init=0"}
	if source != "" {
		args = append(args, "-d", source)
	}
	args = append(args, p)
	r := m.Runner
	if r == nil {
		r = OSRunner{}
	}
	if e = r.Run(ctx, "mkfs.ext4", args...); e != nil {
		os.Remove(p)
		return e
	}
	return nil
}
func (m Manager) VolumePath(name string) (string, error) {
	if !api.ValidName(name) {
		return "", fmt.Errorf("invalid volume name")
	}
	return filepath.Join(m.Root, "volumes", name+".ext4"), nil
}
func CarrierSize(bytes int64) int64 {
	return ((bytes + bytes/5 + 64*api.MiB + api.MiB - 1) / api.MiB) * api.MiB
}
func ParseUint(s string) (uint32, error) { v, e := strconv.ParseUint(s, 10, 32); return uint32(v), e }
