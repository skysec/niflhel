package storage

import (
	"context"
	"errors"
	"niflhel/internal/api"
	"os"
	"path/filepath"
	"testing"
)

type fail struct{}

func (fail) Run(context.Context, string, ...string) error { return errors.New("mkfs failed") }
func TestDiskRollback(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.ext4")
	m := Manager{Runner: fail{}}
	if e := m.Disk(context.Background(), p, 64*api.MiB, ""); e == nil {
		t.Fatal("expected error")
	}
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("disk leaked")
	}
}
func TestVolumePath(t *testing.T) {
	m := Manager{Root: t.TempDir()}
	if _, e := m.VolumePath("../escape"); e == nil {
		t.Fatal("escape accepted")
	}
}
