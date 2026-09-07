package runtime

import (
	"niflhel/internal/api"
	"os"
	"path/filepath"
	"testing"
)

func TestSpecBoundaries(t *testing.T) {
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "etc"), 0755)
	os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("app:x:123:456::/:/bin/sh\n"), 0644)
	s := api.Sandbox{ID: api.ID(), Name: "test", Spec: api.DefaultSpec(), Process: api.Process{User: "app", Args: []string{"app"}, Cwd: "/"}}
	cfg, e := Build(s, root, "/run/netns/app")
	if e != nil {
		t.Fatal(e)
	}
	if cfg.Process.User.UID != 123 || cfg.Process.User.GID != 456 || !cfg.Process.NoNewPrivileges {
		t.Fatal(cfg.Process)
	}
	if cfg.Linux.Resources.Memory.Limit == nil || *cfg.Linux.Resources.Memory.Limit != 512*api.MiB {
		t.Fatal("memory not limited")
	}
	for _, sys := range cfg.Linux.Seccomp.Syscalls {
		for _, n := range sys.Names {
			if n == "mount" || n == "bpf" || n == "ptrace" {
				t.Fatal("dangerous syscall allowed", n)
			}
		}
	}
	if _, e = User(root, "unknown"); e == nil {
		t.Fatal("unknown user accepted")
	}
}
