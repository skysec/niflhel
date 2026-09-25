package firecracker

import (
	"crypto/tls"
	"fmt"
	"net"
	"niflhel/internal/api"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestConfigContainerDrives(t *testing.T) {
	s := api.Sandbox{ID: api.ID(), Spec: api.DefaultSpec(), Slot: 1, GuestMemory: 640 * api.MiB}
	s.Spec.Network = "none"
	c := BuildConfig(s)
	if len(c.Network) != 0 || len(c.Drives) != 4 || !c.Drives[0].ReadOnly || c.Drives[3].ReadOnly {
		t.Fatal(c)
	}
	if c.Machine.Memory != 640 {
		t.Fatal(c)
	}
}
func TestMutualTLS(t *testing.T) {
	cr, e := CredentialsFor("test")
	if e != nil {
		t.Fatal(e)
	}
	server, e := TLSConfig(cr.CA, cr.GuestCert, cr.GuestKey, "", true)
	if e != nil {
		t.Fatal(e)
	}
	client, e := TLSConfig(cr.CA, cr.HostCert, cr.HostKey, "guest-test", false)
	if e != nil {
		t.Fatal(e)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	done := make(chan error, 1)
	go func() { done <- tls.Server(a, server).Handshake() }()
	if e = tls.Client(b, client).Handshake(); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestProcessIdentityIsBootAndCgroupBound(t *testing.T) {
	procRoot := t.TempDir()
	pid := 4242
	ticks := "98765"
	id := strings.Repeat("a", 32)
	writeProcess := func(bootID, cgroup string) {
		t.Helper()
		if e := os.MkdirAll(filepath.Join(procRoot, "sys/kernel/random"), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(procRoot, "sys/kernel/random/boot_id"), []byte(bootID+"\n"), 0600); e != nil {
			t.Fatal(e)
		}
		processDir := filepath.Join(procRoot, strconv.Itoa(pid))
		if e := os.MkdirAll(processDir, 0700); e != nil {
			t.Fatal(e)
		}
		fields := make([]string, 20)
		for i := range fields {
			fields[i] = "0"
		}
		fields[0] = "S"
		fields[19] = ticks
		stat := fmt.Sprintf("%d (firecracker) %s\n", pid, strings.Join(fields, " "))
		if e := os.WriteFile(filepath.Join(processDir, "stat"), []byte(stat), 0600); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(processDir, "cgroup"), []byte("0::"+cgroup+"\n"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	writeProcess("boot-a", "/niflhel/"+id)
	start, e := pidStartAt(procRoot, pid)
	if e != nil {
		t.Fatal(e)
	}
	s := api.Sandbox{ID: id, PID: pid, PIDStart: start}
	if !aliveAt(procRoot, s) {
		t.Fatal("same-boot process identity rejected")
	}
	writeProcess("boot-a", "/other")
	if aliveAt(procRoot, s) {
		t.Fatal("same-boot process outside owned cgroup accepted")
	}
	writeProcess("boot-b", "/other")
	if aliveAt(procRoot, s) {
		t.Fatal("cross-boot PID/start alias accepted")
	}
	legacy := s
	legacy.PIDStart = ticks
	if aliveAt(procRoot, legacy) {
		t.Fatal("legacy start ticks accepted outside the owned cgroup")
	}
	writeProcess("boot-b", "/niflhel/"+id)
	if !aliveAt(procRoot, legacy) {
		t.Fatal("owned legacy identity was not safely adopted")
	}

	m := Manager{Root: t.TempDir(), Firecracker: "/bin/firecracker", procRoot: procRoot}
	if e = os.MkdirAll(m.Jail(id), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(m.Jail(id), "firecracker.pid"), []byte(strconv.Itoa(pid)), 0600); e != nil {
		t.Fatal(e)
	}
	writeProcess("boot-b", "/other")
	discovered, e := m.Discover(s)
	if e != nil || discovered.PID != 0 || discovered.PIDStart != "" {
		t.Fatal(discovered, e)
	}
	writeProcess("boot-b", "/niflhel/"+id)
	discovered, e = m.Discover(s)
	if e != nil || discovered.PID != pid || discovered.PIDStart == start {
		t.Fatal(discovered, e)
	}
}
