package firecracker

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"niflhel/internal/api"
	"niflhel/internal/base"
	"niflhel/internal/fsutil"
	"niflhel/internal/network"
	"niflhel/internal/storage"
	"niflhel/internal/wire"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Manager struct {
	Root        string
	Firecracker string
	Jailer      string
	Storage     storage.Manager
}
type Drive struct {
	ID       string `json:"drive_id"`
	Path     string `json:"path_on_host"`
	Root     bool   `json:"is_root_device"`
	ReadOnly bool   `json:"is_read_only"`
}
type Config struct {
	Boot struct {
		Kernel string `json:"kernel_image_path"`
		Args   string `json:"boot_args"`
	} `json:"boot-source"`
	Machine struct {
		CPUs   int   `json:"vcpu_count"`
		Memory int64 `json:"mem_size_mib"`
	} `json:"machine-config"`
	Drives  []Drive             `json:"drives"`
	Network []map[string]string `json:"network-interfaces,omitempty"`
	Vsock   map[string]any      `json:"vsock"`
}

func (m Manager) Dir(id string) string { return filepath.Join(m.Root, "sandboxes", id) }
func (m Manager) Jail(id string) string {
	return filepath.Join(m.Root, "jailer", filepath.Base(m.Firecracker), id, "root")
}
func (m Manager) Check() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("niflheld must run as root to use jailer, KVM, cgroups, and networking")
	}
	for _, p := range []string{m.Firecracker, m.Jailer} {
		if p == "" {
			return fmt.Errorf("Firecracker and jailer paths must be configured")
		}
		if _, e := exec.LookPath(p); e != nil {
			return e
		}
	}
	f, e := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if e != nil {
		return fmt.Errorf("KVM unavailable: %w", e)
	}
	f.Close()
	if _, e = os.Stat("/sys/fs/cgroup/cgroup.controllers"); e != nil {
		return fmt.Errorf("cgroups v2 required")
	}
	return nil
}
func BuildConfig(s api.Sandbox) Config {
	var c Config
	c.Boot.Kernel = "/kernel"
	c.Boot.Args = "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro init=/sbin/niflhel-init random.trust_cpu=on"
	c.Machine.CPUs = s.Spec.CPUs
	c.Machine.Memory = s.GuestMemory / api.MiB
	c.Drives = []Drive{{"base-root", "/base.ext4", true, true}, {"bootstrap", "/bootstrap.ext4", false, true}, {"app-image", "/app.ext4", false, true}, {"state", "/state.ext4", false, false}}
	for i, m := range s.Spec.Mounts {
		c.Drives = append(c.Drives, Drive{fmt.Sprintf("volume-%d", i), fmt.Sprintf("/volume-%d.ext4", i), false, m.ReadOnly})
	}
	if s.Spec.Network == "bridge" {
		c.Network = []map[string]string{{"iface_id": "eth0", "guest_mac": "06:00:ac:1e:00:02", "host_dev_name": "tap0"}}
	}
	c.Vsock = map[string]any{"guest_cid": uint32(3 + s.Slot), "uds_path": "/run/vsock"}
	return c
}
func (m Manager) Start(ctx context.Context, s api.Sandbox, b base.Bundle) (int, string, error) {
	if e := m.Check(); e != nil {
		return 0, "", e
	}
	version, e := exec.CommandContext(ctx, m.Firecracker, "--version").CombinedOutput()
	if e != nil {
		return 0, "", e
	}
	ok := false
	for _, v := range b.Signed.Config.FirecrackerVersions {
		if strings.Contains(string(version), "Firecracker v"+v+"\n") {
			ok = true
		}
	}
	if !ok {
		return 0, "", fmt.Errorf("base is not qualified for installed Firecracker")
	}
	dir := m.Dir(s.ID)
	jail := m.Jail(s.ID)
	if e = os.MkdirAll(filepath.Join(jail, "run"), 0700); e != nil {
		return 0, "", e
	}
	uid := 100000 + s.Slot
	os.Chown(jail, uid, uid)
	os.Chown(filepath.Join(jail, "run"), uid, uid)
	link := func(source, target string, writable bool) error {
		p := filepath.Join(jail, target)
		os.Remove(p)
		if e := os.Link(source, p); e != nil {
			return fmt.Errorf("base/state and jail must share a filesystem: %w", e)
		}
		if writable {
			if e := os.Chown(p, uid, uid); e != nil {
				return e
			}
			return os.Chmod(p, 0600)
		}
		return os.Chmod(p, 0444)
	}
	for _, v := range []struct {
		src, dst string
		rw       bool
	}{{b.KernelPath, "kernel", false}, {b.RootFSPath, "base.ext4", false}, {filepath.Join(dir, "app.ext4"), "app.ext4", false}, {filepath.Join(dir, "state.ext4"), "state.ext4", true}} {
		if e = link(v.src, v.dst, v.rw); e != nil {
			return 0, "", e
		}
	}
	for i, v := range s.Spec.Mounts {
		p, e := m.Storage.VolumePath(v.Name)
		if e != nil {
			return 0, "", e
		}
		if e = link(p, fmt.Sprintf("volume-%d.ext4", i), true); e != nil {
			return 0, "", e
		}
	}
	creds, e := CredentialsFor(s.ID)
	if e != nil {
		return 0, "", e
	}
	if e = fsutil.JSON(filepath.Join(dir, "control.json"), creds); e != nil {
		return 0, "", e
	}
	seed, e := os.MkdirTemp(dir, "seed-")
	if e != nil {
		return 0, "", e
	}
	defer os.RemoveAll(seed)
	boot := api.Bootstrap{Protocol: api.Protocol, ID: s.ID, Generation: s.Generation, Certificate: creds.GuestCert, PrivateKey: creds.GuestKey, CA: creds.CA, Sandbox: s}
	if e = fsutil.JSON(filepath.Join(seed, "bootstrap.json"), boot); e != nil {
		return 0, "", e
	}
	bp := filepath.Join(jail, "bootstrap.ext4")
	os.Remove(bp)
	if e = m.Storage.Disk(ctx, bp, 64*api.MiB, seed); e != nil {
		return 0, "", e
	}
	os.Chmod(bp, 0444)
	raw, _ := json.Marshal(BuildConfig(s))
	if e = fsutil.Atomic(filepath.Join(jail, "vm.json"), raw, 0444); e != nil {
		return 0, "", e
	}
	args := []string{"--id", s.ID, "--exec-file", m.Firecracker, "--uid", strconv.Itoa(uid), "--gid", strconv.Itoa(uid), "--chroot-base-dir", filepath.Join(m.Root, "jailer"), "--cgroup-version", "2", "--parent-cgroup", "niflhel", "--cgroup", "memory.max=" + strconv.FormatInt(s.GuestMemory+64*api.MiB, 10), "--cgroup", "cpu.max=" + strconv.Itoa(s.Spec.CPUs*100000) + " 100000"}
	if s.Spec.Network == "bridge" {
		n, _ := network.For(s.ID, s.Slot)
		args = append(args, "--netns", "/var/run/netns/"+n.Namespace)
	}
	args = append(args, "--", "--api-sock", "/run/firecracker.sock", "--config-file", "/vm.json")
	readLog, log, e := os.Pipe()
	if e != nil {
		return 0, "", e
	}
	defer log.Close()
	self, e := os.Executable()
	if e != nil {
		readLog.Close()
		return 0, "", e
	}
	logger := exec.Command(self, "--log-sink", filepath.Join(dir, "console.log"))
	logger.Stdin = readLog
	if e = logger.Start(); e != nil {
		readLog.Close()
		return 0, "", e
	}
	readLog.Close()
	go logger.Wait()
	cmd := exec.Command(m.Jailer, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWPID}
	cmd.Stdout = log
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		return 0, "", e
	}
	pid := cmd.Process.Pid
	start, e := PIDStart(pid)
	if e != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return 0, "", e
	}
	go cmd.Wait() // Reap our direct child. Surviving VMMs are adopted after service restart.
	return pid, start, nil
}
func PIDStart(pid int) (string, error) {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		return "", e
	}
	i := strings.LastIndex(string(b), ") ")
	if i < 0 {
		return "", fmt.Errorf("malformed process stat")
	}
	p := strings.Fields(string(b)[i+2:])
	if len(p) < 20 {
		return "", fmt.Errorf("malformed process stat")
	}
	return p[19], nil
}
func Alive(s api.Sandbox) bool {
	v, e := PIDStart(s.PID)
	return e == nil && v == s.PIDStart && s.PID > 1 && s.PIDStart != ""
}
func (m Manager) Kill(ctx context.Context, s api.Sandbox) error {
	if !Alive(s) {
		discovered, e := m.Discover(s)
		if e != nil {
			return e
		}
		s = discovered
		if !Alive(s) {
			return nil
		}
	}
	fd, e := unix.PidfdOpen(s.PID, 0)
	if e == unix.ESRCH {
		return nil
	}
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	if !Alive(s) {
		return nil
	}
	if e = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); e != nil && e != unix.ESRCH {
		return e
	}
	for Alive(s) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	return nil
}
func (m Manager) Client(s api.Sandbox) (*wire.Client, error) {
	var cr Credentials
	if e := fsutil.ReadJSON(filepath.Join(m.Dir(s.ID), "control.json"), &cr); e != nil {
		return nil, e
	}
	cfg, e := TLSConfig(cr.CA, cr.HostCert, cr.HostKey, "guest-"+s.ID, false)
	if e != nil {
		return nil, e
	}
	return &wire.Client{Dial: func(ctx context.Context) (net.Conn, error) {
		c, e := (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(m.Jail(s.ID), "run/vsock"))
		if e != nil {
			return nil, e
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, e = io.WriteString(c, "CONNECT 1024\n"); e != nil {
			c.Close()
			return nil, e
		}
		// Read exactly the handshake, avoiding buffering TLS bytes.
		r := bufio.NewReaderSize(c, 16)
		line, e := r.ReadString('\n')
		if e != nil || !strings.HasPrefix(line, "OK ") {
			c.Close()
			return nil, fmt.Errorf("vsock handshake: %s %v", line, e)
		}
		c.SetDeadline(time.Time{})
		tc := tls.Client(c, cfg)
		if e = tc.HandshakeContext(ctx); e != nil {
			c.Close()
			return nil, e
		}
		return tc, nil
	}}, nil
}
func (m Manager) Ready(ctx context.Context, s api.Sandbox) (*wire.Client, error) {
	c, e := m.Client(s)
	if e != nil {
		return nil, e
	}
	for {
		qctx, cancel := context.WithTimeout(ctx, time.Second)
		var st api.GuestStatus
		e = c.Call(qctx, api.Request{Action: "status"}, &st)
		cancel()
		if e == nil {
			if st.Protocol != api.Protocol || st.ID != s.ID || st.Generation != s.Generation {
				return nil, fmt.Errorf("guest identity/protocol mismatch")
			}
			return c, nil
		}
		if !Alive(s) {
			return nil, fmt.Errorf("VMM exited before guest ready; see console.log")
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("guest readiness timeout: %w", e)
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func (m Manager) Remove(s api.Sandbox) error {
	if Alive(s) {
		return fmt.Errorf("refusing to remove live VM")
	}
	if e := os.RemoveAll(filepath.Dir(m.Jail(s.ID))); e != nil {
		return e
	}
	if e := os.Remove(filepath.Join("/sys/fs/cgroup/niflhel", s.ID)); e != nil && !os.IsNotExist(e) {
		return e
	}
	return nil
}

// Discover closes the crash window between launching the jailer and committing
// its PID. Only a PID in the exact owned cgroup can be adopted from the pidfile.
func (m Manager) Discover(s api.Sandbox) (api.Sandbox, error) {
	if Alive(s) {
		return s, nil
	}
	raw, e := os.ReadFile(filepath.Join(m.Jail(s.ID), filepath.Base(m.Firecracker)+".pid"))
	if os.IsNotExist(e) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	pid, e := strconv.Atoi(strings.TrimSpace(string(raw)))
	if e != nil || pid < 2 {
		return s, fmt.Errorf("invalid jailer PID record")
	}
	group, e := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if os.IsNotExist(e) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	owned := false
	for _, line := range strings.Split(string(group), "\n") {
		if strings.HasSuffix(line, ":/niflhel/"+s.ID) {
			owned = true
		}
	}
	if !owned {
		return s, nil
	}
	start, e := PIDStart(pid)
	if e != nil {
		return s, e
	}
	s.PID = pid
	s.PIDStart = start
	return s, nil
}
