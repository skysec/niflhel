package guest

import (
	"context"
	"fmt"
	"niflhel/internal/api"
	"niflhel/internal/fsutil"
	"niflhel/internal/network"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func mount(source, target, kind string, flags uintptr, data string) error {
	if e := os.MkdirAll(target, 0755); e != nil {
		return e
	}
	e := syscall.Mount(source, target, kind, flags, data)
	if e == syscall.EBUSY {
		return nil
	}
	return e
}
func Initialize() (api.Bootstrap, error) {
	var b api.Bootstrap
	if os.Getpid() != 1 {
		return b, fmt.Errorf("guest init must be PID 1; refusing host execution")
	}
	for _, m := range [][3]string{{"devtmpfs", "/dev", "devtmpfs"}, {"devpts", "/dev/pts", "devpts"}, {"proc", "/proc", "proc"}, {"sysfs", "/sys", "sysfs"}, {"tmpfs", "/run", "tmpfs"}, {"tmpfs", "/tmp", "tmpfs"}, {"cgroup2", "/sys/fs/cgroup", "cgroup2"}} {
		if e := mount(m[0], m[1], m[2], 0, ""); e != nil {
			return b, e
		}
	}
	if e := mount("/dev/vdb", "/bootstrap", "ext4", syscall.MS_RDONLY, ""); e != nil {
		return b, e
	}
	if e := fsutil.ReadJSON("/bootstrap/bootstrap.json", &b); e != nil {
		return b, e
	}
	if b.Protocol != api.Protocol || b.ID != b.Sandbox.ID {
		return b, fmt.Errorf("bootstrap identity mismatch")
	}
	if e := mount("/dev/vdc", "/app-image", "ext4", syscall.MS_RDONLY, ""); e != nil {
		return b, e
	}
	if e := mount("/dev/vdd", "/state", "ext4", 0, ""); e != nil {
		return b, e
	}
	for _, p := range []string{"/run/niflhel", "/state/bundle", "/state/upper", "/state/work", "/state/lower"} {
		if e := os.MkdirAll(p, 0700); e != nil {
			return b, e
		}
	}
	os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+cpu +memory +pids"), 0644)
	if e := os.MkdirAll("/sys/fs/cgroup/niflhel", 0755); e != nil {
		return b, e
	}
	os.WriteFile("/sys/fs/cgroup/niflhel/cgroup.subtree_control", []byte("+cpu +memory +pids"), 0644)
	return b, nil
}
func Prepare(ctx context.Context, b api.Bootstrap) error {
	marker := "/state/image.digest"
	content, _ := os.ReadFile(marker)
	if string(content) != b.Sandbox.ImageDigest {
		os.RemoveAll("/state/lower")
		os.RemoveAll("/state/unpack")
		if e := os.Mkdir("/state/unpack", 0700); e != nil {
			return e
		}
		if e := Unpack(ctx, "/app-image", "/state/unpack", b.Sandbox.Spec.DiskSize/2); e != nil {
			return e
		}
		if e := os.Rename("/state/unpack", "/state/lower"); e != nil {
			return e
		}
		if e := fsutil.Atomic(marker, []byte(b.Sandbox.ImageDigest), 0600); e != nil {
			return e
		}
	}
	root := "/state/bundle/rootfs"
	if e := mount("overlay", root, "overlay", 0, "lowerdir=/state/lower,upperdir=/state/upper,workdir=/state/work"); e != nil {
		return e
	}
	for i, v := range b.Sandbox.Spec.Mounts {
		flags := uintptr(0)
		if v.ReadOnly {
			flags = syscall.MS_RDONLY
		}
		if e := mount(fmt.Sprintf("/dev/vd%c", 'e'+i), fmt.Sprintf("/run/niflhel/volumes/%d", i), "ext4", flags, ""); e != nil {
			return e
		}
	}
	dns := "127.0.0.1"
	if b.Sandbox.Spec.Network == "bridge" {
		n, _ := network.For(b.ID, b.Sandbox.Slot)
		dns = n.HostIP
		if e := prepareNetwork(ctx, b); e != nil {
			return e
		}
	}
	if e := os.WriteFile("/run/niflhel/resolv.conf", []byte("nameserver "+dns+"\noptions timeout:2 attempts:2\n"), 0644); e != nil {
		return e
	}
	// Required mount destinations are created by runc inside its rootfs.
	return nil
}
func run(ctx context.Context, name string, args ...string) error {
	out, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		return fmt.Errorf("%s: %w: %s", name, e, out)
	}
	return nil
}
func prepareNetwork(ctx context.Context, b api.Bootstrap) error {
	cmds := [][]string{
		{"ip", "link", "set", "lo", "up"}, {"ip", "addr", "add", "172.30.0.2/30", "dev", "eth0"}, {"ip", "link", "set", "eth0", "up"}, {"ip", "route", "add", "default", "via", "172.30.0.1"},
		{"ip", "netns", "add", "app"}, {"ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1"}, {"ip", "link", "set", "veth1", "netns", "app"},
		{"ip", "addr", "add", "10.0.0.1/30", "dev", "veth0"}, {"ip", "link", "set", "veth0", "up"},
		{"ip", "-n", "app", "addr", "add", "10.0.0.2/30", "dev", "veth1"}, {"ip", "-n", "app", "link", "set", "veth1", "up"}, {"ip", "-n", "app", "link", "set", "lo", "up"}, {"ip", "-n", "app", "route", "add", "default", "via", "10.0.0.1"},
		{"sysctl", "-qw", "net.ipv4.ip_forward=1"}, {"sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1"},
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.0.0.2", "-o", "eth0", "-j", "MASQUERADE"},
	}
	for _, c := range cmds {
		if e := run(ctx, c[0], c[1:]...); e != nil {
			return e
		}
	}
	for _, p := range b.Sandbox.Spec.Ports {
		if e := run(ctx, "iptables", "-t", "nat", "-A", "PREROUTING", "-i", "eth0", "-p", "tcp", "--dport", fmt.Sprint(p.ContainerPort), "-j", "DNAT", "--to-destination", fmt.Sprintf("10.0.0.2:%d", p.ContainerPort)); e != nil {
			return e
		}
	}
	return nil
}
func RootPath() string { return filepath.Join("/state", "bundle", "rootfs") }
