package cli

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func (a *App) doctor() *cobra.Command {
	return &cobra.Command{Use: "doctor", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		failed := false
		check := func(name string, e error) {
			if e != nil {
				failed = true
				fmt.Fprintf(a.Out, "FAIL %s: %v\n", name, e)
			} else {
				fmt.Fprintf(a.Out, "OK   %s\n", name)
			}
		}
		var e error
		if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
			e = fmt.Errorf("linux/amd64 required")
		}
		check("platform", e)
		f, e := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
		if f != nil {
			f.Close()
		}
		check("KVM access (host service requires root)", e)
		_, e = os.Stat("/sys/fs/cgroup/cgroup.controllers")
		check("cgroups v2", e)
		for _, name := range []string{"firecracker", "jailer", "ip", "nft", "mkfs.ext4"} {
			_, e = exec.LookPath(name)
			check(name, e)
		}
		b, e := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if e == nil && strings.TrimSpace(string(b)) != "1" {
			e = fmt.Errorf("enable net.ipv4.ip_forward for bridge networking")
		}
		check("IPv4 forwarding", e)
		if failed {
			return fmt.Errorf("host prerequisites are incomplete")
		}
		return nil
	}}
}
