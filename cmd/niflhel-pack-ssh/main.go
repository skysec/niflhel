// niflhel-pack-ssh transports packaging inputs to an existing isolated SSH
// worker. It never forwards publisher signing keys or the host control socket.
package main

import (
	"context"
	"flag"
	"fmt"
	"niflhel/internal/api"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	image := flag.String("image", "", "local OCI-layout archive")
	output := flag.String("output", "", "local output directory")
	kernel := flag.String("kernel", "", "local kernel")
	kernelImage := flag.String("kernel-image", "", "remote kernel OCI reference")
	flag.Parse()
	host := os.Getenv("NIFLHEL_BUILD_SSH")
	if !regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@-]*$`).MatchString(host) {
		return fmt.Errorf("set NIFLHEL_BUILD_SSH to an SSH host alias or user@host")
	}
	if *image == "" || *output == "" {
		return fmt.Errorf("--image and --output required")
	}
	remote := "/tmp/niflhel-pack-" + api.ID()
	execute := func(name string, args ...string) error {
		c := exec.CommandContext(context.Background(), name, args...)
		c.Stdout = os.Stderr
		c.Stderr = os.Stderr
		return c.Run()
	}
	ssh := func(command string) error { return execute("ssh", "-oBatchMode=yes", "--", host, command) }
	if e := ssh("mkdir -m 700 " + quote(remote)); e != nil {
		return e
	}
	defer ssh("rm -rf -- " + quote(remote)) // Only our freshly generated worker directory.
	if e := execute("scp", "-oBatchMode=yes", "--", *image, host+":"+remote+"/image.tar"); e != nil {
		return e
	}
	args := " --image " + quote(remote+"/image.tar") + " --output " + quote(remote+"/output")
	if *kernel != "" {
		if e := execute("scp", "-oBatchMode=yes", "--", *kernel, host+":"+remote+"/kernel"); e != nil {
			return e
		}
		args += " --kernel " + quote(remote+"/kernel")
	} else {
		if *kernelImage == "" {
			return fmt.Errorf("kernel or kernel-image required")
		}
		args += " --kernel-image " + quote(*kernelImage)
	}
	if e := ssh("NIFLHEL_ISOLATED_BUILD_WORKER=1 /usr/local/bin/niflhel-pack" + args); e != nil {
		return e
	}
	if e := os.MkdirAll(*output, 0700); e != nil {
		return e
	}
	for _, name := range []string{"kernel", "rootfs.ext4"} {
		if e := execute("scp", "-oBatchMode=yes", "--", host+":"+remote+"/output/"+name, filepath.Join(*output, name)); e != nil {
			return e
		}
	}
	return nil
}
