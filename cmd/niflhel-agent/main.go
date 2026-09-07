package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/mdlayher/vsock"
	"net/http"
	"niflhel/internal/firecracker"
	"niflhel/internal/guest"
	"niflhel/internal/wire"
	"os"
	"syscall"
	"time"
)

func main() {
	if os.Getpid() != 1 {
		fmt.Fprintln(os.Stderr, "niflhel-agent must be the guest PID 1; refusing to run on the host")
		os.Exit(125)
	}
	if e := serve(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		syscall.Sync()
		time.Sleep(time.Second)
		syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
		os.Exit(125)
	}
}
func serve() error {
	b, e := guest.Initialize()
	if e != nil {
		return e
	}
	if e = guest.Prepare(context.Background(), b); e != nil {
		return e
	}
	cfg, e := firecracker.TLSConfig(b.CA, b.Certificate, b.PrivateKey, "", true)
	if e != nil {
		return e
	}
	l, e := vsock.Listen(1024, nil)
	if e != nil {
		return e
	}
	defer l.Close()
	server := &http.Server{Handler: wire.Serve(guest.New(b)), ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	return server.Serve(tls.NewListener(l, cfg))
}
