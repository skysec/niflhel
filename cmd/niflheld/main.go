package main

import (
	"context"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"net/http"
	"niflhel/internal/daemon"
	"niflhel/internal/journal"
	"niflhel/internal/wire"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--log-sink" {
		if e := journal.Sink(os.Args[2], os.Stdin); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	path := flag.String("config", "/etc/niflhel/config.json", "host configuration")
	flag.Parse()
	cfg, e := daemon.Load(*path)
	if e != nil {
		return e
	}
	lockDir := filepath.Dir(cfg.Socket)
	if e = os.MkdirAll(lockDir, 0700); e != nil {
		return e
	}
	lock, e := os.OpenFile(filepath.Join(lockDir, "daemon.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return fmt.Errorf("another niflheld owns this socket: %w", e)
	}
	if st, e := os.Lstat(cfg.Socket); e == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to replace non-socket path")
		}
		if e = os.Remove(cfg.Socket); e != nil {
			return e
		}
	}
	d, e := daemon.New(cfg)
	if e != nil {
		return e
	}
	defer d.Close()
	if e = d.Recover(); e != nil {
		return e
	}
	listener, e := net.Listen("unix", cfg.Socket)
	if e != nil {
		return e
	}
	defer listener.Close()
	defer os.Remove(cfg.Socket)
	if e = os.Chmod(cfg.Socket, 0600); e != nil {
		return e
	}
	if cfg.SocketGroup != "" {
		group, e := user.LookupGroup(cfg.SocketGroup)
		if e != nil {
			return e
		}
		gid, e := strconv.Atoi(group.Gid)
		if e != nil {
			return e
		}
		if e = os.Chown(lockDir, -1, gid); e != nil {
			return e
		}
		if e = os.Chmod(lockDir, 0750); e != nil {
			return e
		}
		if e = os.Chown(cfg.Socket, -1, gid); e != nil {
			return e
		}
		if e = os.Chmod(cfg.Socket, 0660); e != nil {
			return e
		}
	}
	server := &http.Server{Handler: wire.Serve(d), ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(stop)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()
	e = server.Serve(listener)
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}
