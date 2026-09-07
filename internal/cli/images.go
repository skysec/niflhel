package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"niflhel/internal/api"
	"niflhel/internal/daemon"
	"niflhel/internal/filecopy"
	"os"
	"path/filepath"
	"strings"
)

func (a *App) imageCommands() []*cobra.Command {
	makeCommand := func(use, action string, n int) *cobra.Command {
		return &cobra.Command{Use: use, Args: cobra.ExactArgs(n), RunE: func(c *cobra.Command, args []string) error {
			q := api.Request{Action: action}
			if len(args) > 0 {
				q.Ref = args[0]
				q.Data, _ = json.Marshal(daemon.Auth{App: AuthFor(q.Ref)})
			}
			var v any
			if e := a.call(c.Context(), q, &v); e != nil {
				return e
			}
			return a.print(v)
		}}
	}
	group := &cobra.Command{Use: "image"}
	group.AddCommand(makeCommand("inspect IMAGE", "image-inspect", 1), makeCommand("rm IMAGE", "image-rm", 1), makeCommand("ls", "images", 0), makeCommand("pull IMAGE", "pull", 1))
	load := &cobra.Command{Use: "load --tag IMAGE FILE", Args: cobra.ExactArgs(1)}
	var tag string
	load.Flags().StringVarP(&tag, "tag", "t", "", "local image reference")
	load.RunE = func(c *cobra.Command, args []string) error {
		if tag == "" {
			return fmt.Errorf("--tag required")
		}
		f, e := os.Open(args[0])
		if e != nil {
			return e
		}
		defer f.Close()
		return a.upload(c.Context(), "image-load", tag, f)
	}
	group.AddCommand(load)
	return []*cobra.Command{makeCommand("pull IMAGE", "pull", 1), makeCommand("images", "images", 0), group}
}
func (a *App) baseCommands() *cobra.Command {
	root := &cobra.Command{Use: "base", Short: "Build, verify, and distribute signed Firecracker bases"}
	for _, name := range []string{"pull", "push", "ls", "inspect", "rm", "validate"} {
		name := name
		n := 1
		use := name + " REFERENCE"
		if name == "ls" {
			n = 0
			use = name
		}
		root.AddCommand(&cobra.Command{Use: use, Args: cobra.ExactArgs(n), RunE: func(c *cobra.Command, args []string) error {
			q := api.Request{Action: "base-" + name}
			if len(args) > 0 {
				q.Ref = args[0]
				q.Data, _ = json.Marshal(daemon.Auth{App: AuthFor("busybox:1.37"), Base: AuthFor(q.Ref)})
			}
			var v any
			if e := a.call(c.Context(), q, &v); e != nil {
				return e
			}
			return a.print(v)
		}})
	}
	var tag string
	load := &cobra.Command{Use: "load --tag REFERENCE DIRECTORY", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		if tag == "" {
			return fmt.Errorf("--tag required")
		}
		r, w := io.Pipe()
		go func() { e := filecopy.Archive(args[0], ".", w); w.CloseWithError(e) }()
		defer r.Close()
		return a.upload(c.Context(), "base-load", tag, r)
	}}
	load.Flags().StringVarP(&tag, "tag", "t", "", "base reference")
	root.AddCommand(load, a.buildCommand(true), a.keygen())
	return root
}
func (a *App) upload(ctx context.Context, action, ref string, r io.Reader) error {
	s, e := a.client().Session(ctx, api.Request{Action: action, Ref: ref})
	if e != nil {
		return e
	}
	defer s.Close()
	errch := make(chan error, 1)
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, e := r.Read(buf)
			if n > 0 {
				if err := s.Send(api.Frame{Type: "data", Data: append([]byte{}, buf[:n]...)}); err != nil {
					errch <- err
					return
				}
			}
			if e != nil {
				if e == io.EOF {
					e = s.Send(api.Frame{Type: "eof"})
				}
				errch <- e
				return
			}
		}
	}()
	for {
		var f api.Frame
		if e = s.Recv(&f); e != nil {
			return e
		}
		if f.Type == "error" {
			return fmt.Errorf("%s", f.Message)
		}
		if f.Type == "exit" {
			if e := <-errch; e != nil {
				return e
			}
			fmt.Fprintln(a.Out, f.Message)
			return nil
		}
	}
}
func (a *App) copyCommand() *cobra.Command {
	return &cobra.Command{Use: "cp SRC DEST", Short: "Copy regular files/directories to a destination directory", Args: cobra.ExactArgs(2), RunE: func(c *cobra.Command, args []string) error {
		split := func(s string) (string, string, bool) {
			id, p, ok := strings.Cut(s, ":")
			return id, p, ok && !strings.HasPrefix(s, "/")
		}
		sid, src, sremote := split(args[0])
		did, dst, dremote := split(args[1])
		if sremote == dremote {
			return fmt.Errorf("exactly one path must be CONTAINER:/path")
		}
		if dremote {
			source, e := filepath.Abs(args[0])
			if e != nil {
				return e
			}
			parent := filepath.Dir(source)
			name := filepath.Base(source)
			if st, e := os.Stat(source); e == nil && st.IsDir() {
				parent = source
				name = "."
			}
			s, e := a.client().Session(c.Context(), api.Request{Action: "copy-in", ID: did, Path: dst})
			if e != nil {
				return e
			}
			defer s.Close()
			done := make(chan error, 1)
			go func() {
				e := filecopy.Archive(parent, name, sessionDataWriter{s})
				if e == nil {
					e = s.Send(api.Frame{Type: "eof"})
				}
				done <- e
			}()
			var f api.Frame
			if e = s.Recv(&f); e != nil {
				return e
			}
			if f.Type == "error" {
				return fmt.Errorf("%s", f.Message)
			}
			if f.Type != "exit" {
				return fmt.Errorf("invalid copy response")
			}
			return <-done
		}
		dest, e := filepath.Abs(args[1])
		if e != nil {
			return e
		}
		if e = os.MkdirAll(dest, 0755); e != nil {
			return e
		}
		s, e := a.client().Session(c.Context(), api.Request{Action: "copy-out", ID: sid, Path: src})
		if e != nil {
			return e
		}
		defer s.Close()
		r, w := io.Pipe()
		defer r.Close()
		go func() {
			defer w.Close()
			for {
				var f api.Frame
				if e := s.Recv(&f); e != nil {
					w.CloseWithError(e)
					return
				}
				if f.Type == "exit" {
					return
				}
				if f.Type == "error" {
					w.CloseWithError(fmt.Errorf("%s", f.Message))
					return
				}
				if f.Type != "data" {
					w.CloseWithError(fmt.Errorf("invalid copy frame"))
					return
				}
				if _, e := w.Write(f.Data); e != nil {
					return
				}
			}
		}()
		return filecopy.Extract(dest, ".", r)
	}}
}

type sender interface{ Send(any) error }
type sessionDataWriter struct{ s sender }

func (w sessionDataWriter) Write(b []byte) (int, error) {
	n := len(b)
	for len(b) > 0 {
		k := len(b)
		if k > 32<<10 {
			k = 32 << 10
		}
		if e := w.s.Send(api.Frame{Type: "data", Data: append([]byte{}, b[:k]...)}); e != nil {
			return 0, e
		}
		b = b[k:]
	}
	return n, nil
}
