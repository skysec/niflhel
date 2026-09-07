package cli

import (
	"context"
	"fmt"
	"golang.org/x/term"
	"niflhel/internal/api"
	"os"
	"os/signal"
	"syscall"
)

func (a *App) session(ctx context.Context, q api.Request, interactive, tty bool) error {
	s, e := a.client().Session(ctx, q)
	if e != nil {
		return e
	}
	defer s.Close()
	var fd int
	fd = -1
	if f, ok := a.In.(*os.File); ok && tty {
		fd = int(f.Fd())
		if !term.IsTerminal(fd) {
			return fmt.Errorf("stdin is not a terminal")
		}
		old, e := term.MakeRaw(fd)
		if e != nil {
			return e
		}
		defer term.Restore(fd, old)
		w, h, _ := term.GetSize(fd)
		s.Send(api.Frame{Type: "resize", Width: uint16(w), Height: uint16(h)})
	}
	done := make(chan struct{})
	defer close(done)
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGWINCH, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				s.Close()
				return
			case sig := <-sigs:
				if sig == syscall.SIGWINCH {
					if fd >= 0 {
						w, h, _ := term.GetSize(fd)
						s.Send(api.Frame{Type: "resize", Width: uint16(w), Height: uint16(h)})
					}
				} else {
					s.Send(api.Frame{Type: "signal", Message: fmt.Sprint(int(sig.(syscall.Signal)))})
				}
			}
		}
	}()
	if interactive {
		go func() {
			buf := make([]byte, 32<<10)
			pending := false
			for {
				n, e := a.In.Read(buf)
				if n > 0 {
					out := []byte{}
					for _, b := range buf[:n] {
						if tty && pending {
							if b == 17 {
								s.Send(api.Frame{Type: "detach"})
								return
							}
							out = append(out, 16)
							pending = false
						}
						if tty && b == 16 {
							pending = true
						} else {
							out = append(out, b)
						}
					}
					if len(out) > 0 {
						if e := s.Send(api.Frame{Type: "stdin", Data: out}); e != nil {
							return
						}
					}
				}
				if e != nil {
					if pending {
						s.Send(api.Frame{Type: "stdin", Data: []byte{16}})
					}
					s.Send(api.Frame{Type: "eof"})
					return
				}
			}
		}()
	} else {
		s.Send(api.Frame{Type: "eof"})
	}
	for {
		var f api.Frame
		if e = s.Recv(&f); e != nil {
			return e
		}
		switch f.Type {
		case "stdout":
			if _, e = a.Out.Write(f.Data); e != nil {
				return e
			}
		case "stderr":
			if _, e = a.Err.Write(f.Data); e != nil {
				return e
			}
		case "gap":
			fmt.Fprintln(a.Err, f.Message)
		case "error":
			return fmt.Errorf("%s", f.Message)
		case "exit":
			return codeFromFrame(f)
		case "detached":
			return nil
		default:
			return fmt.Errorf("unknown stream frame %q", f.Type)
		}
	}
}
