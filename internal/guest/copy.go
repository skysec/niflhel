package guest

import (
	"context"
	"fmt"
	"io"
	"niflhel/internal/api"
	"niflhel/internal/filecopy"
	"niflhel/internal/wire"
	"os"
	"strconv"
	"strings"
)

func (a *Agent) copy(ctx context.Context, q api.Request, s *wire.Stream) error {
	a.mu.Lock()
	running := a.state == "running"
	a.mu.Unlock()
	if !running {
		return fmt.Errorf("copy requires a running container")
	}
	b, e := os.ReadFile("/run/niflhel/app.pid")
	if e != nil {
		return e
	}
	pid, e := strconv.Atoi(strings.TrimSpace(string(b)))
	if e != nil || pid < 2 {
		return fmt.Errorf("invalid container PID")
	}
	root := fmt.Sprintf("/proc/%d/root", pid)
	rootDir, e := os.Open(root)
	if e != nil {
		return e
	}
	defer rootDir.Close()
	if q.Action == "copy-out" {
		if e = filecopy.ArchiveRoot(rootDir, q.Path, streamWriter{s, "data"}); e != nil {
			return e
		}
		return s.Send(api.Frame{Type: "exit"})
	}
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
			if f.Type == "eof" {
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
	if e = filecopy.ExtractRoot(rootDir, q.Path, r); e != nil {
		return e
	}
	return s.Send(api.Frame{Type: "exit"})
}
