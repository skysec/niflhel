package guest

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/creack/pty"
	"io"
	"niflhel/internal/api"
	"niflhel/internal/fsutil"
	"niflhel/internal/journal"
	rt "niflhel/internal/runtime"
	"niflhel/internal/wire"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Agent struct {
	Boot     api.Bootstrap
	Root     string
	Runtime  string
	Journal  *journal.Journal
	mu       sync.Mutex
	state    string
	exit     *api.Exit
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	terminal *os.File
	pid      int
	op       string
	execs    map[string]bool
}

func New(b api.Bootstrap) *Agent {
	return &Agent{Boot: b, Root: RootPath(), Runtime: "/usr/bin/runc", Journal: journal.Open("/state/application.log"), state: "ready", execs: map[string]bool{}}
}
func (a *Agent) Call(ctx context.Context, q api.Request) (any, error) {
	switch q.Action {
	case "status":
		a.mu.Lock()
		defer a.mu.Unlock()
		return api.GuestStatus{Protocol: api.Protocol, ID: a.Boot.ID, Generation: a.Boot.Generation, State: a.state, Exit: a.exit, PID: a.pid}, nil
	case "start":
		if e := a.start(q.Operation); e != nil {
			return nil, e
		}
		return nil, a.awaitStarted(ctx)
	case "signal":
		return nil, a.signal(ctx, q.Signal)
	case "stop":
		return nil, a.stop(ctx, q.Timeout)
	case "logs":
		var seq uint64
		if len(q.Data) > 0 {
			if e := json.Unmarshal(q.Data, &seq); e != nil {
				return nil, e
			}
		}
		return a.Journal.Read(seq), nil
	case "shutdown":
		a.mu.Lock()
		running := a.state == "running"
		a.mu.Unlock()
		if running {
			return nil, fmt.Errorf("container still running")
		}
		syscall.Sync()
		go func() {
			time.Sleep(100 * time.Millisecond)
			syscall.Sync()
			syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
		}()
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown guest operation %q", q.Action)
	}
}
func (a *Agent) start(op string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if op == "" {
		return fmt.Errorf("operation ID required")
	}
	if a.op == op {
		return nil
	}
	if a.state != "ready" {
		return fmt.Errorf("one container per VM; current state %s", a.state)
	}
	netns := ""
	if a.Boot.Sandbox.Spec.Network == "bridge" {
		netns = "/run/netns/app"
	}
	cfg, e := rt.Build(a.Boot.Sandbox, a.Root, netns)
	if e != nil {
		return e
	}
	if e = fsutil.JSON(filepath.Join(filepath.Dir(a.Root), "config.json"), cfg); e != nil {
		return e
	}
	cmd := exec.Command(a.Runtime, "--root", "/run/niflhel/runc", "run", "--keep", "--bundle", filepath.Dir(a.Root), "--pid-file", "/run/niflhel/app.pid", "app")
	var outDone chan struct{}
	if a.Boot.Sandbox.Spec.TTY {
		f, e := pty.Start(cmd)
		if e != nil {
			return e
		}
		a.terminal = f
		a.stdin = f
		outDone = make(chan struct{})
		go func() { io.Copy(journal.Writer{J: a.Journal, Kind: "stdout"}, f); close(outDone) }()
	} else {
		cmd.Stdout = journal.Writer{J: a.Journal, Kind: "stdout"}
		cmd.Stderr = journal.Writer{J: a.Journal, Kind: "stderr"}
		if a.Boot.Sandbox.Spec.Interactive {
			a.stdin, e = cmd.StdinPipe()
			if e != nil {
				return e
			}
		}
		if e = cmd.Start(); e != nil {
			return e
		}
	}
	a.cmd = cmd
	a.op = op
	a.state = "running"
	go func() {
		e := cmd.Wait()
		if outDone != nil {
			a.terminal.Close()
			<-outDone
		}
		code := 0
		if e != nil {
			code = 125
			if x, ok := e.(*exec.ExitError); ok {
				code = x.ExitCode()
				if code < 0 {
					if ws, ok := x.Sys().(syscall.WaitStatus); ok {
						code = 128 + int(ws.Signal())
					}
				}
			}
		}
		exit := &api.Exit{Code: &code, Reason: "application exited", At: time.Now().UTC()}
		if b, e := os.ReadFile("/sys/fs/cgroup/niflhel/app/memory.events"); e == nil {
			for _, line := range strings.Split(string(b), "\n") {
				parts := strings.Fields(line)
				if len(parts) == 2 && parts[0] == "oom_kill" && parts[1] != "0" {
					exit.OOM = true
					exit.Reason = "application OOM"
				}
			}
		}
		// Kill any remaining children before publishing a terminal state.
		exec.Command(a.Runtime, "--root", "/run/niflhel/runc", "delete", "--force", "app").Run()
		fsutil.JSON("/state/exit.json", exit)
		a.mu.Lock()
		a.state = "exited"
		a.exit = exit
		if a.stdin != nil {
			a.stdin.Close()
		}
		a.mu.Unlock()
	}()
	// runc's pid-file provides the container init PID. Startup only succeeds
	// after it exists, or reports the launcher's early failure.
	return nil
}
func (a *Agent) signal(ctx context.Context, sig string) error {
	if _, e := Signal(sig); e != nil {
		return e
	}
	a.mu.Lock()
	running := a.state == "running"
	a.mu.Unlock()
	if !running {
		return fmt.Errorf("container not running")
	}
	return run(ctx, a.Runtime, "--root", "/run/niflhel/runc", "kill", "app", sig)
}
func Signal(s string) (syscall.Signal, error) {
	names := map[string]syscall.Signal{"TERM": syscall.SIGTERM, "KILL": syscall.SIGKILL, "INT": syscall.SIGINT, "HUP": syscall.SIGHUP, "QUIT": syscall.SIGQUIT, "USR1": syscall.SIGUSR1, "USR2": syscall.SIGUSR2, "WINCH": syscall.SIGWINCH}
	s = strings.TrimPrefix(strings.ToUpper(s), "SIG")
	if n, ok := names[s]; ok {
		return n, nil
	}
	n, e := strconv.Atoi(s)
	if e != nil || n < 1 || n > 64 {
		return 0, fmt.Errorf("invalid signal")
	}
	return syscall.Signal(n), nil
}
func (a *Agent) stop(ctx context.Context, seconds int) error {
	if seconds < 0 || seconds > 300 {
		return fmt.Errorf("invalid stop timeout")
	}
	a.mu.Lock()
	running := a.state == "running"
	a.mu.Unlock()
	if !running {
		return nil
	}
	sig := a.Boot.Sandbox.Process.StopSignal
	if sig == "" {
		sig = "SIGTERM"
	}
	if e := a.signal(ctx, sig); e != nil {
		return e
	}
	timer := time.NewTimer(time.Duration(seconds) * time.Second)
	defer timer.Stop()
	for {
		a.mu.Lock()
		running = a.state == "running"
		a.mu.Unlock()
		if !running {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return a.signal(ctx, "SIGKILL")
		case <-time.After(20 * time.Millisecond):
		}
	}
}
func (a *Agent) Session(ctx context.Context, q api.Request, s *wire.Stream) error {
	switch q.Action {
	case "attach":
		return a.attach(ctx, s)
	case "exec":
		return a.exec(ctx, q, s)
	case "copy-in", "copy-out":
		return a.copy(ctx, q, s)
	default:
		return fmt.Errorf("unsupported guest session")
	}
}
func (a *Agent) attach(ctx context.Context, s *wire.Stream) error {
	a.mu.Lock()
	input := a.stdin
	terminal := a.terminal
	a.mu.Unlock()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			var f api.Frame
			if e := s.Recv(&f); e != nil {
				if input != nil && terminal == nil {
					input.Close()
				}
				return
			}
			switch f.Type {
			case "stdin":
				if input != nil {
					input.Write(f.Data)
				}
			case "eof":
				if input != nil && terminal == nil {
					input.Close()
				}
			case "resize":
				if terminal != nil {
					pty.Setsize(terminal, &pty.Winsize{Rows: f.Height, Cols: f.Width})
				}
			case "signal":
				a.signal(ctx, f.Message)
			case "detach":
				s.Send(api.Frame{Type: "detached"})
				s.Close()
				return
			}
			select {
			case <-done:
				return
			default:
			}
		}
	}()
	var cursor uint64
	for {
		frames := a.Journal.Read(cursor)
		for _, f := range frames {
			if e := s.Send(f); e != nil {
				return e
			}
			cursor = f.Sequence
		}
		a.mu.Lock()
		exit := a.exit
		a.mu.Unlock()
		if exit != nil && len(a.Journal.Read(cursor)) == 0 {
			return s.Send(api.Frame{Type: "exit", Code: exit.Code, Message: exit.Reason})
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.Done():
			return nil
		case <-time.After(30 * time.Millisecond):
		}
	}
}

type streamWriter struct {
	s    *wire.Stream
	kind string
}

func (w streamWriter) Write(b []byte) (int, error) {
	n := len(b)
	for len(b) > 0 {
		k := len(b)
		if k > 32<<10 {
			k = 32 << 10
		}
		if e := w.s.Send(api.Frame{Type: w.kind, Data: append([]byte{}, b[:k]...)}); e != nil {
			return 0, e
		}
		b = b[k:]
	}
	return n, nil
}
func (a *Agent) exec(ctx context.Context, q api.Request, s *wire.Stream) error {
	if q.Exec == nil || len(q.Exec.Args) == 0 || q.Exec.ID == "" {
		return fmt.Errorf("exec ID and arguments required")
	}
	a.mu.Lock()
	if a.state != "running" {
		a.mu.Unlock()
		return fmt.Errorf("container not running")
	}
	if a.execs[q.Exec.ID] {
		a.mu.Unlock()
		return fmt.Errorf("exec ID already submitted; command will not be replayed")
	}
	a.execs[q.Exec.ID] = true
	a.mu.Unlock()
	cfg, e := rt.Build(a.Boot.Sandbox, a.Root, "")
	if e != nil {
		return e
	}
	p := cfg.Process
	p.Args = q.Exec.Args
	p.Env = api.MergeEnv(p.Env, q.Exec.Env)
	p.Terminal = q.Exec.TTY
	if q.Exec.Cwd != "" {
		if !filepath.IsAbs(q.Exec.Cwd) {
			return fmt.Errorf("exec workdir must be absolute")
		}
		p.Cwd = q.Exec.Cwd
	}
	if q.Exec.User != "" {
		p.User, e = rt.User(a.Root, q.Exec.User)
		if e != nil {
			return e
		}
	}
	procFile := filepath.Join("/run/niflhel", "exec-"+api.ID()+".json")
	defer os.Remove(procFile)
	if e = fsutil.JSON(procFile, p); e != nil {
		return e
	}
	cmd := exec.Command(a.Runtime, "--root", "/run/niflhel/runc", "exec", "--process", procFile, "app")
	var input io.WriteCloser
	var terminal *os.File
	var outDone chan struct{}
	if p.Terminal {
		terminal, e = pty.Start(cmd)
		if e != nil {
			return e
		}
		defer terminal.Close()
		input = terminal
		outDone = make(chan struct{})
		go func() { io.Copy(streamWriter{s, "stdout"}, terminal); close(outDone) }()
	} else {
		cmd.Stdout = streamWriter{s, "stdout"}
		cmd.Stderr = streamWriter{s, "stderr"}
		if q.Exec.Interactive {
			input, e = cmd.StdinPipe()
			if e != nil {
				return e
			}
		}
		if e = cmd.Start(); e != nil {
			return e
		}
	}
	go func() {
		for {
			var f api.Frame
			if e := s.Recv(&f); e != nil {
				if input != nil && terminal == nil {
					input.Close()
				}
				return
			}
			switch f.Type {
			case "stdin":
				if input != nil {
					input.Write(f.Data)
				}
			case "eof":
				if input != nil && terminal == nil {
					input.Close()
				}
			case "resize":
				if terminal != nil {
					pty.Setsize(terminal, &pty.Winsize{Rows: f.Height, Cols: f.Width})
				}
			case "signal":
				sig, e := Signal(f.Message)
				if e == nil {
					cmd.Process.Signal(sig)
				}
			}
		}
	}()
	e = cmd.Wait()
	if terminal != nil {
		terminal.Close()
		<-outDone
	}
	code := 0
	if e != nil {
		code = 125
		if x, ok := e.(*exec.ExitError); ok {
			code = x.ExitCode()
			if code < 0 {
				code = 137
			}
		}
	}
	return s.Send(api.Frame{Type: "exit", Code: &code})
}

func (a *Agent) awaitStarted(ctx context.Context) error {
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for {
		b, e := os.ReadFile("/run/niflhel/app.pid")
		if e == nil {
			pid, e := strconv.Atoi(strings.TrimSpace(string(b)))
			if e == nil && pid > 1 {
				a.mu.Lock()
				a.pid = pid
				a.mu.Unlock()
				return nil
			}
		}
		a.mu.Lock()
		exit := a.exit
		a.mu.Unlock()
		if exit != nil {
			return fmt.Errorf("container runtime exited before init was started: %s", exit.Reason)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("container init start timeout")
		case <-time.After(10 * time.Millisecond):
		}
	}
}
