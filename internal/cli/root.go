package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"niflhel/internal/api"
	"niflhel/internal/daemon"
	"niflhel/internal/wire"
	"os"
	"time"
)

type ExitError struct{ Code int }

func (e ExitError) Error() string { return fmt.Sprintf("process exited with code %d", e.Code) }

type App struct {
	In     io.Reader
	Out    io.Writer
	Err    io.Writer
	Socket string
}

func (a *App) client() *wire.Client { return wire.Unix(a.Socket) }
func (a *App) call(ctx context.Context, q api.Request, out any) error {
	return a.client().Call(ctx, q, out)
}
func (a *App) print(v any) error {
	enc := json.NewEncoder(a.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
func New(in io.Reader, out, errout io.Writer) *cobra.Command {
	a := &App{In: in, Out: out, Err: errout, Socket: os.Getenv("NIFLHEL_SOCKET")}
	if a.Socket == "" {
		a.Socket = "/run/niflhel/niflhel.sock"
	}
	root := &cobra.Command{Use: "niflhel", Short: "One OCI application container per Firecracker microVM", SilenceUsage: true, SilenceErrors: true}
	root.SetIn(in)
	root.SetOut(out)
	root.SetErr(errout)
	root.PersistentFlags().StringVar(&a.Socket, "socket", a.Socket, "niflheld Unix socket")
	root.AddCommand(a.lifecycle(false)...)
	container := &cobra.Command{Use: "container", Short: "Manage application containers"}
	container.AddCommand(a.lifecycle(true)...)
	root.AddCommand(container)
	root.AddCommand(a.imageCommands()...)
	root.AddCommand(a.baseCommands())
	root.AddCommand(a.volumeCommands())
	root.AddCommand(a.buildCommand(false))
	root.AddCommand(&cobra.Command{Use: "version", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error { fmt.Fprintln(a.Out, api.Version); return nil }})
	root.AddCommand(&cobra.Command{Use: "info", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		var v any
		if e := a.call(c.Context(), api.Request{Action: "info"}, &v); e != nil {
			return e
		}
		return a.print(v)
	}})
	root.AddCommand(a.doctor())
	root.AddCommand(a.login(false))
	root.AddCommand(a.login(true))
	return root
}
func (a *App) lifecycle(alias bool) []*cobra.Command {
	out := []*cobra.Command{a.run(false), a.run(true), a.execCommand(), a.copyCommand()}
	for _, name := range []string{"start", "stop", "restart", "kill", "rm", "inspect", "wait", "attach"} {
		name := name
		var attach, interactive, force bool
		seconds := 10
		sig := "SIGKILL"
		format := "json"
		c := &cobra.Command{Use: name + " CONTAINER", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
			id := args[0]
			if name == "attach" {
				return a.session(c.Context(), api.Request{Action: "attach", ID: id}, true, false)
			}
			if name == "start" || name == "restart" {
				var v api.Sandbox
				if e := a.call(c.Context(), api.Request{Action: name, ID: id, Timeout: seconds}, &v); e != nil {
					return e
				}
				if attach {
					return a.attachOrWait(c.Context(), v, interactive)
				}
				fmt.Fprintln(a.Out, v.ID)
				return nil
			}
			if name == "wait" {
				var v api.Exit
				if e := a.call(c.Context(), api.Request{Action: "wait", ID: id}, &v); e != nil {
					return e
				}
				if v.Code == nil {
					return fmt.Errorf("%s", v.Reason)
				}
				fmt.Fprintln(a.Out, *v.Code)
				return nil
			}
			if name == "inspect" {
				if format != "json" {
					return fmt.Errorf("only --format json supported")
				}
				var v api.Sandbox
				if e := a.call(c.Context(), api.Request{Action: name, ID: id}, &v); e != nil {
					return e
				}
				v.Spec.Env = nil
				v.Process.Env = nil
				return a.print(v)
			}
			if e := a.call(c.Context(), api.Request{Action: name, ID: id, Timeout: seconds, Force: force, Signal: sig}, nil); e != nil {
				return e
			}
			fmt.Fprintln(a.Out, id)
			return nil
		}}
		switch name {
		case "start":
			c.Flags().BoolVarP(&attach, "attach", "a", false, "attach and wait")
			c.Flags().BoolVarP(&interactive, "interactive", "i", false, "open stdin")
		case "stop", "restart":
			c.Flags().IntVarP(&seconds, "time", "t", 10, "stop grace period seconds")
		case "kill":
			c.Flags().StringVarP(&sig, "signal", "s", "SIGKILL", "signal application init")
		case "rm":
			c.Flags().BoolVarP(&force, "force", "f", false, "kill before removal")
		case "inspect":
			c.Flags().StringVar(&format, "format", "json", "output format")
		}
		out = append(out, c)
	}
	var all, quiet bool
	format := ""
	ps := &cobra.Command{Use: "ps", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		var rows []api.Sandbox
		if e := a.call(c.Context(), api.Request{Action: "ps"}, &rows); e != nil {
			return e
		}
		selected := []api.Sandbox{}
		for _, v := range rows {
			if all || v.State == "running" {
				selected = append(selected, v)
			}
		}
		if format != "" && format != "json" {
			return fmt.Errorf("only --format json supported")
		}
		if format == "json" {
			for i := range selected {
				selected[i].Spec.Env = nil
				selected[i].Process.Env = nil
			}
			return a.print(selected)
		}
		if !quiet {
			fmt.Fprintln(a.Out, "CONTAINER ID\tIMAGE\tSTATUS\tNAMES")
		}
		for _, v := range selected {
			if quiet {
				fmt.Fprintln(a.Out, v.ID)
			} else {
				fmt.Fprintf(a.Out, "%s\t%s\t%s\t%s\n", v.ID[:12], v.Spec.Image, v.State, v.Name)
			}
		}
		return nil
	}}
	ps.Flags().BoolVarP(&all, "all", "a", false, "include stopped containers")
	ps.Flags().BoolVarP(&quiet, "quiet", "q", false, "IDs only")
	ps.Flags().StringVar(&format, "format", "", "json output")
	out = append(out, ps, a.logs())
	return out
}
func (a *App) run(create bool) *cobra.Command {
	spec := api.DefaultSpec()
	name := "run"
	if create {
		name = "create"
	}
	var detach bool
	var memory, disk, entry string
	var envFiles, ports, mounts, volumes []string
	c := &cobra.Command{Use: name + " [OPTIONS] IMAGE [COMMAND] [ARG...]", Args: cobra.MinimumNArgs(1), RunE: func(c *cobra.Command, args []string) error {
		spec.Image = args[0]
		spec.Command = args[1:]
		var e error
		if spec.Memory, e = api.Size(memory); e != nil {
			return e
		}
		if spec.DiskSize, e = api.Size(disk); e != nil {
			return e
		}
		if c.Flags().Changed("entrypoint") {
			spec.Entrypoint = &entry
		}
		for _, p := range ports {
			v, e := api.ParsePort(p)
			if e != nil {
				return e
			}
			spec.Ports = append(spec.Ports, v)
		}
		for _, m := range append(mounts, volumes...) {
			v, e := api.ParseMount(m)
			if e != nil {
				return e
			}
			spec.Mounts = append(spec.Mounts, v)
		}
		env := []string{}
		for _, p := range envFiles {
			v, e := readEnv(p)
			if e != nil {
				return e
			}
			env = append(env, v...)
		}
		spec.Env = api.MergeEnv(env, spec.Env)
		if e = spec.Validate(); e != nil {
			return e
		}
		if spec.Base == "" {
			var info struct{ DefaultBase string }
			if e = a.call(c.Context(), api.Request{Action: "info"}, &info); e != nil {
				return e
			}
			spec.Base = info.DefaultBase
		}
		auth := daemon.Auth{App: AuthFor(spec.Image), Base: AuthFor(spec.Base)}
		raw, _ := json.Marshal(auth)
		var v api.Sandbox
		if e = a.call(c.Context(), api.Request{Action: "create", Spec: &spec, Data: raw}, &v); e != nil {
			return e
		}
		for _, warning := range v.Warnings {
			fmt.Fprintln(a.Err, warning)
		}
		if create {
			fmt.Fprintln(a.Out, v.ID)
			return nil
		}
		if e = a.call(c.Context(), api.Request{Action: "start", ID: v.ID}, &v); e != nil {
			return fmt.Errorf("%w (inspect/remove retained container %s)", e, v.ID)
		}
		if detach {
			fmt.Fprintln(a.Out, v.ID)
			return nil
		}
		return a.attachOrWait(c.Context(), v, spec.Interactive)
	}}
	f := c.Flags()
	f.SetInterspersed(false)
	f.StringVar(&spec.Name, "name", "", "container name")
	f.StringVar(&spec.Base, "base", "", "signed VM base reference")
	f.BoolVarP(&detach, "detach", "d", false, "run in background")
	f.BoolVarP(&spec.Interactive, "interactive", "i", false, "keep stdin open")
	f.BoolVarP(&spec.TTY, "tty", "t", false, "allocate a terminal")
	f.BoolVar(&spec.AutoRemove, "rm", false, "remove after exit")
	f.IntVar(&spec.CPUs, "cpus", 1, "whole vCPU count")
	f.StringVarP(&memory, "memory", "m", "512m", "application memory limit")
	f.StringVar(&disk, "disk-size", "4g", "state disk size")
	f.Int64Var(&spec.PidsLimit, "pids-limit", 256, "container PID limit")
	f.StringVar(&spec.Network, "network", "bridge", "bridge or none")
	f.StringSliceVarP(&ports, "publish", "p", nil, "[HOST_IP:]HOST_PORT:CONTAINER_PORT")
	f.StringArrayVarP(&spec.Env, "env", "e", nil, "KEY=VALUE")
	f.StringArrayVar(&envFiles, "env-file", nil, "environment file")
	f.StringVarP(&spec.User, "user", "u", "", "container user")
	f.StringVarP(&spec.Workdir, "workdir", "w", "", "container working directory")
	f.StringVar(&entry, "entrypoint", "", "override entrypoint")
	f.StringArrayVar(&mounts, "mount", nil, "type=volume,src=NAME,dst=/PATH")
	f.StringArrayVarP(&volumes, "volume", "v", nil, "NAME:/PATH[:ro]")
	f.BoolVar(&spec.ReadOnly, "read-only", false, "read-only application root")
	f.StringVar(&spec.Pull, "pull", "missing", "missing, always, or never")
	f.StringVar(&spec.Runtime, "runtime", "runc", "guest runtime")
	f.StringVar(&spec.Platform, "platform", "linux/amd64", "image platform")
	return c
}
func (a *App) execCommand() *cobra.Command {
	var q api.Exec
	c := &cobra.Command{Use: "exec [OPTIONS] CONTAINER COMMAND [ARG...]", Args: cobra.MinimumNArgs(2), RunE: func(c *cobra.Command, args []string) error {
		q.ID = api.ID()
		q.Args = args[1:]
		return a.session(c.Context(), api.Request{Action: "exec", ID: args[0], Exec: &q}, q.Interactive, q.TTY)
	}}
	c.Flags().SetInterspersed(false)
	c.Flags().BoolVarP(&q.Interactive, "interactive", "i", false, "stdin")
	c.Flags().BoolVarP(&q.TTY, "tty", "t", false, "terminal")
	c.Flags().StringArrayVarP(&q.Env, "env", "e", nil, "KEY=VALUE")
	c.Flags().StringVarP(&q.User, "user", "u", "", "user")
	c.Flags().StringVarP(&q.Cwd, "workdir", "w", "", "working directory")
	return c
}
func (a *App) attachOrWait(ctx context.Context, v api.Sandbox, interactive bool) error {
	e := a.session(ctx, api.Request{Action: "attach", ID: v.ID}, interactive, v.Spec.TTY)
	if e == nil {
		return nil
	}
	if _, ok := e.(ExitError); ok {
		return e
	}
	// A very short-lived application may already have exited before attach.
	var exit api.Exit
	if err := a.call(ctx, api.Request{Action: "wait", ID: v.ID}, &exit); err != nil {
		return e
	}
	if exit.Code == nil {
		return fmt.Errorf("%s", exit.Reason)
	}
	if *exit.Code != 0 {
		return ExitError{*exit.Code}
	}
	return nil
}
func (a *App) logs() *cobra.Command {
	var follow, timestamps bool
	var tail int
	var since string
	c := &cobra.Command{Use: "logs CONTAINER", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		var after time.Time
		if since != "" {
			var e error
			after, e = time.Parse(time.RFC3339, since)
			if e != nil {
				return e
			}
		}
		var cursor uint64
		initial := []api.Frame{}
		for {
			raw, _ := json.Marshal(cursor)
			var frames []api.Frame
			if e := a.call(c.Context(), api.Request{Action: "logs", ID: args[0], Data: raw}, &frames); e != nil {
				return e
			}
			for _, f := range frames {
				cursor = f.Sequence
				if f.Time.Before(after) {
					continue
				}
				initial = append(initial, f)
			}
			if len(frames) > 0 {
				continue
			}
			if tail >= 0 && len(initial) > tail {
				initial = initial[len(initial)-tail:]
			}
			for _, f := range initial {
				w := a.Out
				if f.Type == "stderr" {
					w = a.Err
				}
				if f.Type == "gap" {
					fmt.Fprintln(a.Err, f.Message)
					continue
				}
				if timestamps {
					fmt.Fprint(w, f.Time.Format(time.RFC3339Nano)+" ")
				}
				w.Write(f.Data)
			}
			initial = nil
			if !follow {
				return nil
			}
			tail = -1
			var v api.Sandbox
			if e := a.call(c.Context(), api.Request{Action: "inspect", ID: args[0]}, &v); e != nil {
				return e
			}
			if v.State == "exited" || v.State == "failed" {
				return nil
			}
			select {
			case <-c.Context().Done():
				return c.Context().Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}}
	c.Flags().BoolVarP(&follow, "follow", "f", false, "follow output")
	c.Flags().IntVar(&tail, "tail", -1, "last N records")
	c.Flags().StringVar(&since, "since", "", "RFC3339 timestamp")
	c.Flags().BoolVar(&timestamps, "timestamps", false, "include timestamps")
	return c
}
func (a *App) volumeCommands() *cobra.Command {
	root := &cobra.Command{Use: "volume"}
	var size string
	create := &cobra.Command{Use: "create NAME", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		n, e := api.Size(size)
		if e != nil {
			return e
		}
		var v api.Volume
		if e = a.call(c.Context(), api.Request{Action: "volume-create", Volume: &api.Volume{Name: args[0], Size: n}}, &v); e != nil {
			return e
		}
		fmt.Fprintln(a.Out, v.Name)
		return nil
	}}
	create.Flags().StringVar(&size, "size", "4g", "volume size")
	root.AddCommand(create)
	for _, name := range []string{"ls", "inspect", "rm"} {
		name := name
		args := cobra.ExactArgs(1)
		use := name + " NAME"
		if name == "ls" {
			args = cobra.NoArgs
			use = name
		}
		root.AddCommand(&cobra.Command{Use: use, Args: args, RunE: func(c *cobra.Command, args []string) error {
			q := api.Request{Action: "volume-" + name}
			if len(args) > 0 {
				q.ID = args[0]
			}
			var v any
			if e := a.call(c.Context(), q, &v); e != nil {
				return e
			}
			return a.print(v)
		}})
	}
	return root
}
func codeFromFrame(f api.Frame) error {
	if f.Code != nil && *f.Code != 0 {
		return ExitError{*f.Code}
	}
	return nil
}
