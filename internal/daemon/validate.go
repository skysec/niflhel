package daemon

import (
	"context"
	"fmt"
	"niflhel/internal/api"
	"niflhel/internal/fsutil"
	"path/filepath"
	"time"
)

type Validation struct {
	BaseDigest      string
	Firecracker     string
	At              time.Time
	ApplicationExit int
}

func (d *Daemon) ValidateBase(ctx context.Context, ref string, auth Auth) (Validation, error) {
	var report Validation
	b, e := d.Bases.Get(ref)
	if e != nil {
		return report, e
	}
	s := api.DefaultSpec()
	s.Image = "busybox:1.37"
	s.Base = b.Digest
	s.Network = "none"
	s.Command = []string{"sh", "-c", "echo niflhel-base-ready; sleep 30"}
	v, e := d.Create(ctx, s, auth)
	if e != nil {
		return report, e
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		d.Remove(cleanup, v.ID, true)
	}()
	v, e = d.Start(ctx, v.ID)
	if e != nil {
		return report, e
	}
	client, e := d.VM.Client(v)
	if e != nil {
		return report, e
	}
	stream, e := client.Session(ctx, api.Request{Action: "exec", Exec: &api.Exec{ID: api.ID(), Args: []string{"sh", "-c", "test ! -e /bootstrap/bootstrap.json && printf niflhel-exec-ready"}}})
	if e != nil {
		return report, e
	}
	defer stream.Close()
	stream.Send(api.Frame{Type: "eof"})
	output := ""
	for {
		var f api.Frame
		if e = stream.Recv(&f); e != nil {
			return report, e
		}
		if f.Type == "error" {
			return report, fmt.Errorf("%s", f.Message)
		}
		if f.Type == "stdout" {
			output += string(f.Data)
			if len(output) > 1024 {
				return report, fmt.Errorf("unexpected probe output")
			}
		}
		if f.Type == "exit" {
			if f.Code == nil || *f.Code != 0 || output != "niflhel-exec-ready" {
				return report, fmt.Errorf("guest exec smoke test failed")
			}
			break
		}
	}
	if e = d.Stop(ctx, v.ID, 1); e != nil {
		return report, e
	}
	exit, e := d.Wait(ctx, v.ID)
	if e != nil {
		return report, e
	}
	if exit.Code == nil {
		return report, fmt.Errorf("guest exit status unavailable")
	}
	report = Validation{BaseDigest: b.Digest, Firecracker: d.Config.Firecracker, At: time.Now().UTC(), ApplicationExit: *exit.Code}
	return report, fsutil.JSON(filepath.Join(d.Config.Root, "bases", "validated", b.Digest[7:]+".json"), report)
}
