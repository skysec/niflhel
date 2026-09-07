//go:build integration

package integration

import (
	"context"
	"niflhel/internal/api"
	"niflhel/internal/wire"
	"os"
	"testing"
	"time"
)

func TestFirecrackerContainer(t *testing.T) {
	socket := os.Getenv("NIFLHEL_INTEGRATION_SOCKET")
	base := os.Getenv("NIFLHEL_INTEGRATION_BASE")
	if socket == "" || base == "" {
		t.Skip("set NIFLHEL_INTEGRATION_SOCKET and NIFLHEL_INTEGRATION_BASE for a root-owned disposable KVM worker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := wire.Unix(socket)
	spec := api.DefaultSpec()
	spec.Image = "busybox:1.37"
	spec.Base = base
	spec.Network = "none"
	spec.Command = []string{"sh", "-c", "echo ready; sleep 30"}
	var v api.Sandbox
	if e := c.Call(ctx, api.Request{Action: "create", Spec: &spec}, &v); e != nil {
		t.Fatal(e)
	}
	defer c.Call(context.Background(), api.Request{Action: "rm", ID: v.ID, Force: true}, nil)
	if e := c.Call(ctx, api.Request{Action: "start", ID: v.ID}, &v); e != nil {
		t.Fatal(e)
	}
	s, e := c.Session(ctx, api.Request{Action: "exec", ID: v.ID, Exec: &api.Exec{ID: api.ID(), Args: []string{"sh", "-c", "test ! -e /bootstrap/bootstrap.json && echo isolated"}}})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	s.Send(api.Frame{Type: "eof"})
	output := ""
	for {
		var f api.Frame
		if e = s.Recv(&f); e != nil {
			t.Fatal(e)
		}
		if f.Type == "error" {
			t.Fatal(f.Message)
		}
		if f.Type == "stdout" {
			output += string(f.Data)
		}
		if f.Type == "exit" {
			if f.Code == nil || *f.Code != 0 {
				t.Fatal(f)
			}
			break
		}
	}
	if output != "isolated\n" {
		t.Fatal(output)
	}
	if e = c.Call(ctx, api.Request{Action: "stop", ID: v.ID, Timeout: 1}, nil); e != nil {
		t.Fatal(e)
	}
	var exit api.Exit
	if e = c.Call(ctx, api.Request{Action: "wait", ID: v.ID}, &exit); e != nil || exit.Code == nil {
		t.Fatal(exit, e)
	}
}
