package daemon

import (
	"context"
	"fmt"
	"niflhel/internal/api"
	"niflhel/internal/base"
	"niflhel/internal/wire"
	"path/filepath"
	"testing"
)

type fakeVM struct{ killErr error }

func (fakeVM) Check() error { return nil }
func (fakeVM) Start(context.Context, api.Sandbox, base.Bundle) (int, string, error) {
	return 0, "", fmt.Errorf("injected start failure")
}
func (fakeVM) Ready(context.Context, api.Sandbox) (*wire.Client, error) {
	return nil, fmt.Errorf("not ready")
}
func (fakeVM) Client(api.Sandbox) (*wire.Client, error)  { return nil, fmt.Errorf("offline") }
func (f fakeVM) Kill(context.Context, api.Sandbox) error { return f.killErr }
func (fakeVM) Remove(api.Sandbox) error                  { return nil }

type fakeNet struct{}

func (fakeNet) Prepare(context.Context, api.Sandbox) error { return nil }
func (fakeNet) Remove(context.Context, api.Sandbox) error  { return nil }
func testDaemon(t *testing.T) *Daemon {
	t.Helper()
	c := DefaultConfig()
	c.Root = t.TempDir()
	c.Socket = filepath.Join(c.Root, "sock")
	d, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	d.VM = fakeVM{}
	d.Network = fakeNet{}
	t.Cleanup(func() { d.Close() })
	return d
}
func TestUnsupportedRejectedBeforeAllocation(t *testing.T) {
	d := testDaemon(t)
	s := api.DefaultSpec()
	s.Image = "x"
	s.Runtime = "runsc"
	if _, e := d.Create(context.Background(), s, Auth{}); e == nil {
		t.Fatal("runsc accepted")
	}
	v, _ := d.Store.List()
	if len(v) != 0 {
		t.Fatal("invalid spec allocated resources")
	}
}
func TestRemoveRequiresDeathAndForce(t *testing.T) {
	d := testDaemon(t)
	v := api.Sandbox{ID: api.ID(), Name: "live", State: "running", Spec: api.DefaultSpec()}
	d.Store.Create(v)
	if e := d.Remove(context.Background(), v.ID, false); e == nil {
		t.Fatal("removed live container without force")
	}
	d.VM = fakeVM{killErr: fmt.Errorf("cannot reap")}
	if e := d.Remove(context.Background(), v.ID, true); e == nil {
		t.Fatal("removed despite failed kill")
	}
	if _, e := d.Store.Get(v.ID); e != nil {
		t.Fatal("lost retained state")
	}
	d.VM = fakeVM{}
	if e := d.Remove(context.Background(), v.ID, true); e != nil {
		t.Fatal(e)
	}
}
func TestInterruptedRecovery(t *testing.T) {
	d := testDaemon(t)
	v := api.Sandbox{ID: api.ID(), Name: "partial", State: "creating"}
	d.Store.Create(v)
	if e := d.Recover(); e != nil {
		t.Fatal(e)
	}
	got, _ := d.Store.Get(v.ID)
	if got.State != "failed" {
		t.Fatal(got)
	}
}
