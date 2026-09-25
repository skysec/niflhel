package daemon

import (
	"context"
	"fmt"
	"niflhel/internal/api"
	"niflhel/internal/base"
	"niflhel/internal/wire"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	if got.State != "failed" || !got.VMResourcesReleased {
		t.Fatal(got)
	}
}

func TestFailedTerminationRetainsVMResourceReservation(t *testing.T) {
	d := testDaemon(t)
	seedArtifacts(t, d)
	mount := api.Mount{Name: "shared", Target: "/data"}
	holder := api.Sandbox{
		ID: api.ID(), Name: "holder", State: "running", Generation: 1,
		Spec: api.Spec{Mounts: []api.Mount{mount}}, GuestMemory: 128 * api.MiB,
	}
	candidate := api.Sandbox{
		ID: api.ID(), Name: "candidate", State: "created", BaseDigest: "local/base:test",
		Spec: api.Spec{Mounts: []api.Mount{mount}}, GuestMemory: 128 * api.MiB,
	}
	if e := d.Store.Create(holder); e != nil {
		t.Fatal(e)
	}
	if e := d.Store.Create(candidate); e != nil {
		t.Fatal(e)
	}

	d.VM = fakeVM{killErr: fmt.Errorf("cannot confirm VMM death")}
	d.finish(holder, &api.Exit{Reason: "control lost", At: time.Now().UTC()})
	got, e := d.Store.Get(holder.ID)
	if e != nil || got.State != "failed" {
		t.Fatal(got, e)
	}
	if got.VMResourcesReleased || !reservesVMResources(got) {
		t.Fatal("unconfirmed termination released VM resources", got)
	}
	if e = d.Recover(); e != nil {
		t.Fatal(e)
	}
	got, e = d.Store.Get(holder.ID)
	if e != nil || got.VMResourcesReleased {
		t.Fatal("recovery released resources without confirming termination", got, e)
	}

	d.VM = fakeVM{}
	if _, e = d.Start(context.Background(), candidate.ID); e == nil || !strings.Contains(e.Error(), "volume shared") {
		t.Fatalf("failed holder did not retain the volume reservation: %v", e)
	}
	if e = d.Remove(context.Background(), holder.ID, true); e != nil {
		t.Fatal(e)
	}
	if _, e = d.Start(context.Background(), candidate.ID); e != nil && strings.Contains(e.Error(), "volume shared") {
		t.Fatalf("confirmed removal did not release the volume reservation: %v", e)
	}
}

func TestVMResourceReservationStates(t *testing.T) {
	for _, tc := range []struct {
		state    string
		released bool
		reserved bool
	}{
		{"creating", false, false}, {"created", false, false},
		{"starting", false, true}, {"running", true, true},
		{"stopping", false, true}, {"exited", false, false},
		{"failed", false, true}, {"failed", true, false},
		{"removing", false, false},
	} {
		v := api.Sandbox{State: tc.state, VMResourcesReleased: tc.released}
		if got := reservesVMResources(v); got != tc.reserved {
			t.Errorf("state %s: reserved=%v, want %v", tc.state, got, tc.reserved)
		}
	}
}

func TestConfirmedStartFailureReleasesVMResources(t *testing.T) {
	d := testDaemon(t)
	seedArtifacts(t, d)
	mount := api.Mount{Name: "shared", Target: "/data"}
	newSandbox := func(name string) api.Sandbox {
		return api.Sandbox{
			ID: api.ID(), Name: name, State: "created", BaseDigest: "local/base:test",
			Spec: api.Spec{Mounts: []api.Mount{mount}}, GuestMemory: 128 * api.MiB,
			VMResourcesReleased: true,
		}
	}
	first := newSandbox("first")
	if e := d.Store.Create(first); e != nil {
		t.Fatal(e)
	}
	if _, e := d.Start(context.Background(), first.ID); e == nil || !strings.Contains(e.Error(), "injected start failure") {
		t.Fatalf("expected injected start failure, got %v", e)
	}
	got, e := d.Store.Get(first.ID)
	if e != nil || got.State != "failed" || !got.VMResourcesReleased || reservesVMResources(got) {
		t.Fatal("confirmed cleanup retained VM resources", got, e)
	}

	second := newSandbox("second")
	if e = d.Store.Create(second); e != nil {
		t.Fatal(e)
	}
	if _, e = d.Start(context.Background(), second.ID); e == nil || !strings.Contains(e.Error(), "injected start failure") {
		t.Fatalf("confirmed-clean failed holder blocked sequential volume reuse: %v", e)
	}
}
