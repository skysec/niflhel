package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/go-containerregistry/pkg/authn"
	"net"
	"niflhel/internal/api"
	"niflhel/internal/base"
	"niflhel/internal/firecracker"
	"niflhel/internal/fsutil"
	"niflhel/internal/journal"
	"niflhel/internal/network"
	"niflhel/internal/oci"
	"niflhel/internal/state"
	"niflhel/internal/storage"
	"niflhel/internal/wire"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Backend interface {
	Check() error
	Start(context.Context, api.Sandbox, base.Bundle) (int, string, error)
	Ready(context.Context, api.Sandbox) (*wire.Client, error)
	Client(api.Sandbox) (*wire.Client, error)
	Kill(context.Context, api.Sandbox) error
	Remove(api.Sandbox) error
}
type Network interface {
	Prepare(context.Context, api.Sandbox) error
	Remove(context.Context, api.Sandbox) error
}
type Auth struct {
	App  *authn.AuthConfig
	Base *authn.AuthConfig
}
type Daemon struct {
	Config   Config
	Store    *state.Store
	Images   *oci.Store
	Bases    base.Store
	Storage  storage.Manager
	VM       Backend
	Network  Network
	mu       sync.Mutex
	locks    map[string]*sync.Mutex
	monitors map[string]int
	dns      map[string]func()
	ports    map[string][]net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func New(c Config) (*Daemon, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	if e := os.MkdirAll(c.Root, 0700); e != nil {
		return nil, e
	}
	s, e := state.Open(filepath.Join(c.Root, "state.db"))
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	disk := storage.Manager{Root: c.Root}
	d := &Daemon{Config: c, Store: s, Images: oci.New(filepath.Join(c.Root, "images")), Bases: base.Store{Root: filepath.Join(c.Root, "bases"), Trust: c.TrustedKeys}, Storage: disk, VM: firecracker.Manager{Root: c.Root, Firecracker: c.Firecracker, Jailer: c.Jailer, Storage: disk}, Network: network.Manager{}, locks: map[string]*sync.Mutex{}, monitors: map[string]int{}, dns: map[string]func(){}, ports: map[string][]net.Listener{}, ctx: ctx, cancel: cancel}
	return d, nil
}
func (d *Daemon) Close() error {
	d.cancel()
	d.wg.Wait()
	d.mu.Lock()
	for _, f := range d.dns {
		f()
	}
	for _, listeners := range d.ports {
		for _, l := range listeners {
			l.Close()
		}
	}
	d.mu.Unlock()
	return d.Store.Close()
}
func (d *Daemon) lock(id string) func() {
	d.mu.Lock()
	m := d.locks[id]
	if m == nil {
		m = &sync.Mutex{}
		d.locks[id] = m
	}
	d.mu.Unlock()
	m.Lock()
	return m.Unlock
}
func (d *Daemon) dir(id string) string { return filepath.Join(d.Config.Root, "sandboxes", id) }
func (d *Daemon) Create(ctx context.Context, s api.Spec, auth Auth) (api.Sandbox, error) {
	var v api.Sandbox
	if e := s.Validate(); e != nil {
		return v, e
	}
	if s.Base == "" {
		s.Base = d.Config.DefaultBase
	}
	if s.Base == "" {
		return v, fmt.Errorf("no default base configured; set DefaultBase or use --base")
	}
	// Serialize allocations, not ongoing application execution.
	unlock := d.lock("allocations")
	defer unlock()
	all, e := d.Store.List()
	if e != nil {
		return v, e
	}
	used := map[int]bool{}
	for _, existing := range all {
		if existing.Name == s.Name && s.Name != "" {
			return v, fmt.Errorf("name already exists")
		}
		used[existing.Slot] = true
		for _, p := range s.Ports {
			for _, q := range existing.Spec.Ports {
				if p.HostPort == q.HostPort {
					return v, fmt.Errorf("host port %d is reserved", p.HostPort)
				}
			}
		}
	}
	for _, m := range s.Mounts {
		if _, e = d.Store.Volume(m.Name); e != nil {
			return v, e
		}
	}
	slot := 1
	for used[slot] {
		slot++
	}
	if slot > 16000 {
		return v, fmt.Errorf("no address slots available")
	}
	id := api.ID()
	if s.Name == "" {
		s.Name = "nf-" + id[:12]
	}
	now := time.Now().UTC()
	v = api.Sandbox{ID: id, Name: s.Name, Spec: s, State: "creating", Slot: slot, Created: now, Updated: now}
	if e = d.Store.Create(v); e != nil {
		return v, e
	}
	fail := func(err error) (api.Sandbox, error) {
		for _, name := range []string{"app.ext4", "state.ext4"} {
			os.Remove(filepath.Join(d.dir(id), name))
		}
		d.Store.Update(id, func(v *api.Sandbox) error { return state.Transition(v, "failed", err.Error()) })
		return v, err
	}
	if e = os.MkdirAll(d.dir(id), 0700); e != nil {
		return fail(e)
	}
	d.Store.Intent(id, "prepare-images")
	img, e := d.Images.Pull(ctx, s.Image, s.Pull, auth.App)
	if e != nil {
		return fail(e)
	}
	b, e := d.Bases.Pull(ctx, s.Base, s.Pull, auth.Base)
	if e != nil {
		return fail(e)
	}
	p, e := api.Resolve(s, img.Config)
	if e != nil {
		return fail(e)
	}
	if img.Config.Healthcheck {
		v.Warnings = append(v.Warnings, "image healthcheck is unsupported in phase one")
	}
	if len(img.Config.Volumes) > 0 {
		v.Warnings = append(v.Warnings, fmt.Sprintf("image VOLUME paths remain in writable root unless explicitly mounted: %v", img.Config.Volumes))
	}
	v.Process = p
	v.ImageDigest = img.Digest
	v.BaseDigest = b.Digest
	v.GuestMemory = ((s.Memory+api.MiB-1)/api.MiB + b.Signed.Config.GuestReserveMiB) * api.MiB
	d.Store.Intent(id, "prepare-disks")
	tmp, e := os.MkdirTemp(d.dir(id), "carrier-")
	if e != nil {
		return fail(e)
	}
	defer os.RemoveAll(tmp)
	if e = d.Images.Carrier(tmp, img); e != nil {
		return fail(e)
	}
	size := int64(0)
	for _, layer := range img.Layers {
		size += layer.Size
	}
	if e = d.Storage.Disk(ctx, filepath.Join(d.dir(id), "app.ext4"), storage.CarrierSize(size), tmp); e != nil {
		return fail(e)
	}
	if e = d.Storage.Disk(ctx, filepath.Join(d.dir(id), "state.ext4"), s.DiskSize, ""); e != nil {
		return fail(e)
	}
	v.State = "created"
	if e = d.Store.Update(id, func(old *api.Sandbox) error { *old = v; return nil }); e != nil {
		return fail(e)
	}
	return v, nil
}
func (d *Daemon) Start(ctx context.Context, id string) (api.Sandbox, error) {
	v, e := d.Store.Get(id)
	if e != nil {
		return v, e
	}
	unlock := d.lock(v.ID)
	defer unlock()
	v, e = d.Store.Get(v.ID)
	if e != nil {
		return v, e
	}
	if v.State != "created" && v.State != "exited" {
		return v, fmt.Errorf("cannot start sandbox in state %s", v.State)
	}
	if e = d.VM.Check(); e != nil {
		return v, e
	}
	b, e := d.Bases.Get(v.BaseDigest)
	if e != nil {
		return v, e
	}
	alloc := d.lock("allocations")
	all, e := d.Store.List()
	if e != nil {
		alloc()
		return v, e
	}
	for _, x := range all {
		if x.ID == v.ID || !(x.State == "running" || x.State == "starting" || x.State == "stopping") {
			continue
		}
		for _, m := range v.Spec.Mounts {
			for _, n := range x.Spec.Mounts {
				if m.Name == n.Name {
					alloc()
					return v, fmt.Errorf("volume %s already attached to live sandbox", m.Name)
				}
			}
		}
	}
	reserved := v.GuestMemory + 64*api.MiB
	for _, x := range all {
		if x.State == "running" || x.State == "starting" || x.State == "stopping" {
			reserved += x.GuestMemory + 64*api.MiB
		}
	}
	available, budgetErr := availableMemory()
	if budgetErr == nil {
		budgetErr = memoryBudget(reserved, available)
	}
	if budgetErr != nil {
		alloc()
		return v, budgetErr
	}
	v.Generation++
	v.State = "starting"
	v.Exit = nil
	v.Reason = ""
	e = d.Store.Update(v.ID, func(old *api.Sandbox) error { *old = v; return nil })
	alloc()
	if e != nil {
		return v, e
	}
	bootCtx, cancel := context.WithTimeout(d.ctx, time.Duration(d.Config.BootTimeoutSeconds)*time.Second)
	defer cancel()
	fail := func(err error) (api.Sandbox, error) {
		cleanupCtx, cc := context.WithTimeout(context.Background(), 10*time.Second)
		defer cc()
		if killErr := d.VM.Kill(cleanupCtx, v); killErr == nil {
			d.stopDNS(v.ID)
			d.Network.Remove(cleanupCtx, v)
			d.VM.Remove(v)
		}
		d.Store.Update(v.ID, func(x *api.Sandbox) error {
			x.PID = v.PID
			x.PIDStart = v.PIDStart
			return state.Transition(x, "failed", err.Error())
		})
		return v, err
	}
	d.Store.Intent(v.ID, "prepare-network")
	if e = d.reservePorts(v); e != nil {
		return fail(e)
	}
	if e = d.Network.Prepare(bootCtx, v); e != nil {
		return fail(e)
	}
	if v.Spec.Network == "bridge" {
		if e = d.startDNS(v); e != nil {
			return fail(e)
		}
	}
	d.Store.Intent(v.ID, "start-vmm")
	v.PID, v.PIDStart, e = d.VM.Start(bootCtx, v, b)
	if e != nil {
		return fail(e)
	}
	if e = d.Store.Update(v.ID, func(x *api.Sandbox) error { x.PID = v.PID; x.PIDStart = v.PIDStart; return nil }); e != nil {
		return fail(e)
	}
	c, e := d.VM.Ready(bootCtx, v)
	if e != nil {
		return fail(e)
	}
	if e = c.Call(bootCtx, api.Request{Action: "start", Operation: fmt.Sprintf("%s-%d", v.ID, v.Generation)}, nil); e != nil {
		return fail(e)
	}
	if e = d.Store.Update(v.ID, func(x *api.Sandbox) error { return state.Transition(x, "running", "") }); e != nil {
		return fail(e)
	}
	v.State = "running"
	d.monitor(v)
	return v, nil
}
func (d *Daemon) startDNS(s api.Sandbox) error {
	n, e := network.For(s.ID, s.Slot)
	if e != nil {
		return e
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dns[s.ID] != nil {
		return nil
	}
	stop, e := network.DNS(d.ctx, n.HostIP, d.Config.DNSUpstream)
	if e == nil {
		d.dns[s.ID] = stop
	}
	return e
}
func (d *Daemon) stopDNS(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if f := d.dns[id]; f != nil {
		f()
		delete(d.dns, id)
	}
	for _, l := range d.ports[id] {
		l.Close()
	}
	delete(d.ports, id)
}
func (d *Daemon) monitor(v api.Sandbox) {
	d.mu.Lock()
	if d.monitors[v.ID] == v.Generation {
		d.mu.Unlock()
		return
	}
	d.monitors[v.ID] = v.Generation
	d.wg.Add(1)
	d.mu.Unlock()
	go func() {
		defer d.wg.Done()
		defer func() {
			d.mu.Lock()
			if d.monitors[v.ID] == v.Generation {
				delete(d.monitors, v.ID)
			}
			d.mu.Unlock()
		}()
		log := journal.Open(filepath.Join(d.dir(v.ID), "application.log"))
		var cursor uint64
		cursorFile := filepath.Join(d.dir(v.ID), fmt.Sprintf("log-cursor-%d.json", v.Generation))
		fsutil.ReadJSON(cursorFile, &cursor)
		failures := 0
		for {
			select {
			case <-d.ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
			current, e := d.Store.Get(v.ID)
			if e != nil || current.Generation != v.Generation {
				return
			}
			c, e := d.VM.Client(v)
			if e != nil {
				failures++
			} else {
				ctx, cancel := context.WithTimeout(d.ctx, 2*time.Second)
				data, _ := json.Marshal(cursor)
				var frames []api.Frame
				e = c.Call(ctx, api.Request{Action: "logs", Data: data}, &frames)
				if e == nil {
					for _, f := range frames {
						if f.Type == "gap" {
							log.Write("gap", []byte(f.Message))
						} else {
							log.Write(f.Type, f.Data)
						}
						cursor = f.Sequence
					}
					fsutil.JSON(cursorFile, cursor)
				}
				var st api.GuestStatus
				if e == nil {
					e = c.Call(ctx, api.Request{Action: "status"}, &st)
				}
				cancel()
				if e != nil {
					failures++
				} else {
					failures = 0
					if st.ID != v.ID || st.Generation != v.Generation {
						failures = 100
					} else if st.State == "exited" && st.Exit != nil {
						// Drain every remaining bounded batch before stopping the VM.
						for {
							ctx, cancel := context.WithTimeout(d.ctx, 2*time.Second)
							data, _ = json.Marshal(cursor)
							var tail []api.Frame
							e = c.Call(ctx, api.Request{Action: "logs", Data: data}, &tail)
							cancel()
							if e != nil || len(tail) == 0 {
								break
							}
							for _, f := range tail {
								log.Write(f.Type, f.Data)
								cursor = f.Sequence
							}
						}
						d.finish(v, st.Exit)
						return
					}
				}
			}
			if failures >= 5 {
				d.finish(v, &api.Exit{Reason: "guest control lost; application exit status unknown", At: time.Now().UTC()})
				return
			}
		}
	}()
}
func (d *Daemon) finish(v api.Sandbox, exit *api.Exit) {
	unlock := d.lock(v.ID)
	defer unlock()
	current, e := d.Store.Get(v.ID)
	if e != nil || current.Generation != v.Generation {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if c, e := d.VM.Client(v); e == nil {
		if c.Call(ctx, api.Request{Action: "shutdown"}, nil) == nil {
			until := time.Now().Add(5 * time.Second)
			for firecracker.Alive(v) && time.Now().Before(until) && ctx.Err() == nil {
				time.Sleep(20 * time.Millisecond)
			}
		}
	}
	if e = d.VM.Kill(ctx, v); e != nil {
		d.Store.Update(v.ID, func(s *api.Sandbox) error {
			s.State = "failed"
			s.Reason = "VMM termination failed: " + e.Error()
			return nil
		})
		return
	}
	d.stopDNS(v.ID)
	netErr := d.Network.Remove(ctx, v)
	vmErr := d.VM.Remove(v)
	d.Store.Update(v.ID, func(s *api.Sandbox) error {
		s.State = "exited"
		s.Exit = exit
		s.PID = 0
		s.PIDStart = ""
		if netErr != nil || vmErr != nil {
			s.State = "failed"
			s.Reason = fmt.Sprintf("cleanup failed: %v %v", netErr, vmErr)
		}
		return nil
	})
	if current.Spec.AutoRemove && netErr == nil && vmErr == nil {
		if e = d.saveResult(v, exit); e != nil {
			d.Store.Update(v.ID, func(s *api.Sandbox) error { s.Reason = "automatic removal deferred: " + e.Error(); return nil })
			return
		}
		// Retain the small result tombstone for wait delivery, not writable disks.
		d.Store.Intent(v.ID, "auto-remove")
		os.RemoveAll(d.dir(v.ID))
		d.Store.Delete(v.ID)
	}
}
func (d *Daemon) Stop(ctx context.Context, id string, seconds int) error {
	v, e := d.Store.Get(id)
	if e != nil {
		return e
	}
	if v.State == "exited" || v.State == "created" {
		return nil
	}
	if seconds < 0 || seconds > 300 {
		return fmt.Errorf("timeout must be 0..300 seconds")
	}
	d.Store.Update(v.ID, func(s *api.Sandbox) error { return state.Transition(s, "stopping", "") })
	c, e := d.VM.Client(v)
	if e == nil {
		stopctx, cancel := context.WithTimeout(ctx, time.Duration(seconds+2)*time.Second)
		e = c.Call(stopctx, api.Request{Action: "stop", Timeout: seconds}, nil)
		cancel()
	}
	if e != nil {
		d.finish(v, &api.Exit{Reason: "forced VM stop; workload exit status unknown", At: time.Now().UTC()})
	}
	_, e = d.Wait(ctx, v.ID)
	return e
}
func (d *Daemon) Wait(ctx context.Context, id string) (*api.Exit, error) {
	for {
		v, e := d.Store.Get(id)
		if e != nil {
			saved, resultErr := d.findResult(id)
			if resultErr == nil {
				return &saved.Exit, nil
			}
			return nil, e
		}
		if v.State == "created" {
			return nil, fmt.Errorf("container has not started")
		}
		if v.Exit != nil {
			return v.Exit, nil
		}
		if v.State == "failed" {
			return &api.Exit{Reason: v.Reason, At: v.Updated}, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
func (d *Daemon) Remove(ctx context.Context, id string, force bool) error {
	v, e := d.Store.Get(id)
	if e != nil {
		return e
	}
	unlock := d.lock(v.ID)
	defer unlock()
	v, e = d.Store.Get(v.ID)
	if e != nil {
		return e
	}
	if v.State == "running" || v.State == "starting" || v.State == "stopping" {
		if !force {
			return fmt.Errorf("container running; use rm -f")
		}
	}
	d.Store.Intent(v.ID, "remove")
	if e = d.VM.Kill(ctx, v); e != nil {
		return e
	}
	d.stopDNS(v.ID)
	if e = d.Network.Remove(ctx, v); e != nil {
		return e
	}
	if e = d.VM.Remove(v); e != nil {
		return e
	}
	d.Store.Update(v.ID, func(s *api.Sandbox) error { s.State = "removing"; return nil })
	if e = os.RemoveAll(d.dir(v.ID)); e != nil {
		return e
	}
	return d.Store.Delete(v.ID)
}
func (d *Daemon) Recover() error {
	all, e := d.Store.List()
	if e != nil {
		return e
	}
	for _, v := range all {
		switch v.State {
		case "running", "stopping":
			if firecracker.Alive(v) {
				if e = d.reservePorts(v); e != nil {
					return e
				}
				if v.Spec.Network == "bridge" {
					if e = d.startDNS(v); e != nil {
						return e
					}
				}
				d.monitor(v)
			} else {
				d.finish(v, &api.Exit{Reason: "host/VMM stopped; application exit unknown", At: time.Now().UTC()})
			}
		case "creating", "starting", "removing":
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if e = d.VM.Kill(ctx, v); e == nil {
				d.Network.Remove(ctx, v)
				d.VM.Remove(v)
			}
			cancel()
			d.Store.Update(v.ID, func(s *api.Sandbox) error {
				s.State = "failed"
				s.Reason = "interrupted operation; remove and recreate"
				return nil
			})
		}
	}
	return nil
}

func (d *Daemon) reservePorts(v api.Sandbox) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.ports[v.ID]) > 0 {
		return nil
	}
	listeners := []net.Listener{}
	for _, p := range v.Spec.Ports {
		l, e := net.Listen("tcp4", fmt.Sprintf("%s:%d", p.HostIP, p.HostPort))
		if e != nil {
			for _, held := range listeners {
				held.Close()
			}
			return fmt.Errorf("host port unavailable: %w", e)
		}
		listeners = append(listeners, l)
	}
	d.ports[v.ID] = listeners
	return nil
}
