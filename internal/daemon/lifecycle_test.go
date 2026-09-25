package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"net"
	"net/http"
	"niflhel/internal/api"
	"niflhel/internal/base"
	"niflhel/internal/fsutil"
	"niflhel/internal/oci"
	"niflhel/internal/wire"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type noFormat struct{}

func (noFormat) Run(context.Context, string, ...string) error { return nil }

type simulatedGuest struct {
	mu         sync.Mutex
	id         string
	generation int
	state      string
}

func (g *simulatedGuest) Call(_ context.Context, q api.Request) (any, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch q.Action {
	case "start":
		g.state = "running"
		return nil, nil
	case "status":
		st := api.GuestStatus{Protocol: 1, ID: g.id, Generation: g.generation, State: g.state}
		if g.state == "exited" {
			code := 7
			st.Exit = &api.Exit{Code: &code, Reason: "test application exit", At: time.Now().UTC()}
		}
		return st, nil
	case "logs":
		return []api.Frame{}, nil
	case "stop":
		g.state = "exited"
		return nil, nil
	case "shutdown":
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected operation %s", q.Action)
}
func (g *simulatedGuest) Session(context.Context, api.Request, *wire.Stream) error {
	return fmt.Errorf("not used")
}

type simulatedVM struct {
	fakeVM
	guest   *simulatedGuest
	client  *wire.Client
	started int
}

func (v *simulatedVM) Start(_ context.Context, s api.Sandbox, _ base.Bundle) (int, string, error) {
	v.guest.mu.Lock()
	v.guest.id = s.ID
	v.guest.generation = s.Generation
	v.guest.state = "ready"
	v.guest.mu.Unlock()
	v.started++
	return 0, "simulated", nil
}
func (v *simulatedVM) Ready(context.Context, api.Sandbox) (*wire.Client, error) { return v.client, nil }
func (v *simulatedVM) Client(api.Sandbox) (*wire.Client, error)                 { return v.client, nil }
func seedArtifacts(t *testing.T, d *Daemon) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	d.Bases.Trust = map[string]string{"test": base64.StdEncoding.EncodeToString(pub)}
	tmp := t.TempDir()
	kernel := make([]byte, 20)
	copy(kernel, []byte{127, 'E', 'L', 'F', 2, 1})
	kernel[18] = 62
	root := []byte("test rootfs")
	kp := filepath.Join(tmp, "kernel")
	rp := filepath.Join(tmp, "root")
	os.WriteFile(kp, kernel, 0600)
	os.WriteFile(rp, root, 0600)
	cfg := base.Config{SchemaVersion: 1, OS: "linux", Architecture: "amd64", AgentProtocol: 1, InitPath: "/sbin/niflhel-init", Runtime: "runc", GuestReserveMiB: 128, FirecrackerVersions: []string{"test"}, Kernel: oci.Descriptor{Digest: fsutil.Digest(kernel), Size: int64(len(kernel))}, RootFS: oci.Descriptor{Digest: fsutil.Digest(root), Size: int64(len(root))}}
	signed, e := base.Sign(cfg, "test", key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = d.Bases.Import("local/base:test", signed, kp, rp); e != nil {
		t.Fatal(e)
	}
	img, e := mutate.ConfigFile(empty.Image, &v1.ConfigFile{OS: "linux", Architecture: "amd64", Config: v1.Config{Cmd: []string{"/bin/app"}}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = d.Images.Import(context.Background(), "local/app:test", img); e != nil {
		t.Fatal(e)
	}
}
func TestLifecycleAcrossGuestRPC(t *testing.T) {
	d := testDaemon(t)
	seedArtifacts(t, d)
	d.Storage.Runner = noFormat{}
	socket := filepath.Join(t.TempDir(), "guest.sock")
	l, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	g := &simulatedGuest{}
	server := &http.Server{Handler: wire.Serve(g)}
	go server.Serve(l)
	defer server.Close()
	vm := &simulatedVM{guest: g, client: wire.Unix(socket)}
	d.VM = vm
	spec := api.DefaultSpec()
	spec.Image = "local/app:test"
	spec.Base = "local/base:test"
	spec.Pull = "never"
	spec.Network = "none"
	spec.DiskSize = 64 * api.MiB
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	v, e := d.Create(ctx, spec, Auth{})
	if e != nil {
		t.Fatal(e)
	}
	if v.State != "created" {
		t.Fatal(v)
	}
	v, e = d.Start(ctx, v.ID)
	if e != nil {
		t.Fatal(e)
	}
	if v.State != "running" || v.Generation != 1 {
		t.Fatal(v)
	}
	if _, e = d.Start(ctx, v.ID); e == nil {
		t.Fatal("duplicate start allowed")
	}
	if e = d.Stop(ctx, v.ID, 1); e != nil {
		t.Fatal(e)
	}
	exit, e := d.Wait(ctx, v.ID)
	if e != nil || exit.Code == nil || *exit.Code != 7 {
		t.Fatal(exit, e)
	}
	v, e = d.Start(ctx, v.ID)
	if e != nil {
		t.Fatal(e)
	}
	if v.Generation != 2 || vm.started != 2 {
		t.Fatal(v)
	}
	if e = d.Remove(ctx, v.ID, true); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(d.dir(v.ID)); !os.IsNotExist(e) {
		t.Fatal("writable state not removed")
	}
}
func TestResultIdentityAndRetention(t *testing.T) {
	d := testDaemon(t)
	v := api.Sandbox{ID: api.ID(), Name: "short-job"}
	os.MkdirAll(d.dir(v.ID), 0700)
	os.WriteFile(filepath.Join(d.dir(v.ID), "application.log"), []byte(""), 0600)
	code := 0
	if e := d.saveResult(v, &api.Exit{Code: &code, At: time.Now()}); e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{v.ID, v.Name, v.ID[:12]} {
		got, e := d.findResult(key)
		if e != nil || got.ID != v.ID {
			t.Fatal(got, e)
		}
	}
	if _, e := d.findResult("../../escape"); e == nil {
		t.Fatal("unsafe result lookup accepted")
	}
	old := time.Now().Add(-resultRetention - time.Minute)
	for _, ext := range []string{".json", ".log"} {
		if e := os.Chtimes(filepath.Join(d.Config.Root, "results", v.ID+ext), old, old); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := d.findResult(v.ID); e == nil {
		t.Fatal("expired result remained readable")
	}
	for _, ext := range []string{".json", ".log"} {
		if _, e := os.Stat(filepath.Join(d.Config.Root, "results", v.ID+ext)); !os.IsNotExist(e) {
			t.Fatal("expired result artifact was not pruned", ext, e)
		}
	}
}

func TestExpiredResultsPrunedAtStartup(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "results")
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	id := api.ID()
	code := 0
	if e := fsutil.JSON(filepath.Join(dir, id+".json"), result{Exit: api.Exit{Code: &code}, ID: id, Name: "expired"}); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, id+".log"), []byte("secret"), 0600); e != nil {
		t.Fatal(e)
	}
	old := time.Now().Add(-resultRetention - time.Minute)
	for _, ext := range []string{".json", ".log"} {
		if e := os.Chtimes(filepath.Join(dir, id+ext), old, old); e != nil {
			t.Fatal(e)
		}
	}
	cfg := DefaultConfig()
	cfg.Root = root
	cfg.Socket = filepath.Join(root, "socket")
	d, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	for _, ext := range []string{".json", ".log"} {
		if _, e := os.Stat(filepath.Join(dir, id+ext)); !os.IsNotExist(e) {
			t.Fatal("startup retained expired artifact", ext, e)
		}
	}
}
