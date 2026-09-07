package cli

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"niflhel/internal/api"
	"niflhel/internal/wire"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type cliPeer struct{ created chan api.Spec }

func (p cliPeer) Call(_ context.Context, q api.Request) (any, error) {
	switch q.Action {
	case "info":
		return map[string]string{"DefaultBase": "example/base:1"}, nil
	case "create":
		p.created <- *q.Spec
		return api.Sandbox{ID: strings.Repeat("a", 32), State: "created"}, nil
	}
	return nil, fmt.Errorf("unexpected action %s", q.Action)
}
func (cliPeer) Session(context.Context, api.Request, *wire.Stream) error {
	return fmt.Errorf("unexpected session")
}
func TestCreatePreservesContainerArguments(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	socket := filepath.Join(t.TempDir(), "socket")
	l, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	peer := cliPeer{created: make(chan api.Spec, 1)}
	srv := &http.Server{Handler: wire.Serve(peer)}
	go srv.Serve(l)
	defer srv.Close()
	var output bytes.Buffer
	c := New(strings.NewReader(""), &output, &output)
	c.SetArgs([]string{"--socket", socket, "container", "create", "--network", "none", "--memory", "256m", "-e", "A=a,b", "example/app:1", "sh", "-c", "echo $HOME"})
	if e = c.Execute(); e != nil {
		t.Fatal(e)
	}
	got := <-peer.created
	if !reflect.DeepEqual(got.Command, []string{"sh", "-c", "echo $HOME"}) || got.Memory != 256*api.MiB || !reflect.DeepEqual(got.Env, []string{"A=a,b"}) {
		t.Fatal(got)
	}
}
