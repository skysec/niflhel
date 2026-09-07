package wire

import (
	"context"
	"net"
	"net/http"
	"niflhel/internal/api"
	"path/filepath"
	"strings"
	"testing"
)

type echo struct{}

func (echo) Call(_ context.Context, q api.Request) (any, error) { return q.ID, nil }
func (echo) Session(_ context.Context, q api.Request, s *Stream) error {
	var f api.Frame
	if e := s.Recv(&f); e != nil {
		return e
	}
	return s.Send(f)
}
func TestRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "socket")
	l, e := net.Listen("unix", p)
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{Handler: Serve(echo{})}
	go server.Serve(l)
	defer server.Close()
	c := Unix(p)
	var result string
	if e = c.Call(context.Background(), api.Request{ID: "value"}, &result); e != nil || result != "value" {
		t.Fatal(result, e)
	}
	s, e := c.Session(context.Background(), api.Request{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	b := []byte{0, 1, 255, 10}
	if e = s.Send(api.Frame{Type: "stdin", Data: b}); e != nil {
		t.Fatal(e)
	}
	var f api.Frame
	if e = s.Recv(&f); e != nil || string(f.Data) != string(b) {
		t.Fatal(f, e)
	}
}
func TestFrameLimit(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if e := NewStream(a).Send(api.Frame{Data: []byte(strings.Repeat("x", MaxFrame))}); e == nil {
		t.Fatal("oversize frame accepted")
	}
}
