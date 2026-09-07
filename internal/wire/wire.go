// Package wire implements bounded versioned JSON RPC and duplex IO on Unix/vsock transports.
package wire

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"niflhel/internal/api"
	"strings"
	"sync"
	"time"
)

const MaxFrame = 1 << 20

type Stream struct {
	conn net.Conn
	r    *bufio.Reader
	mu   sync.Mutex
	once sync.Once
	done chan struct{}
}

func NewStream(c net.Conn) *Stream {
	return &Stream{conn: c, r: bufio.NewReaderSize(c, 64<<10), done: make(chan struct{})}
}
func (s *Stream) Close() error          { s.once.Do(func() { close(s.done); s.conn.Close() }); return nil }
func (s *Stream) Done() <-chan struct{} { return s.done }
func (s *Stream) Send(v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if len(b) > MaxFrame {
		return fmt.Errorf("frame too large")
	}
	b = append(b, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	defer s.conn.SetWriteDeadline(time.Time{})
	for len(b) > 0 {
		n, e := s.conn.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func (s *Stream) Recv(v any) error {
	var b []byte
	for {
		p, prefix, e := s.r.ReadLine()
		if e != nil {
			s.Close()
			return e
		}
		if len(b)+len(p) > MaxFrame {
			return fmt.Errorf("frame too large")
		}
		b = append(b, p...)
		if !prefix {
			break
		}
	}
	return json.Unmarshal(b, v)
}

type Handler interface {
	Call(context.Context, api.Request) (any, error)
	Session(context.Context, api.Request, *Stream) error
}

func Serve(h Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/call", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		var q api.Request
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxFrame))
		d.DisallowUnknownFields()
		if e := d.Decode(&q); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		v, e := h.Call(r.Context(), q)
		w.Header().Set("Content-Type", "application/json")
		if e != nil {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": e.Error()})
			return
		}
		json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("/v1/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || !strings.EqualFold(r.Header.Get("Upgrade"), "niflhel") {
			http.Error(w, "upgrade required", 400)
			return
		}
		c, rw, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		defer c.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: niflhel\r\n\r\n")
		if e = rw.Flush(); e != nil {
			return
		}
		s := NewStream(c)
		defer s.Close()
		s.r = rw.Reader
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		var q api.Request
		if e = s.Recv(&q); e != nil {
			return
		}
		c.SetReadDeadline(time.Time{})
		if e = h.Session(r.Context(), q, s); e != nil {
			s.Send(api.Frame{Type: "error", Message: e.Error()})
		}
	})
	return mux
}

type Client struct {
	Dial func(context.Context) (net.Conn, error)
}

func Unix(path string) *Client {
	return &Client{Dial: func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "unix", path) }}
}
func (c *Client) Call(ctx context.Context, q api.Request, out any) error {
	b, e := json.Marshal(q)
	if e != nil {
		return e
	}
	if len(b) > MaxFrame {
		return fmt.Errorf("request too large")
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return c.Dial(ctx) }, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, "POST", "http://niflhel/v1/call", strings.NewReader(string(b)))
	if e != nil {
		return e
	}
	res, e := (&http.Client{Transport: tr}).Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		var v struct{ Error string }
		json.NewDecoder(io.LimitReader(res.Body, MaxFrame)).Decode(&v)
		return fmt.Errorf("%s", v.Error)
	}
	if out == nil {
		_, e = io.Copy(io.Discard, io.LimitReader(res.Body, MaxFrame))
		return e
	}
	return json.NewDecoder(io.LimitReader(res.Body, 16*MaxFrame)).Decode(out)
}
func (c *Client) Session(ctx context.Context, q api.Request) (*Stream, error) {
	conn, e := c.Dial(ctx)
	if e != nil {
		return nil, e
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	_, e = io.WriteString(conn, "POST /v1/session HTTP/1.1\r\nHost: niflhel\r\nConnection: Upgrade\r\nUpgrade: niflhel\r\nContent-Length: 0\r\n\r\n")
	if e != nil {
		conn.Close()
		return nil, e
	}
	br := bufio.NewReader(conn)
	res, e := http.ReadResponse(br, nil)
	if e != nil {
		conn.Close()
		return nil, e
	}
	if res.StatusCode != 101 {
		conn.Close()
		return nil, fmt.Errorf("session rejected: %s", res.Status)
	}
	conn.SetDeadline(time.Time{})
	s := NewStream(conn)
	s.r = br
	if e = s.Send(q); e != nil {
		s.Close()
		return nil, e
	}
	go func() {
		select {
		case <-ctx.Done():
			s.Close()
		case <-s.Done():
		}
	}()
	return s, nil
}
func Relay(a, b *Stream) error {
	done := make(chan error, 2)
	copyFrames := func(dst, src *Stream) {
		for {
			var f api.Frame
			if e := src.Recv(&f); e != nil {
				done <- e
				return
			}
			if e := dst.Send(f); e != nil {
				done <- e
				return
			}
			if f.Type == "exit" || f.Type == "error" || f.Type == "detached" {
				done <- nil
				return
			}
		}
	}
	go copyFrames(a, b)
	go copyFrames(b, a)
	e := <-done
	a.Close()
	b.Close()
	<-done
	if e == io.EOF {
		return nil
	}
	return e
}
