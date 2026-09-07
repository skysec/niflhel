package network

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"
)

func serveUDP(ctx context.Context, pc net.PacketConn, upstream string) {
	sem := make(chan struct{}, 64)
	for {
		b := make([]byte, 4096)
		n, a, e := pc.ReadFrom(b)
		if e != nil {
			return
		}
		if n < 12 {
			continue
		}
		select {
		case sem <- struct{}{}:
			go func(data []byte, addr net.Addr) {
				defer func() { <-sem }()
				c, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp", upstream)
				if e != nil {
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				if _, e = c.Write(data); e != nil {
					return
				}
				reply := make([]byte, 4096)
				n, e := c.Read(reply)
				if e == nil && n >= 12 && reply[0] == data[0] && reply[1] == data[1] {
					pc.WriteTo(reply[:n], addr)
				}
			}(b[:n], a)
		default:
		}
	}
}
func serveTCP(ctx context.Context, l net.Listener, upstream string) {
	sem := make(chan struct{}, 64)
	for {
		c, e := l.Accept()
		if e != nil {
			return
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				head := make([]byte, 2)
				if _, e := io.ReadFull(c, head); e != nil {
					return
				}
				n := binary.BigEndian.Uint16(head)
				if n < 12 || n > 4096 {
					return
				}
				b := make([]byte, int(n)+2)
				copy(b, head)
				if _, e := io.ReadFull(c, b[2:]); e != nil {
					return
				}
				u, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", upstream)
				if e != nil {
					return
				}
				defer u.Close()
				u.SetDeadline(time.Now().Add(3 * time.Second))
				if _, e = u.Write(b); e != nil {
					return
				}
				io.CopyN(c, u, 4098)
			}()
		default:
			c.Close()
		}
	}
}
