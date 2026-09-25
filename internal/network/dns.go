package network

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

const (
	maxDNSMessage           = 4096
	perSandboxDNSRate       = 256
	perSandboxDNSBurst      = 512
	perSandboxDNSConcurrent = 64
	globalDNSRate           = 4096
	globalDNSBurst          = 8192
	globalDNSConcurrent     = 256
)

type tokenBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newTokenBucket(rate float64, burst int) *tokenBucket {
	return &tokenBucket{rate: rate, burst: float64(burst), tokens: float64(burst)}
}

func (b *tokenBucket) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rate <= 0 || b.burst < 1 {
		return false
	}
	if b.last.IsZero() {
		b.last = now
	} else if now.After(b.last) {
		b.tokens += now.Sub(b.last).Seconds() * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type dnsAdmission struct {
	localTokens  *tokenBucket
	globalTokens *tokenBucket
	localWork    chan struct{}
	globalWork   chan struct{}
	now          func() time.Time
}

var processDNSAdmission = struct {
	tokens *tokenBucket
	work   chan struct{}
}{newTokenBucket(globalDNSRate, globalDNSBurst), make(chan struct{}, globalDNSConcurrent)}

func newDNSAdmission() *dnsAdmission {
	return &dnsAdmission{
		localTokens:  newTokenBucket(perSandboxDNSRate, perSandboxDNSBurst),
		globalTokens: processDNSAdmission.tokens,
		localWork:    make(chan struct{}, perSandboxDNSConcurrent),
		globalWork:   processDNSAdmission.work,
		now:          time.Now,
	}
}

func (a *dnsAdmission) acquire() (func(), bool) {
	now := a.now()
	if !a.localTokens.allow(now) || !a.globalTokens.allow(now) {
		return nil, false
	}
	select {
	case a.localWork <- struct{}{}:
	default:
		return nil, false
	}
	select {
	case a.globalWork <- struct{}{}:
		return func() { <-a.globalWork; <-a.localWork }, true
	default:
		<-a.localWork
		return nil, false
	}
}

var dnsBuffers = sync.Pool{New: func() any { return new([maxDNSMessage + 2]byte) }}

func serveUDP(ctx context.Context, pc net.PacketConn, upstream string, admission *dnsAdmission) {
	var incoming [maxDNSMessage + 1]byte
	for {
		n, addr, e := pc.ReadFrom(incoming[:])
		if e != nil {
			return
		}
		if n < 12 || n > maxDNSMessage {
			continue
		}
		release, ok := admission.acquire()
		if !ok {
			continue
		}
		buf := dnsBuffers.Get().(*[maxDNSMessage + 2]byte)
		copy(buf[:n], incoming[:n])
		go func(size int, target net.Addr, data *[maxDNSMessage + 2]byte, done func()) {
			defer done()
			defer dnsBuffers.Put(data)
			id0, id1 := data[0], data[1]
			up, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp", upstream)
			if e != nil {
				return
			}
			defer up.Close()
			up.SetDeadline(time.Now().Add(3 * time.Second))
			if _, e = up.Write(data[:size]); e != nil {
				return
			}
			n, e := up.Read(data[:maxDNSMessage+1])
			if e == nil && n >= 12 && n <= maxDNSMessage && data[0] == id0 && data[1] == id1 {
				pc.WriteTo(data[:n], target)
			}
		}(n, addr, buf, release)
	}
}

func serveTCP(ctx context.Context, listener net.Listener, upstream string, admission *dnsAdmission) {
	for {
		client, e := listener.Accept()
		if e != nil {
			return
		}
		release, ok := admission.acquire()
		if !ok {
			client.Close()
			continue
		}
		go func() {
			defer release()
			defer client.Close()
			client.SetDeadline(time.Now().Add(5 * time.Second))
			buf := dnsBuffers.Get().(*[maxDNSMessage + 2]byte)
			defer dnsBuffers.Put(buf)
			if _, e := io.ReadFull(client, buf[:2]); e != nil {
				return
			}
			n := binary.BigEndian.Uint16(buf[:2])
			if n < 12 || n > maxDNSMessage {
				return
			}
			if _, e := io.ReadFull(client, buf[2:int(n)+2]); e != nil {
				return
			}
			up, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", upstream)
			if e != nil {
				return
			}
			defer up.Close()
			up.SetDeadline(time.Now().Add(3 * time.Second))
			if _, e = up.Write(buf[:int(n)+2]); e != nil {
				return
			}
			io.CopyN(client, up, maxDNSMessage+2)
		}()
	}
}
