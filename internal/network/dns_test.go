package network

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func testDNSAdmission(now func() time.Time) *dnsAdmission {
	return &dnsAdmission{
		localTokens:  newTokenBucket(1000, 1000),
		globalTokens: newTokenBucket(1000, 1000),
		localWork:    make(chan struct{}, 8),
		globalWork:   make(chan struct{}, 8),
		now:          now,
	}
}

func TestDNSAdmissionRateAndGlobalConcurrency(t *testing.T) {
	now := time.Unix(100, 0)
	a := &dnsAdmission{
		localTokens:  newTokenBucket(1, 2),
		globalTokens: newTokenBucket(100, 100),
		localWork:    make(chan struct{}, 2),
		globalWork:   make(chan struct{}, 2),
		now:          func() time.Time { return now },
	}
	for i := 0; i < 2; i++ {
		release, ok := a.acquire()
		if !ok {
			t.Fatal("initial DNS burst rejected")
		}
		release()
	}
	if _, ok := a.acquire(); ok {
		t.Fatal("per-sandbox DNS burst limit bypassed")
	}
	now = now.Add(time.Second)
	if release, ok := a.acquire(); !ok {
		t.Fatal("DNS token did not refill")
	} else {
		release()
	}

	sharedTokens := newTokenBucket(100, 100)
	sharedWork := make(chan struct{}, 1)
	first := testDNSAdmission(func() time.Time { return now })
	second := testDNSAdmission(func() time.Time { return now })
	first.globalTokens, first.globalWork = sharedTokens, sharedWork
	second.globalTokens, second.globalWork = sharedTokens, sharedWork
	release, ok := first.acquire()
	if !ok {
		t.Fatal("first global DNS slot rejected")
	}
	if _, ok = second.acquire(); ok {
		t.Fatal("global DNS concurrency limit bypassed")
	}
	release()
}

func TestDNSForwardsValidUDPAndTCP(t *testing.T) {
	now := func() time.Time { return time.Now() }
	query := make([]byte, 12)
	query[0], query[1] = 0x12, 0x34

	udpUpstream, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udpUpstream.Close()
	udpErr := make(chan error, 1)
	go func() {
		buf := make([]byte, maxDNSMessage)
		n, addr, e := udpUpstream.ReadFrom(buf)
		if e == nil {
			_, e = udpUpstream.WriteTo(buf[:n], addr)
		}
		udpErr <- e
	}()
	udpProxy, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serveUDP(ctx, udpProxy, udpUpstream.LocalAddr().String(), testDNSAdmission(now))
	udpClient, e := net.Dial("udp4", udpProxy.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	udpClient.SetDeadline(time.Now().Add(2 * time.Second))
	if _, e = udpClient.Write(query); e != nil {
		t.Fatal(e)
	}
	reply := make([]byte, len(query))
	if _, e = io.ReadFull(udpClient, reply); e != nil || !bytes.Equal(reply, query) {
		t.Fatal(reply, e)
	}
	udpClient.Close()
	udpProxy.Close()
	if e = <-udpErr; e != nil {
		t.Fatal(e)
	}

	tcpUpstream, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer tcpUpstream.Close()
	tcpErr := make(chan error, 1)
	go func() {
		conn, e := tcpUpstream.Accept()
		if e != nil {
			tcpErr <- e
			return
		}
		defer conn.Close()
		framed := make([]byte, len(query)+2)
		_, e = io.ReadFull(conn, framed)
		if e == nil {
			_, e = conn.Write(framed)
		}
		tcpErr <- e
	}()
	tcpProxy, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	go serveTCP(ctx, tcpProxy, tcpUpstream.Addr().String(), testDNSAdmission(now))
	tcpClient, e := net.Dial("tcp4", tcpProxy.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	tcpClient.SetDeadline(time.Now().Add(2 * time.Second))
	framed := make([]byte, len(query)+2)
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
	copy(framed[2:], query)
	if _, e = tcpClient.Write(framed); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len(framed))
	if _, e = io.ReadFull(tcpClient, got); e != nil || !bytes.Equal(got, framed) {
		t.Fatal(got, e)
	}
	tcpClient.Close()
	tcpProxy.Close()
	if e = <-tcpErr; e != nil {
		t.Fatal(e)
	}
}
