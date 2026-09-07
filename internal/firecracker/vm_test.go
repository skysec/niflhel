package firecracker

import (
	"crypto/tls"
	"net"
	"niflhel/internal/api"
	"testing"
)

func TestConfigContainerDrives(t *testing.T) {
	s := api.Sandbox{ID: api.ID(), Spec: api.DefaultSpec(), Slot: 1, GuestMemory: 640 * api.MiB}
	s.Spec.Network = "none"
	c := BuildConfig(s)
	if len(c.Network) != 0 || len(c.Drives) != 4 || !c.Drives[0].ReadOnly || c.Drives[3].ReadOnly {
		t.Fatal(c)
	}
	if c.Machine.Memory != 640 {
		t.Fatal(c)
	}
}
func TestMutualTLS(t *testing.T) {
	cr, e := CredentialsFor("test")
	if e != nil {
		t.Fatal(e)
	}
	server, e := TLSConfig(cr.CA, cr.GuestCert, cr.GuestKey, "", true)
	if e != nil {
		t.Fatal(e)
	}
	client, e := TLSConfig(cr.CA, cr.HostCert, cr.HostKey, "guest-test", false)
	if e != nil {
		t.Fatal(e)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	done := make(chan error, 1)
	go func() { done <- tls.Server(a, server).Handshake() }()
	if e = tls.Client(b, client).Handshake(); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}
