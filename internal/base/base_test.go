package base

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"niflhel/internal/fsutil"
	"niflhel/internal/oci"
	"testing"
)

func TestTrustAndTampering(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	c := Config{SchemaVersion: 1, OS: "linux", Architecture: "amd64", AgentProtocol: 1, InitPath: "/sbin/niflhel-init", Runtime: "runc", GuestReserveMiB: 128, FirecrackerVersions: []string{"1.16.1"}, Kernel: oci.Descriptor{Digest: fsutil.Digest([]byte("kernel")), Size: 6}, RootFS: oci.Descriptor{Digest: fsutil.Digest([]byte("root")), Size: 4}}
	signed, e := Sign(c, "release", key)
	if e != nil {
		t.Fatal(e)
	}
	s := Store{Trust: map[string]string{"release": base64.StdEncoding.EncodeToString(pub)}}
	if e = s.Verify(signed); e != nil {
		t.Fatal(e)
	}
	signed.Config.GuestReserveMiB++
	if e = s.Verify(signed); e == nil {
		t.Fatal("tampered metadata accepted")
	}
	signed, _ = Sign(c, "unknown", key)
	if e = s.Verify(signed); e == nil {
		t.Fatal("untrusted publisher accepted")
	}
	c.AgentProtocol = 2
	if _, e = Sign(c, "release", key); e == nil {
		t.Fatal("incompatible protocol accepted")
	}
}
