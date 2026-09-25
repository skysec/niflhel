package base

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
	canonical := signed.Signature
	for _, variant := range []string{"\n" + canonical, canonical[:8] + "\r\n" + canonical[8:], canonical + "\n"} {
		changed := signed
		changed.Signature = variant
		if e = s.Verify(changed); e == nil {
			t.Fatal("non-canonical signature accepted")
		}
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

func TestParseSignedBoundsAndSchema(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	c := Config{SchemaVersion: 1, OS: "linux", Architecture: "amd64", AgentProtocol: 1, InitPath: "/sbin/niflhel-init", Runtime: "runc", GuestReserveMiB: 128, FirecrackerVersions: []string{"1.16.1"}, Kernel: oci.Descriptor{Digest: fsutil.Digest([]byte("kernel")), Size: 6}, RootFS: oci.Descriptor{Digest: fsutil.Digest([]byte("root")), Size: 4}}
	signed, e := Sign(c, "release", key)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(signed)
	parsed, e := ParseSigned(raw)
	if e != nil || parsed.Signature != signed.Signature {
		t.Fatal(parsed, e)
	}
	unknown := append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"Unknown":true}`)...)
	if _, e = ParseSigned(unknown); e == nil {
		t.Fatal("unknown signed-envelope field accepted")
	}
	if _, e = ParseSigned(bytes.Repeat([]byte(" "), int(MaxSignedMetadata)+1)); e == nil {
		t.Fatal("oversized signed envelope accepted")
	}
}
