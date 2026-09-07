package network

import (
	"niflhel/internal/api"
	"strings"
	"testing"
)

func TestIsolationPlan(t *testing.T) {
	c, e := For(strings.Repeat("a", 32), 1)
	if e != nil {
		t.Fatal(e)
	}
	if c.HostIP != "10.240.0.5" || len(c.HostVeth) > 15 {
		t.Fatal(c)
	}
	r := HostRules(c, []api.Port{{HostIP: "127.0.0.1", HostPort: 8080, ContainerPort: 80}})
	for _, required := range []string{"169.254.0.0/16", "meta nfproto ipv6 drop", "ip saddr !=", "ct state established,related", "ip daddr 127.0.0.1 tcp dport 8080"} {
		if !strings.Contains(r, required) {
			t.Fatal(required, r)
		}
	}
	pre := strings.Split(strings.Split(r, "chain prerouting")[1], "chain output")[0]
	if strings.Contains(pre, "8080") {
		t.Fatal("loopback port exposed externally")
	}
	if _, e = For("../escape", 1); e == nil {
		t.Fatal("unsafe ID accepted")
	}
}
