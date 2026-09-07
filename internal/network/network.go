// Package network owns per-sandbox routes, namespaces, and firewall tables.
package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"niflhel/internal/api"
	"niflhel/internal/storage"
	"os"
	"os/exec"
	"strings"
)

type Config struct {
	Namespace string
	HostVeth  string
	PeerVeth  string
	HostIP    string
	PeerIP    string
	Table     string
	GuestIP   string
	Gateway   string
}

func For(id string, slot int) (Config, error) {
	if len(id) != 32 || slot < 1 || slot > 16000 {
		return Config{}, fmt.Errorf("invalid network allocation")
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return Config{}, fmt.Errorf("invalid sandbox ID")
		}
	}
	a := slot * 4
	return Config{Namespace: "nf-" + id[:12], HostVeth: "nh" + id[:10], PeerVeth: "np" + id[:10], HostIP: fmt.Sprintf("10.240.%d.%d", a/256, a%256+1), PeerIP: fmt.Sprintf("10.240.%d.%d", a/256, a%256+2), Table: "nf_" + id[:12], GuestIP: "172.30.0.2", Gateway: "172.30.0.1"}, nil
}

type Manager struct{ Runner storage.Runner }

func (m Manager) run(ctx context.Context, n string, a ...string) error {
	r := m.Runner
	if r == nil {
		r = storage.OSRunner{}
	}
	return r.Run(ctx, n, a...)
}
func (m Manager) Prepare(ctx context.Context, s api.Sandbox) error {
	if s.Spec.Network == "none" {
		return nil
	}
	c, e := For(s.ID, s.Slot)
	if e != nil {
		return e
	}
	if m.Runner == nil {
		forwarding, e := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if e != nil || strings.TrimSpace(string(forwarding)) != "1" {
			return fmt.Errorf("enable host net.ipv4.ip_forward before bridge networking")
		}
		raw, e := exec.CommandContext(ctx, "ip", "-j", "route", "show").Output()
		if e != nil {
			return e
		}
		var routes []struct{ Dst string }
		if e = json.Unmarshal(raw, &routes); e != nil {
			return e
		}
		ip := net.ParseIP(c.HostIP)
		for _, route := range routes {
			if route.Dst == "default" || route.Dst == "" {
				continue
			}
			_, subnet, e := net.ParseCIDR(route.Dst)
			if e == nil && subnet.Contains(ip) {
				return fmt.Errorf("sandbox address %s conflicts with host route %s", c.HostIP, route.Dst)
			}
		}
	}
	// Each resource has a deterministic owner-derived name. The daemon persists
	// allocation intent before this method and retries Remove after any failure.
	cmds := [][]string{
		{"ip", "netns", "add", c.Namespace},
		{"ip", "link", "add", c.HostVeth, "type", "veth", "peer", "name", c.PeerVeth},
		{"ip", "link", "set", c.PeerVeth, "netns", c.Namespace},
		{"ip", "addr", "add", c.HostIP + "/30", "dev", c.HostVeth},
		{"ip", "link", "set", c.HostVeth, "up"},
		{"ip", "-n", c.Namespace, "addr", "add", c.PeerIP + "/30", "dev", c.PeerVeth},
		{"ip", "-n", c.Namespace, "link", "set", c.PeerVeth, "up"},
		{"ip", "-n", c.Namespace, "link", "set", "lo", "up"},
		{"ip", "-n", c.Namespace, "route", "add", "default", "via", c.HostIP},
		{"ip", "netns", "exec", c.Namespace, "ip", "tuntap", "add", "dev", "tap0", "mode", "tap"},
		{"ip", "-n", c.Namespace, "addr", "add", c.Gateway + "/30", "dev", "tap0"},
		{"ip", "-n", c.Namespace, "link", "set", "tap0", "up"},
		{"ip", "netns", "exec", c.Namespace, "sysctl", "-qw", "net.ipv4.ip_forward=1"},
		{"ip", "netns", "exec", c.Namespace, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1"},
	}
	for _, cmd := range cmds {
		if e = m.run(ctx, cmd[0], cmd[1:]...); e != nil {
			return e
		}
	}
	if e = m.nft(ctx, "", HostRules(c, s.Spec.Ports)); e != nil {
		return e
	}
	return m.nft(ctx, c.Namespace, NamespaceRules(c, s.Spec.Ports))
}
func (m Manager) nft(ctx context.Context, ns, script string) error {
	// An injectable runner makes command plans testable without host mutation.
	if m.Runner != nil {
		return m.Runner.Run(ctx, "nft-script", ns, script)
	}
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	if ns != "" {
		cmd = exec.CommandContext(ctx, "ip", "netns", "exec", ns, "nft", "-f", "-")
	}
	cmd.Stdin = strings.NewReader(script)
	b, e := cmd.CombinedOutput()
	if e != nil {
		return fmt.Errorf("nft: %w: %s", e, b)
	}
	return nil
}
func HostRules(c Config, ports []api.Port) string {
	// Reply exceptions precede destination filters, but source validation precedes
	// conntrack acceptance. Rules match only this sandbox's interface.
	b := fmt.Sprintf(`table inet %s {
 chain input { type filter hook input priority -20; policy accept;
  iifname "%s" ip saddr != %s drop
  iifname "%s" ip daddr %s udp dport 53 accept
  iifname "%s" ip daddr %s tcp dport 53 accept
  iifname "%s" ct state established,related accept
  iifname "%s" drop
 }
 chain forward { type filter hook forward priority -20; policy accept;
  iifname "%s" meta nfproto ipv6 drop
  iifname "%s" ip saddr != %s drop
  iifname "%s" ct state established,related accept
  iifname "%s" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4 } drop
  iifname "%s" accept
  oifname "%s" ct state established,related accept
  oifname "%s" ct status dnat accept
  oifname "%s" drop
 }
 chain postrouting { type nat hook postrouting priority srcnat; policy accept;
  ip saddr %s masquerade
  oifname "%s" ct status dnat masquerade
 }
 chain prerouting { type nat hook prerouting priority dstnat; policy accept;
`, c.Table, c.HostVeth, c.PeerIP, c.HostVeth, c.HostIP, c.HostVeth, c.HostIP, c.HostVeth, c.HostVeth, c.HostVeth, c.HostVeth, c.PeerIP, c.HostVeth, c.HostVeth, c.HostVeth, c.HostVeth, c.HostVeth, c.HostVeth, c.PeerIP, c.HostVeth)
	for _, p := range ports {
		if p.HostIP == "0.0.0.0" {
			b += fmt.Sprintf(" fib daddr type local tcp dport %d dnat ip to %s:%d\n", p.HostPort, c.PeerIP, p.ContainerPort)
		}
	}
	b += " }\n chain output { type nat hook output priority dstnat; policy accept;\n"
	for _, p := range ports {
		target := "ip daddr 127.0.0.1"
		if p.HostIP == "0.0.0.0" {
			target = "fib daddr type local"
		}
		b += fmt.Sprintf(" %s tcp dport %d dnat ip to %s:%d\n", target, p.HostPort, c.PeerIP, p.ContainerPort)
	}
	return b + " }\n}\n"
}
func NamespaceRules(c Config, ports []api.Port) string {
	b := `table ip niflhel {
 chain postrouting { type nat hook postrouting priority srcnat; policy accept; oifname "` + c.PeerVeth + `" ip saddr 172.30.0.2 masquerade; }
 chain prerouting { type nat hook prerouting priority dstnat; policy accept;
`
	for _, p := range ports {
		b += fmt.Sprintf(" iifname %q tcp dport %d dnat to 172.30.0.2:%d\n", c.PeerVeth, p.ContainerPort, p.ContainerPort)
	}
	b += ` }
 chain forward { type filter hook forward priority filter; policy drop;
 iifname "tap0" ip saddr != 172.30.0.2 drop
 ct state established,related accept
 iifname "tap0" accept
 ct status dnat accept
 }
}
`
	return b
}
func (m Manager) Remove(ctx context.Context, s api.Sandbox) error {
	if s.Spec.Network == "none" {
		return nil
	}
	c, e := For(s.ID, s.Slot)
	if e != nil {
		return e
	}
	// Missing resources are harmless; other failures must remain retryable.
	for _, cmd := range [][]string{{"nft", "delete", "table", "inet", c.Table}, {"ip", "link", "delete", c.HostVeth}, {"ip", "netns", "delete", c.Namespace}} {
		e = m.run(ctx, cmd[0], cmd[1:]...)
		if e != nil && !strings.Contains(e.Error(), "No such") && !strings.Contains(e.Error(), "Cannot find") && !strings.Contains(e.Error(), "does not exist") {
			return e
		}
	}
	return nil
}

// DNS serves a fixed upstream without permitting the guest to choose a host target.
func DNS(ctx context.Context, ip, upstream string) (func(), error) {
	udp, e := net.ListenPacket("udp4", net.JoinHostPort(ip, "53"))
	if e != nil {
		return nil, e
	}
	tcp, e := net.Listen("tcp4", net.JoinHostPort(ip, "53"))
	if e != nil {
		udp.Close()
		return nil, e
	}
	stop := func() { udp.Close(); tcp.Close() }
	go serveUDP(ctx, udp, upstream)
	go serveTCP(ctx, tcp, upstream)
	return stop, nil
}
