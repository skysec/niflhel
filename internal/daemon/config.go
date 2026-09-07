package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	Root               string
	Socket             string
	SocketGroup        string
	Firecracker        string
	Jailer             string
	DefaultBase        string
	TrustedKeys        map[string]string
	DNSUpstream        string
	BootTimeoutSeconds int
}

func DefaultConfig() Config {
	return Config{Root: "/var/lib/niflhel", Socket: "/run/niflhel/niflhel.sock", Firecracker: "/usr/local/bin/firecracker", Jailer: "/usr/local/bin/jailer", DNSUpstream: "1.1.1.1:53", BootTimeoutSeconds: 60, TrustedKeys: map[string]string{}}
}
func Load(path string) (Config, error) {
	c := DefaultConfig()
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	if e = json.Unmarshal(b, &c); e != nil {
		return c, e
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	for _, p := range []string{c.Root, c.Socket, c.Firecracker, c.Jailer} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("configured paths must be absolute")
		}
	}
	if c.BootTimeoutSeconds < 1 || c.BootTimeoutSeconds > 600 {
		return fmt.Errorf("invalid boot timeout")
	}
	return nil
}
