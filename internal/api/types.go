// Package api defines the versioned local and guest control contract.
package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const Version = "0.1.0"
const Protocol = 1
const MiB int64 = 1 << 20
const GiB int64 = 1 << 30

type Port struct {
	HostIP        string
	HostPort      int
	ContainerPort int
}
type Mount struct {
	Name     string
	Target   string
	ReadOnly bool
}
type Spec struct {
	Image       string
	Base        string
	Name        string
	Command     []string
	Entrypoint  *string
	Env         []string
	User        string
	Workdir     string
	CPUs        int
	Memory      int64
	DiskSize    int64
	PidsLimit   int64
	Network     string
	Ports       []Port
	Mounts      []Mount
	Runtime     string
	Platform    string
	Pull        string
	ReadOnly    bool
	Interactive bool
	TTY         bool
	AutoRemove  bool
}

func DefaultSpec() Spec {
	return Spec{CPUs: 1, Memory: 512 * MiB, DiskSize: 4 * GiB, PidsLimit: 256, Network: "bridge", Runtime: "runc", Platform: "linux/amd64", Pull: "missing"}
}

var validName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)

func ValidName(s string) bool { return validName.MatchString(s) }
func ID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func Size(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	multiplier := int64(1)
	for _, u := range []struct {
		s string
		n int64
	}{{"gib", GiB}, {"mib", MiB}, {"kib", 1024}, {"gb", GiB}, {"mb", MiB}, {"kb", 1024}, {"g", GiB}, {"m", MiB}, {"k", 1024}, {"b", 1}} {
		if strings.HasSuffix(s, u.s) {
			s = strings.TrimSuffix(s, u.s)
			multiplier = u.n
			break
		}
	}
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil || n <= 0 || n > (1<<63-1)/multiplier {
		return 0, fmt.Errorf("invalid positive size %q", s)
	}
	return n * multiplier, nil
}
func (s Spec) Validate() error {
	if s.Image == "" {
		return fmt.Errorf("image is required")
	}
	if s.Name != "" && !ValidName(s.Name) {
		return fmt.Errorf("invalid name %q", s.Name)
	}
	if s.Runtime != "runc" {
		return fmt.Errorf("UnsupportedFeature: runtime %q; phase one supports runc", s.Runtime)
	}
	if s.Platform != "linux/amd64" {
		return fmt.Errorf("UnsupportedFeature: platform %q", s.Platform)
	}
	if s.CPUs < 1 || s.CPUs > 32 {
		return fmt.Errorf("cpus must be a whole number between 1 and 32")
	}
	if s.Memory < 64*MiB || s.Memory > 1024*GiB {
		return fmt.Errorf("memory must be between 64 MiB and 1 TiB")
	}
	if s.DiskSize < 64*MiB || s.DiskSize > 1024*GiB {
		return fmt.Errorf("disk size must be between 64 MiB and 1 TiB")
	}
	if s.PidsLimit < 1 || s.PidsLimit > 1<<20 {
		return fmt.Errorf("invalid pids limit")
	}
	if s.Network != "bridge" && s.Network != "none" {
		return fmt.Errorf("UnsupportedFeature: network %q", s.Network)
	}
	if s.Network == "none" && len(s.Ports) > 0 {
		return fmt.Errorf("cannot publish ports with network none")
	}
	if s.Pull != "always" && s.Pull != "missing" && s.Pull != "never" {
		return fmt.Errorf("pull must be always, missing, or never")
	}
	if s.Workdir != "" && !path.IsAbs(s.Workdir) {
		return fmt.Errorf("workdir must be absolute")
	}
	for _, e := range s.Env {
		k, _, ok := strings.Cut(e, "=")
		if !ok || k == "" || strings.ContainsAny(e, "\x00") {
			return fmt.Errorf("invalid environment entry")
		}
	}
	seen := map[string]bool{}
	for _, p := range s.Ports {
		if p.HostIP != "127.0.0.1" && p.HostIP != "0.0.0.0" {
			return fmt.Errorf("host IP must be 127.0.0.1 or 0.0.0.0")
		}
		if p.HostPort < 1 || p.HostPort > 65535 || p.ContainerPort < 1 || p.ContainerPort > 65535 {
			return fmt.Errorf("port out of range")
		}
		k := strconv.Itoa(p.HostPort)
		if seen[k] {
			return fmt.Errorf("duplicate host port")
		}
		seen[k] = true
	}
	seen = map[string]bool{}
	if len(s.Mounts) > 8 {
		return fmt.Errorf("at most eight named volumes are supported")
	}
	for _, m := range s.Mounts {
		if !ValidName(m.Name) || !path.IsAbs(m.Target) || path.Clean(m.Target) != m.Target || m.Target == "/" {
			return fmt.Errorf("invalid named volume mount")
		}
		for _, reserved := range []string{"/proc", "/sys", "/dev", "/run/niflhel"} {
			if m.Target == reserved || strings.HasPrefix(m.Target, reserved+"/") {
				return fmt.Errorf("reserved mount target %s", m.Target)
			}
		}
		if seen[m.Target] || seen["name:"+m.Name] {
			return fmt.Errorf("duplicate volume or destination")
		}
		seen[m.Target] = true
		seen["name:"+m.Name] = true
	}
	return nil
}
func ParsePort(s string) (Port, error) {
	s = strings.TrimSuffix(s, "/tcp")
	p := strings.Split(s, ":")
	var out Port
	if len(p) == 2 {
		p = append([]string{"127.0.0.1"}, p...)
	}
	if len(p) != 3 {
		return out, fmt.Errorf("expected [HOST_IP:]HOST_PORT:CONTAINER_PORT[/tcp]")
	}
	var e error
	out.HostIP = p[0]
	out.HostPort, e = strconv.Atoi(p[1])
	if e != nil {
		return out, e
	}
	out.ContainerPort, e = strconv.Atoi(p[2])
	return out, e
}
func ParseMount(s string) (Mount, error) {
	var m Mount
	if !strings.Contains(s, "=") {
		p := strings.Split(s, ":")
		if len(p) < 2 || len(p) > 3 {
			return m, fmt.Errorf("expected NAME:/PATH[:ro]")
		}
		m.Name = p[0]
		m.Target = p[1]
		if len(p) == 3 {
			if p[2] != "ro" {
				return m, fmt.Errorf("only ro mount option supported")
			}
			m.ReadOnly = true
		}
	} else {
		typ := ""
		for _, v := range strings.Split(s, ",") {
			k, x, _ := strings.Cut(v, "=")
			switch k {
			case "type":
				typ = x
			case "src", "source":
				m.Name = x
			case "dst", "target":
				m.Target = x
			case "readonly":
				if x != "" && x != "true" {
					return m, fmt.Errorf("invalid readonly value")
				}
				m.ReadOnly = true
			default:
				return m, fmt.Errorf("unsupported mount option %q", k)
			}
		}
		if typ != "volume" {
			return m, fmt.Errorf("UnsupportedFeature: only named volumes; use cp for host files")
		}
	}
	if !ValidName(m.Name) {
		return m, fmt.Errorf("host bind mounts unsupported; use a named volume or cp")
	}
	return m, nil
}

type Process struct {
	Args        []string
	Env         []string
	User        string
	Cwd         string
	StopSignal  string
	TTY         bool
	Interactive bool
}
type ImageConfig struct {
	Entrypoint  []string
	Cmd         []string
	Env         []string
	User        string
	WorkingDir  string
	StopSignal  string
	Volumes     []string
	Healthcheck bool
}

func MergeEnv(base, override []string) []string {
	out := []string{}
	index := map[string]int{}
	for _, entry := range append(append([]string{}, base...), override...) {
		k, _, _ := strings.Cut(entry, "=")
		if i, ok := index[k]; ok {
			out[i] = entry
		} else {
			index[k] = len(out)
			out = append(out, entry)
		}
	}
	return out
}
func Resolve(s Spec, c ImageConfig) (Process, error) {
	p := Process{Env: MergeEnv(c.Env, s.Env), User: c.User, Cwd: c.WorkingDir, StopSignal: c.StopSignal, TTY: s.TTY, Interactive: s.Interactive}
	entry := append([]string{}, c.Entrypoint...)
	cmd := append([]string{}, c.Cmd...)
	if s.Entrypoint != nil {
		entry = nil
		if *s.Entrypoint != "" {
			entry = []string{*s.Entrypoint}
		}
		cmd = nil
	}
	if len(s.Command) > 0 {
		cmd = s.Command
	}
	p.Args = append(entry, cmd...)
	if len(p.Args) == 0 {
		return p, fmt.Errorf("image has no command; specify COMMAND")
	}
	for _, a := range p.Args {
		if strings.ContainsRune(a, 0) {
			return p, fmt.Errorf("NUL in argument")
		}
	}
	if s.User != "" {
		p.User = s.User
	}
	if s.Workdir != "" {
		p.Cwd = s.Workdir
	}
	if p.Cwd == "" {
		p.Cwd = "/"
	}
	if !path.IsAbs(p.Cwd) {
		return p, fmt.Errorf("image working directory is not absolute")
	}
	if p.StopSignal == "" {
		p.StopSignal = "SIGTERM"
	}
	return p, nil
}

type Exit struct {
	Code   *int
	Reason string
	OOM    bool
	At     time.Time
}
type Sandbox struct {
	ID          string
	Name        string
	Spec        Spec
	Process     Process
	ImageDigest string
	BaseDigest  string
	State       string
	Reason      string
	Warnings    []string
	Generation  int
	Created     time.Time
	Updated     time.Time
	Exit        *Exit
	PID         int
	PIDStart    string
	GuestMemory int64
	Slot        int
	// VMResourcesReleased is false by default so legacy failed records remain
	// quarantined until recovery or removal confirms VMM cleanup.
	VMResourcesReleased bool
}
type Volume struct {
	Name    string
	Size    int64
	Created time.Time
}
type Exec struct {
	ID          string
	Args        []string
	Env         []string
	User        string
	Cwd         string
	TTY         bool
	Interactive bool
}
type Bootstrap struct {
	Protocol    int
	ID          string
	Generation  int
	Token       string
	Certificate []byte
	PrivateKey  []byte
	CA          []byte
	Sandbox     Sandbox
}
type GuestStatus struct {
	Protocol   int
	ID         string
	Generation int
	State      string
	Exit       *Exit
	PID        int
}
type Request struct {
	Action    string
	ID        string
	Operation string
	Spec      *Spec
	Exec      *Exec
	Volume    *Volume
	Ref       string
	Policy    string
	Force     bool
	Signal    string
	Timeout   int
	Path      string
	Data      []byte
}
type Frame struct {
	Type     string
	Data     []byte
	Message  string
	Code     *int
	Width    uint16
	Height   uint16
	Sequence uint64
	Time     time.Time
}
