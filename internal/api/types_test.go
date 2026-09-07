package api

import (
	"reflect"
	"testing"
)

func TestResolve(t *testing.T) {
	c := ImageConfig{Entrypoint: []string{"python"}, Cmd: []string{"main.py"}, Env: []string{"A=1", "B=2"}, WorkingDir: "/app"}
	s := DefaultSpec()
	s.Command = []string{"-c", "print('$HOME')"}
	s.Env = []string{"A=3"}
	p, e := Resolve(s, c)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(p.Args, []string{"python", "-c", "print('$HOME')"}) {
		t.Fatal(p.Args)
	}
	if !reflect.DeepEqual(p.Env, []string{"A=3", "B=2"}) {
		t.Fatal(p.Env)
	}
	entry := "/bin/sh"
	s.Entrypoint = &entry
	s.Command = nil
	p, e = Resolve(s, c)
	if e != nil || !reflect.DeepEqual(p.Args, []string{entry}) {
		t.Fatal(p, e)
	}
	empty := ""
	s.Entrypoint = &empty
	if _, e = Resolve(s, c); e == nil {
		t.Fatal("empty command accepted")
	}
}
func TestValidation(t *testing.T) {
	for _, change := range []func(*Spec){
		func(s *Spec) { s.Runtime = "runsc" }, func(s *Spec) { s.Platform = "linux/arm64" }, func(s *Spec) { s.CPUs = 0 },
		func(s *Spec) { s.Memory = 1 }, func(s *Spec) { s.Name = "../escape" }, func(s *Spec) { s.Network = "host" },
		func(s *Spec) { s.Network = "none"; s.Ports = []Port{{"127.0.0.1", 80, 80}} },
		func(s *Spec) { s.Mounts = []Mount{{"work", "/proc/x", false}} },
		func(s *Spec) { s.Env = []string{"BAD"} },
	} {
		s := DefaultSpec()
		s.Image = "alpine"
		change(&s)
		if s.Validate() == nil {
			t.Fatalf("accepted %+v", s)
		}
	}
	s := DefaultSpec()
	s.Image = "alpine"
	if e := s.Validate(); e != nil {
		t.Fatal(e)
	}
}
func TestSizesAndMounts(t *testing.T) {
	for _, s := range []string{"-1g", "999999999999999999g", "0", "1.5g", "what"} {
		if _, e := Size(s); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	for _, s := range []string{"1g", "1024m", "1GiB"} {
		n, e := Size(s)
		if n != GiB || e != nil {
			t.Fatal(n, e)
		}
	}
	if _, e := ParseMount("/tmp:/work"); e == nil {
		t.Fatal("host path accepted")
	}
	m, e := ParseMount("type=volume,src=work,dst=/work,readonly")
	if e != nil || !m.ReadOnly {
		t.Fatal(m, e)
	}
	p, e := ParsePort("8080:80")
	if e != nil || p.HostIP != "127.0.0.1" {
		t.Fatal(p, e)
	}
}
