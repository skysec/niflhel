package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelpAndUnsupported(t *testing.T) {
	for _, args := range [][]string{{"run", "--privileged", "alpine"}, {"run", "--runtime", "runsc", "alpine"}, {"run", "--cpus", "0", "alpine"}, {"exec"}, {"run", "--network", "none", "-p", "8080:80", "alpine"}} {
		var b bytes.Buffer
		c := New(strings.NewReader(""), &b, &b)
		c.SetArgs(args)
		if e := c.Execute(); e == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	var b bytes.Buffer
	c := New(strings.NewReader(""), &b, &b)
	c.SetArgs([]string{"--help"})
	if e := c.Execute(); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"run", "exec", "base", "volume", "doctor"} {
		if !strings.Contains(b.String(), s) {
			t.Fatal("missing", s)
		}
	}
}
func TestBuildArgumentsRemainLiteral(t *testing.T) {
	args := BuildArgs("unix:///buildkit.sock", "/a b", "/a b/Dockerfile", "/out.tar", "", []string{"VALUE=$(touch /tmp/no)"})
	found := false
	for _, arg := range args {
		if arg == "build-arg:VALUE=$(touch /tmp/no)" {
			found = true
		}
	}
	if !found {
		t.Fatal(args)
	}
}
