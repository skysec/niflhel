package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
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

func TestPublisherKeyOutsideBuildKitRoots(t *testing.T) {
	publisherKey := func(path string, roots ...string) (ed25519.PrivateKey, error) {
		key, _, err := prepareBaseBuild(path, t.TempDir(), roots...)
		return key, err
	}
	writeKey := func(path string) {
		t.Helper()
		key := bytes.Repeat([]byte{1}, ed25519.PrivateKeySize)
		if e := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0600); e != nil {
			t.Fatal(e)
		}
	}
	contextDir := t.TempDir()
	inside := filepath.Join(contextDir, "publisher.key")
	writeKey(inside)
	if _, e := publisherKey(inside, contextDir); e == nil {
		t.Fatal("in-context publisher key accepted")
	}
	if e := os.Remove(inside); e != nil {
		t.Fatal(e)
	}
	externalDir := t.TempDir()
	external := filepath.Join(externalDir, "publisher.key")
	writeKey(external)
	link := filepath.Join(contextDir, "linked.key")
	if e := os.Symlink(external, link); e != nil {
		t.Fatal(e)
	}
	if _, e := publisherKey(link, contextDir); e == nil {
		t.Fatal("in-context symlink to publisher key accepted")
	}
	if e := os.Remove(link); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(external, filepath.Join(contextDir, "alias.key")); e != nil {
		t.Fatal(e)
	}
	if _, e := publisherKey(external, contextDir); e == nil {
		t.Fatal("hard-link alias in build context accepted")
	}
	if e := os.Remove(filepath.Join(contextDir, "alias.key")); e != nil {
		t.Fatal(e)
	}
	key, e := publisherKey(external, contextDir)
	if e != nil || len(key) != ed25519.PrivateKeySize {
		t.Fatal(len(key), e)
	}
	if _, e = publisherKey(external, contextDir, externalDir); e == nil {
		t.Fatal("key in exported Dockerfile root accepted")
	}
}
