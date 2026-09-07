package journal

import (
	"path/filepath"
	"testing"
)

func TestRestartAndCursor(t *testing.T) {
	p := filepath.Join(t.TempDir(), "log")
	j := Open(p)
	j.Write("stdout", []byte("one"))
	j.Write("stderr", []byte("two"))
	j = Open(p)
	v := j.Read(1)
	if len(v) != 1 || string(v[0].Data) != "two" || v[0].Type != "stderr" {
		t.Fatal(v)
	}
	j.Write("stdout", []byte("three"))
	if j.Read(2)[0].Sequence != 3 {
		t.Fatal("cursor reset")
	}
}
