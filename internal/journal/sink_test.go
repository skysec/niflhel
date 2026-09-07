package journal

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDiagnosticRotation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "console.log")
	if e := Sink(p, bytes.NewReader(bytes.Repeat([]byte("x"), Limit*3))); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{p, p + ".1"} {
		s, e := os.Stat(path)
		if e != nil || s.Size() > Limit {
			t.Fatal(s, e)
		}
	}
}
