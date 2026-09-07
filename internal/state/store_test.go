package state

import (
	"errors"
	"niflhel/internal/api"
	"path/filepath"
	"sync"
	"testing"
)

func TestPersistenceAndLookup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.db")
	s, e := Open(p)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []api.Sandbox{{ID: "abc1", Name: "one", State: "created"}, {ID: "abc2", Name: "two", State: "created"}} {
		if e = s.Create(v); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = s.Get("abc"); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if e = s.Create(api.Sandbox{ID: "other", Name: "one"}); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if e = s.Update("abc1", func(v *api.Sandbox) error { return Transition(v, "starting", "") }); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	v, e := s.Get("one")
	if e != nil || v.State != "starting" {
		t.Fatal(v, e)
	}
}
func TestTransitionAndConcurrentUpdates(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "s.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	s.Create(api.Sandbox{ID: "id", Name: "x", State: "created"})
	if e = s.Update("id", func(v *api.Sandbox) error { return Transition(v, "running", "") }); e == nil {
		t.Fatal("skipped boot transition")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := s.Update("id", func(v *api.Sandbox) error { v.Generation++; return nil }); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	v, _ := s.Get("id")
	if v.Generation != 20 {
		t.Fatal(v.Generation)
	}
}
