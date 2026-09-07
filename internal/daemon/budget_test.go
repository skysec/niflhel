package daemon

import (
	"niflhel/internal/api"
	"testing"
)

func TestMemoryAdmission(t *testing.T) {
	if e := memoryBudget(512*api.MiB, 1024*api.MiB); e != nil {
		t.Fatal(e)
	}
	if e := memoryBudget(900*api.MiB, 1024*api.MiB); e == nil {
		t.Fatal("host reserve overcommitted")
	}
}
