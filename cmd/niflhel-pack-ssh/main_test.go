package main

import (
	"testing"
)

func TestQuote(t *testing.T) {
	if got := quote("a'b;$(x)"); got != "'a'\"'\"'b;$(x)'" {
		t.Fatal(got)
	}
}
