//go:build windows

package secret

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for _, machine := range []bool{false, true} {
		plain := []byte("4#9*1=7%2/ test code")
		ent := []byte("att-monitor test")
		blob, err := Protect(plain, ent, machine)
		if err != nil {
			t.Fatalf("protect(machine=%v): %v", machine, err)
		}
		if bytes.Contains(blob, plain) {
			t.Fatal("blob contains plaintext")
		}
		got, err := Unprotect(blob, ent)
		if err != nil {
			t.Fatalf("unprotect: %v", err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("got %q want %q", got, plain)
		}
		if _, err := Unprotect(blob, []byte("wrong entropy")); err == nil {
			t.Fatal("expected failure with wrong entropy")
		}
	}
}
