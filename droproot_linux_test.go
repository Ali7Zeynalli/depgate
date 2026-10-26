//go:build linux

package main

import (
	"os"
	"testing"
)

func TestOwnerOfMount(t *testing.T) {
	dir := t.TempDir()
	if os.Getuid() == 0 {
		if err := os.Chown(dir, 1234, 2345); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("DEPGATE_UID", "")
	t.Setenv("DEPGATE_ROOTS", dir)
	t.Setenv("HOME", "/nonexistent")
	u, g := ownerOfMount()
	if os.Getuid() == 0 && (u != 1234 || g != 2345) {
		t.Fatalf("owner of the mounted folder: got %d:%d", u, g)
	}
	if os.Getuid() != 0 && u != os.Getuid() {
		t.Fatalf("owner: got %d, want %d", u, os.Getuid())
	}
	t.Setenv("DEPGATE_UID", "1500")
	t.Setenv("DEPGATE_GID", "1600")
	if u, g := ownerOfMount(); u != 1500 || g != 1600 {
		t.Fatalf("DEPGATE_UID/GID: got %d:%d", u, g)
	}
}
