//go:build !linux

package main

// dropRoot is only needed in the Linux container.
func dropRoot(dataDir string, chown bool) error { return nil }
