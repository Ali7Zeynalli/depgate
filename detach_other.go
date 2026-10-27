//go:build !windows

package main

// detach is only needed on Windows (see detach_windows.go).
func detach() bool { return false }
