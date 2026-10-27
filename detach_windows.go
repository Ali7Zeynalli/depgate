//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

// Double-clicked in Explorer, a console program gets a terminal window of its
// own that closes DepGate when it is closed. Then DepGate starts itself again
// without a window and lets this copy (and its terminal) go: the server runs in
// the background and is opened in the browser. Started from a terminal (cmd,
// PowerShell) or with arguments, nothing changes.

const createNoWindow = 0x08000000

func detach() bool {
	if len(os.Args) > 1 || os.Getenv(childEnv) != "" || !ownConsole() {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), childEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd.Start() == nil
}

// ownConsole reports whether this process is the only one on its console,
// that is, Windows made the console for it (a double-click) rather than it
// being started from a terminal.
func ownConsole() bool {
	k := syscall.NewLazyDLL("kernel32.dll")
	p := k.NewProc("GetConsoleProcessList")
	if p.Find() != nil {
		return false
	}
	var ids [4]uint32
	n, _, _ := p.Call(uintptr(unsafe.Pointer(&ids[0])), uintptr(len(ids)))
	return n == 1
}
