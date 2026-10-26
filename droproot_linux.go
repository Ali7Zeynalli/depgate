//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// dropRoot runs when the container starts as root (the default compose file
// does this). It picks the user whose files DepGate has to read — DEPGATE_UID /
// DEPGATE_GID when set, else the owner of the first mounted folder
// (DEPGATE_ROOTS, then HOME) — gives that user the data folder, and switches to
// it for good. After setuid the process keeps no capabilities, so nobody has to
// know their own uid and DepGate never runs as root.
func dropRoot(dataDir string, chown bool) error {
	if os.Getuid() != 0 {
		return nil
	}
	uid, gid := ownerOfMount()
	if uid == 0 {
		uid, gid = 65532, 65532 // folders owned by root: an unprivileged user, read access only
	}
	if chown {
		if err := chownTree(dataDir, fmt.Sprintf("%d:%d", uid, gid)); err != nil {
			return fmt.Errorf("data folder %s: %w", dataDir, err)
		}
	}
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid %d: %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid %d: %w", uid, err)
	}
	return nil
}

func ownerOfMount() (int, int) {
	if u, err := strconv.Atoi(os.Getenv("DEPGATE_UID")); err == nil && u >= 0 {
		g := u
		if v, err := strconv.Atoi(os.Getenv("DEPGATE_GID")); err == nil && v >= 0 {
			g = v
		}
		return u, g
	}
	var dirs []string
	for _, d := range strings.Split(os.Getenv("DEPGATE_ROOTS"), string(os.PathListSeparator)) {
		if d = strings.TrimSpace(d); d != "" {
			dirs = append(dirs, filepath.Clean(d))
		}
	}
	if h := os.Getenv("HOME"); h != "" {
		dirs = append(dirs, h)
	}
	for _, d := range dirs {
		var st syscall.Stat_t
		if syscall.Stat(d, &st) == nil && st.Uid != 0 {
			return int(st.Uid), int(st.Gid)
		}
	}
	return 0, 0
}
