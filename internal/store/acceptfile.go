package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AcceptFileName is the file a team commits so that the UI and CI (depgate --ci)
// treat the same risks as accepted. DepGate only reads it; the UI offers it as a download.
const AcceptFileName = "depgate-accept.json"

// AcceptFile is the content of depgate-accept.json.
type AcceptFile struct {
	Schema   string      `json:"schema"` // depgate/accept@1
	Accepted []FileEntry `json:"accepted"`
}

// FileEntry is one accepted risk; Key is the finding key shown by DepGate
// (it includes the version, e.g. vuln:express@4.19.2).
type FileEntry struct {
	Key    string `json:"key"`
	Pkg    string `json:"pkg,omitempty"`
	Reason string `json:"reason"`
	Until  string `json:"until"` // 2026-12-31 or RFC 3339
	At     string `json:"at,omitempty"`
}

// FileAcceptances reads depgate-accept.json from dir and its parent folders (up
// to the repository root) and returns its entries as acceptances for dir.
// Entries without a reason, a key or a valid end date are ignored; malware
// can never be accepted (ApplyAcceptances skips it).
func FileAcceptances(dir string) []Acceptance {
	dir = filepath.Clean(dir)
	var out []Acceptance
	for d, i := dir, 0; i < 8; d, i = filepath.Dir(d), i+1 {
		p := filepath.Join(d, AcceptFileName)
		if b, err := os.ReadFile(p); err == nil && len(b) < 1<<20 {
			var f AcceptFile
			if json.Unmarshal(b, &f) == nil {
				for _, e := range f.Accepted {
					until, ok := parseDay(e.Until, true)
					if !ok || strings.TrimSpace(e.Reason) == "" || e.Key == "" || strings.HasPrefix(e.Key, "malware:") {
						continue
					}
					at, _ := parseDay(e.At, false)
					out = append(out, Acceptance{Dir: dir, Key: e.Key, Pkg: e.Pkg, Reason: strings.TrimSpace(e.Reason), At: at, Until: until, File: p})
				}
			}
		}
		if st, err := os.Stat(filepath.Join(d, ".git")); err == nil && st != nil || filepath.Dir(d) == d {
			break // the repository root (or the file system root)
		}
	}
	return out
}

// parseDay reads 2026-12-31 or an RFC 3339 time; a plain date ends at the end of that day.
func parseDay(s string, end bool) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		if end {
			t = t.Add(24*time.Hour - time.Second)
		}
		return t, true
	}
	return time.Time{}, false
}
