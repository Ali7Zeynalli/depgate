// Package history keeps a short record of every scan and of what AI agents
// did over MCP, so the UI can show what changed between two scans and why.
//
// Layout under the data directory:
//
//	history/<key>.jsonl   one line per scan of a project (newest last)
//	activity.jsonl        one line per MCP tool call, all projects
//
// Everything stays on the computer. Old entries are dropped automatically.
package history

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/report"
)

const (
	keepScans    = 200
	keepDays     = 90
	keepActivity = 500
)

// Item is one finding as remembered for comparison.
type Item struct {
	Key    string `json:"k"`
	Pkg    string `json:"p"`
	Ver    string `json:"v,omitempty"`
	Kind   string `json:"t"` // vuln | malware | removed | update | deprecated | docker | server
	Group  string `json:"g,omitempty"`
	Sev    string `json:"s,omitempty"`
	Target string `json:"to,omitempty"`
	Title  string `json:"n,omitempty"`
}

// Scan is the compact record of one scan.
type Scan struct {
	At       time.Time      `json:"at"`
	By       string         `json:"by"`              // ui | mcp | cli | ci
	Agent    string         `json:"agent,omitempty"` // MCP client, e.g. "claude-code 2.1.4"
	Lock     string         `json:"lock,omitempty"`  // fingerprint of the lockfile
	Packages int            `json:"packages"`
	Summary  report.Summary `json:"sum"`
	Docker   int            `json:"docker"`
	Server   int            `json:"server"`
	Node     string         `json:"node,omitempty"`
	NodeNeed string         `json:"nodeNeed,omitempty"`
	Items    []Item         `json:"items"`
}

// Diff is what changed from one scan to the next.
type Diff struct {
	New         []Item `json:"new"`
	Fixed       []Item `json:"fixed"`
	Changed     []Item `json:"changed"`
	LockChanged bool   `json:"lockChanged"`
	First       bool   `json:"first,omitempty"` // no earlier scan to compare with
}

// Event is one thing an AI agent did over MCP.
type Event struct {
	At      time.Time `json:"at"`
	Agent   string    `json:"agent"`
	Via     string    `json:"via"` // http | stdio
	Project string    `json:"project,omitempty"`
	Tool    string    `json:"tool"`
	Target  string    `json:"target,omitempty"`  // e.g. lodahs@1.0.0
	Verdict string    `json:"verdict,omitempty"` // ok | caution | block (check_package)
	Note    string    `json:"note,omitempty"`
	Error   bool      `json:"error,omitempty"`
}

// FromProject makes the record of a scan. lock is the lockfile fingerprint ("" if none).
func FromProject(p *report.Project, by, agent, lock string) Scan {
	s := Scan{At: p.ScannedAt, By: by, Agent: agent, Lock: lock, Packages: p.Packages, Summary: p.Summary, Docker: len(p.Docker), Server: len(p.Server)}
	if s.At.IsZero() {
		s.At = time.Now().UTC()
	}
	if p.Node != nil {
		s.Node, s.NodeNeed = p.Node.Version, string(p.Node.Need)
	}
	for _, f := range p.Findings {
		if f.Group == report.GroupOK || f.Group == report.GroupOptional && f.Kind == "update" {
			continue // plain "newer version available" churns daily; not worth a history line
		}
		s.Items = append(s.Items, Item{Key: f.Kind + ":" + f.Pkg + "@" + f.Current, Pkg: f.Pkg, Ver: f.Current, Kind: f.Kind,
			Group: string(f.Group), Sev: f.Severity, Target: f.Target, Title: clip(f.Title, 120)})
	}
	for kind, is := range map[string][]report.DockerIssue{"docker": p.Docker, "server": p.Server} {
		for _, d := range is {
			s.Items = append(s.Items, Item{Key: kind + ":" + d.Rule + ":" + d.File + ":" + d.Service, Pkg: d.File, Kind: kind, Sev: d.Severity, Title: clip(d.Title.En, 120)})
		}
	}
	sort.Slice(s.Items, func(i, j int) bool { return s.Items[i].Key < s.Items[j].Key })
	return s
}

// Compare tells what changed from prev to cur (prev nil: first scan).
func Compare(prev, cur *Scan) Diff {
	d := Diff{New: []Item{}, Fixed: []Item{}, Changed: []Item{}}
	if prev == nil {
		d.First = true
		return d
	}
	d.LockChanged = prev.Lock != "" && cur.Lock != "" && prev.Lock != cur.Lock
	old := map[string]Item{}
	for _, it := range prev.Items {
		old[it.Key] = it
	}
	seen := map[string]bool{}
	for _, it := range cur.Items {
		seen[it.Key] = true
		o, ok := old[it.Key]
		switch {
		case !ok:
			d.New = append(d.New, it)
		case o.Sev != it.Sev || o.Target != it.Target || o.Group != it.Group:
			d.Changed = append(d.Changed, it)
		}
	}
	for _, it := range prev.Items {
		if !seen[it.Key] {
			d.Fixed = append(d.Fixed, it)
		}
	}
	return d
}

// Same reports whether a diff found nothing to show.
func (d Diff) Same() bool {
	return !d.First && len(d.New)+len(d.Fixed)+len(d.Changed) == 0
}

// Log stores scans and agent events in the data directory.
type Log struct {
	Dir string
	mu  sync.Mutex
}

func (l *Log) scanPath(project string) string {
	h := sha256.Sum256([]byte(filepath.Clean(project)))
	return filepath.Join(l.Dir, "history", hex.EncodeToString(h[:])[:24]+".jsonl")
}

// AddScan appends a scan of project and trims old ones.
func (l *Log) AddScan(project string, s Scan) error {
	if l == nil || l.Dir == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	p := l.scanPath(project)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if err := appendLine(p, s); err != nil {
		return err
	}
	scans := readLines[Scan](p)
	if len(scans) > keepScans+20 || len(scans) > 0 && time.Since(scans[0].At) > keepDays*24*time.Hour {
		cut := time.Now().Add(-keepDays * 24 * time.Hour)
		var keep []Scan
		for _, x := range scans {
			if x.At.After(cut) {
				keep = append(keep, x)
			}
		}
		if len(keep) > keepScans {
			keep = keep[len(keep)-keepScans:]
		}
		return rewrite(p, keep)
	}
	return nil
}

// Scans returns the scans of project, newest first.
func (l *Log) Scans(project string) []Scan {
	if l == nil || l.Dir == "" {
		return nil
	}
	s := readLines[Scan](l.scanPath(project))
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

// Forget removes the history of a project.
func (l *Log) Forget(project string) {
	if l == nil || l.Dir == "" {
		return
	}
	_ = os.Remove(l.scanPath(project))
}

// AddEvent appends an agent event and keeps the last few hundred.
func (l *Log) AddEvent(e Event) error {
	if l == nil || l.Dir == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	p := filepath.Join(l.Dir, "activity.jsonl")
	if err := appendLine(p, e); err != nil {
		return err
	}
	if st, err := os.Stat(p); err == nil && st.Size() > 400<<10 {
		es := readLines[Event](p)
		if len(es) > keepActivity {
			es = es[len(es)-keepActivity:]
		}
		return rewrite(p, es)
	}
	return nil
}

// Events returns agent events under dir ("" = all), newest first, at most n.
func (l *Log) Events(dir string, n int) []Event {
	if l == nil || l.Dir == "" {
		return nil
	}
	all := readLines[Event](filepath.Join(l.Dir, "activity.jsonl"))
	var out []Event
	for i := len(all) - 1; i >= 0 && len(out) < n; i-- {
		e := all[i]
		if dir != "" && !within(e.Project, dir) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Clear deletes the history of the projects under dir and their agent events.
func (l *Log) Clear(dir string, projects []string) error {
	if l == nil || l.Dir == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, p := range projects {
		_ = os.Remove(l.scanPath(p))
	}
	p := filepath.Join(l.Dir, "activity.jsonl")
	var keep []Event
	for _, e := range readLines[Event](p) {
		if !within(e.Project, dir) {
			keep = append(keep, e)
		}
	}
	return rewrite(p, keep)
}

func within(p, dir string) bool {
	if p == "" || dir == "" {
		return false
	}
	p, dir = filepath.Clean(p), filepath.Clean(dir)
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

// appendLine writes one JSON line; O_APPEND keeps lines from the UI server and
// an MCP stdio process from mixing.
func appendLine(p string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

func readLines[T any](p string) []T {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var out []T
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var v T
		if json.Unmarshal(sc.Bytes(), &v) == nil {
			out = append(out, v)
		}
	}
	return out
}

func rewrite[T any](p string, vs []T) error {
	var buf bytes.Buffer
	for _, v := range vs {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(append(b, '\n'))
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// LockFingerprint fingerprints the lockfile of a project (its own folder or a
// parent, for workspaces); "" when there is none.
func LockFingerprint(dir, name string) string {
	if name == "" {
		return ""
	}
	if filepath.IsAbs(name) {
		if b, err := os.ReadFile(name); err == nil {
			h := sha256.Sum256(b)
			return hex.EncodeToString(h[:])[:16]
		}
	}
	base := filepath.Base(name)
	for d, i := filepath.Clean(dir), 0; i < 6; d, i = filepath.Dir(d), i+1 {
		if b, err := os.ReadFile(filepath.Join(d, base)); err == nil {
			h := sha256.Sum256(b)
			return hex.EncodeToString(h[:])[:16]
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	return ""
}

func clip(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}
