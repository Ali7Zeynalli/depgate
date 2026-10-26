package app

import (
	"path/filepath"
	"sort"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/history"
	"github.com/Ali7Zeynalli/depgate/internal/store"
)

// History is the scan history and agent activity of a project or folder.
type History struct {
	Dir      string           `json:"dir"`
	Projects []ProjectHistory `json:"projects"`
	Events   []history.Event  `json:"events"`
	Agents   []Agent          `json:"agents"`
}

// ProjectHistory lists the scans of one project, newest first.
type ProjectHistory struct {
	Dir   string     `json:"dir"`
	Name  string     `json:"name"`
	Scans []ScanView `json:"scans"`
}

// ScanView is one scan and what changed since the scan before it.
type ScanView struct {
	history.Scan
	Diff history.Diff `json:"diff"`
}

// Agent sums up what one AI agent did.
type Agent struct {
	Name    string    `json:"name"`
	Via     string    `json:"via"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	Calls   int       `json:"calls"`
	Checks  int       `json:"checks"`
	Blocked int       `json:"blocked"` // check_package said caution or block
	Scans   int       `json:"scans"`
}

const showScans = 60

// History returns the history of dir: one project or a folder of projects.
func (m *Manager) History(dir string) (*History, error) {
	h := &History{Dir: dir, Projects: []ProjectHistory{}, Events: []history.Event{}, Agents: []Agent{}}
	if m.ro != nil || dir == "" {
		return h, nil
	}
	dir = filepath.Clean(dir)
	for _, e := range m.under(dir) {
		ph := ProjectHistory{Dir: e.Dir, Name: e.Name, Scans: []ScanView{}}
		scans := m.Store.History.Scans(e.Dir)
		for i := 0; i < len(scans) && i < showScans; i++ {
			var prev *history.Scan
			if i+1 < len(scans) {
				prev = &scans[i+1]
			}
			v := ScanView{Scan: scans[i], Diff: history.Compare(prev, &scans[i])}
			v.Items = nil // the diff says what matters; keeps the answer small
			ph.Scans = append(ph.Scans, v)
		}
		h.Projects = append(h.Projects, ph)
	}
	if ev := m.Store.History.Events(dir, 200); ev != nil {
		h.Events = ev
	}
	h.Agents = agents(h.Events)
	return h, nil
}

// ClearHistory forgets the scan history and agent activity under dir.
func (m *Manager) ClearHistory(dir string) error {
	if m.ro != nil {
		return ErrReadOnly
	}
	dir = filepath.Clean(dir)
	var ds []string
	for _, e := range m.under(dir) {
		ds = append(ds, e.Dir)
	}
	return m.Store.History.Clear(dir, ds)
}

func (m *Manager) under(dir string) []store.Entry {
	var out []store.Entry
	for _, e := range m.Store.Projects() {
		if store.Within(e.Dir, dir) {
			out = append(out, e)
		}
	}
	return out
}

// agents groups events (newest first) by agent, most recent first.
func agents(ev []history.Event) []Agent {
	by := map[string]*Agent{}
	for _, e := range ev {
		k := e.Agent + "|" + e.Via
		a := by[k]
		if a == nil {
			a = &Agent{Name: e.Agent, Via: e.Via, Last: e.At, First: e.At}
			by[k] = a
		}
		if e.At.After(a.Last) {
			a.Last = e.At
		}
		if e.At.Before(a.First) {
			a.First = e.At
		}
		switch e.Tool {
		case "connect":
			continue
		case "check_package":
			a.Checks++
			if e.Verdict == "caution" || e.Verdict == "block" {
				a.Blocked++
			}
		case "scan_project":
			a.Scans++
		}
		a.Calls++
	}
	out := []Agent{}
	for _, a := range by {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	return out
}
