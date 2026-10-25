// Package app is the long-running DepGate service behind the web UI: it keeps
// the remembered projects, scans them in the background and lets the UI
// browse folders to add new ones.
package app

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/project"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/scan"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
	"github.com/Ali7Zeynalli/depgate/internal/store"
)

// ProjectState is one project as the UI sees it.
type ProjectState struct {
	Dir      string          `json:"dir"`
	Name     string          `json:"name"`
	Group    string          `json:"group"` // folder this project is shown under in the sidebar
	AddedAt  time.Time       `json:"addedAt,omitempty"`
	Scanning bool            `json:"scanning"`
	Queued   bool            `json:"queued"`
	Report   *report.Project `json:"report"`
}

// State is everything the UI needs in one response.
type State struct {
	Tool      string         `json:"tool"`
	ReadOnly  bool           `json:"readOnly"`
	Roots     []string       `json:"roots"`
	Busy      bool           `json:"busy"`
	LastScan  *time.Time     `json:"lastScan,omitempty"`
	Errors    []string       `json:"errors,omitempty"`
	Offline   bool           `json:"offline,omitempty"`
	Projects  []ProjectState `json:"projects"`
	Container bool           `json:"container,omitempty"`
}

// Entry is one folder in a Browse listing.
type Entry struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	IsProject bool   `json:"isProject"`
	Lockfile  bool   `json:"lockfile"`
	Added     bool   `json:"added"`
}

type Listing struct {
	Path    string   `json:"path"`             // "" = list of roots
	Parent  string   `json:"parent,omitempty"` // "" at a root
	Crumbs  []Crumb  `json:"crumbs"`           // breadcrumb from the root
	Entries []Entry  `json:"entries"`
	Project bool     `json:"project"`         // the folder itself has a package.json
	Found   []string `json:"found,omitempty"` // projects Add would register for this folder
}

type Crumb struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// Manager implements the web backend.
type Manager struct {
	Store     *store.Store
	Fetcher   func() sources.Fetcher
	Opt       scan.Options
	Roots     []string // folders the UI may browse; never empty
	Depth     int
	Container bool

	mu       sync.Mutex
	running  map[string]bool
	queued   map[string]bool
	errors   []string
	lastScan *time.Time
	jobs     chan []string
	once     sync.Once

	ro *report.Report // read-only mode (--view)
}

// ReadOnly builds a Manager that only shows a saved report.
func ReadOnly(r *report.Report) *Manager { return &Manager{ro: r} }

// Error is an error with a bilingual message for the UI.
type Error struct{ T i18n.T }

func (e *Error) Error() string { return e.T.En }

func newErr(az, en string, args ...any) error { return &Error{i18n.F(az, en, args...)} }

var ErrReadOnly = newErr("saxlanmış hesabat rejimi: dəyişiklik mümkün deyil", "read-only report view: changes are not possible")
var ErrOutside = newErr("bu qovluq icazə verilən köklərdən kənardadır", "this folder is outside the allowed roots")

func (m *Manager) start(ctx context.Context) {
	m.once.Do(func() {
		m.running, m.queued = map[string]bool{}, map[string]bool{}
		m.jobs = make(chan []string, 64)
		go m.worker(ctx)
	})
}

// Start launches the background scanner.
func (m *Manager) Start(ctx context.Context) {
	if m.ro == nil {
		m.start(ctx)
	}
}

func (m *Manager) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case dirs := <-m.jobs:
			m.mu.Lock()
			var todo []string
			for _, d := range dirs {
				if m.queued[d] {
					delete(m.queued, d)
					m.running[d] = true
					todo = append(todo, d)
				}
			}
			m.mu.Unlock()
			if len(todo) == 0 {
				continue
			}
			opt := m.Opt
			opt.Now = time.Now()
			rep := scan.Run(ctx, m.Fetcher(), todo, opt)
			for i := range rep.Projects {
				p := &rep.Projects[i]
				_ = m.Store.SaveReport(p)
				m.Store.Rename(p.Dir, p.Name)
			}
			now := time.Now().UTC()
			m.mu.Lock()
			for _, d := range todo {
				delete(m.running, d)
			}
			m.errors, m.lastScan = rep.Errors, &now
			m.mu.Unlock()
		}
	}
}

// Scan queues dirs (all remembered projects when empty).
func (m *Manager) Scan(dirs []string) error {
	if m.ro != nil {
		return ErrReadOnly
	}
	if len(dirs) == 0 {
		for _, e := range m.Store.Projects() {
			dirs = append(dirs, e.Dir)
		}
	}
	var ok []string
	m.mu.Lock()
	for _, d := range dirs {
		d = filepath.Clean(d)
		if !m.Store.Has(d) || m.queued[d] {
			continue
		}
		m.queued[d] = true
		ok = append(ok, d)
	}
	m.mu.Unlock()
	if len(ok) > 0 {
		m.jobs <- ok
	}
	return nil
}

// Add registers every project found under path and scans the new ones.
func (m *Manager) Add(path string) ([]string, error) {
	if m.ro != nil {
		return nil, ErrReadOnly
	}
	abs, err := m.allowed(path)
	if err != nil {
		return nil, err
	}
	dirs, err := project.Find(abs, m.Depth)
	if err != nil {
		return nil, err
	}
	if len(dirs) == 0 {
		return nil, newErr("bu qovluqda asılılığı olan package.json tapılmadı", "no package.json with dependencies in this folder")
	}
	var es []store.Entry
	for _, d := range dirs {
		es = append(es, store.Entry{Dir: d, Group: abs})
	}
	added, err := m.Store.Add(es...)
	if err != nil {
		return nil, err
	}
	if len(added) > 0 {
		_ = m.Scan(added)
	}
	return dirs, nil
}

// Remove forgets a project.
func (m *Manager) Remove(dir string) error {
	if m.ro != nil {
		return ErrReadOnly
	}
	return m.Store.Remove(filepath.Clean(dir))
}

// State returns the current view.
func (m *Manager) State() State {
	if m.ro != nil {
		st := State{Tool: m.ro.Tool, ReadOnly: true, Errors: m.ro.Errors, Offline: m.ro.Offline, Projects: []ProjectState{}}
		t := m.ro.ScannedAt
		st.LastScan = &t
		for i := range m.ro.Projects {
			p := &m.ro.Projects[i]
			st.Projects = append(st.Projects, ProjectState{Dir: p.Dir, Name: p.Name, Report: p})
		}
		assignGroups(st.Projects, nil)
		return st
	}
	m.mu.Lock()
	st := State{Tool: "depgate " + m.Opt.Version, Roots: m.Roots, Errors: m.errors, LastScan: m.lastScan, Offline: m.Opt.Offline, Container: m.Container, Projects: []ProjectState{}}
	running, queued := copyMap(m.running), copyMap(m.queued)
	m.mu.Unlock()
	st.Busy = len(running)+len(queued) > 0
	explicit := map[string]string{}
	for _, e := range m.Store.Projects() {
		st.Projects = append(st.Projects, ProjectState{Dir: e.Dir, Name: e.Name, AddedAt: e.AddedAt, Scanning: running[e.Dir], Queued: queued[e.Dir], Report: m.Store.Report(e.Dir)})
		explicit[e.Dir] = e.Group
	}
	assignGroups(st.Projects, explicit)
	return st
}

// assignGroups sets the sidebar folder of every project and sorts the list by
// folder, then by path inside it (the folder's own project first). A project
// uses the folder it was added from; projects saved before groups existed are
// put under the outermost other project that contains them, else on their own.
func assignGroups(ps []ProjectState, explicit map[string]string) {
	for i := range ps {
		g := explicit[ps[i].Dir]
		if g == "" || !store.Within(ps[i].Dir, g) {
			g = ps[i].Dir
			for _, o := range ps {
				if o.Dir != ps[i].Dir && store.Within(ps[i].Dir, o.Dir) && len(o.Dir) < len(g) {
					g = o.Dir
				}
			}
		}
		ps[i].Group = g
	}
	// a project that sits inside another group's folder joins the outer group
	for moved := true; moved; {
		moved = false
		for i := range ps {
			for _, o := range ps {
				if o.Group != ps[i].Group && store.Within(ps[i].Group, o.Group) {
					ps[i].Group, moved = o.Group, true
				}
			}
		}
	}
	sort.SliceStable(ps, func(i, j int) bool {
		a, b := ps[i], ps[j]
		if a.Group != b.Group {
			ga, gb := strings.ToLower(filepath.Base(a.Group)), strings.ToLower(filepath.Base(b.Group))
			if ga != gb {
				return ga < gb
			}
			return a.Group < b.Group
		}
		return a.Dir < b.Dir
	})
}

func copyMap(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// allowed resolves path and checks it is inside one of the roots.
func (m *Manager) allowed(path string) (string, error) {
	if path == "" {
		return "", newErr("qovluq göstərilməyib", "no folder given")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", newErr("qovluq tapılmadı: %s", "folder not found: %s", abs)
	}
	st, err := os.Stat(real)
	if err != nil || !st.IsDir() {
		return "", newErr("qovluq deyil: %s", "not a folder: %s", abs)
	}
	for _, r := range m.Roots {
		rr, err := filepath.EvalSymlinks(r)
		if err != nil {
			continue
		}
		if real == rr || strings.HasPrefix(real, rr+string(os.PathSeparator)) {
			return real, nil
		}
	}
	return "", ErrOutside
}

var hideDirs = map[string]bool{"node_modules": true, "vendor": true, "dist": true, "build": true, "target": true, "__pycache__": true}

// Browse lists sub-folders of path (the roots when path is empty).
func (m *Manager) Browse(path string) (*Listing, error) {
	if m.ro != nil {
		return nil, ErrReadOnly
	}
	var added []string
	for _, e := range m.Store.Projects() {
		added = append(added, e.Dir)
	}
	isAdded := func(p string) bool { // the folder itself or a project below it is remembered
		for _, d := range added {
			if d == p || strings.HasPrefix(d, p+string(os.PathSeparator)) {
				return true
			}
		}
		return false
	}
	mk := func(name, p string) Entry {
		e := Entry{Name: name, Path: p, Added: isAdded(p)}
		if _, err := os.Stat(filepath.Join(p, "package.json")); err == nil {
			e.IsProject = true
			for _, lf := range []string{"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "npm-shrinkwrap.json"} {
				if _, err := os.Stat(filepath.Join(p, lf)); err == nil {
					e.Lockfile = true
					break
				}
			}
		}
		return e
	}
	if path == "" && len(m.Roots) > 1 {
		l := &Listing{Crumbs: []Crumb{}}
		for _, r := range m.Roots {
			l.Entries = append(l.Entries, mk(r, r))
		}
		return l, nil
	}
	if path == "" {
		path = m.Roots[0]
	}
	abs, err := m.allowed(path)
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(abs)
	if err != nil {
		return nil, err
	}
	l := &Listing{Path: abs, Entries: []Entry{}}
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, ".") || hideDirs[n] {
			continue
		}
		p := filepath.Join(abs, n)
		if !e.IsDir() {
			if e.Type()&os.ModeSymlink == 0 {
				continue
			}
			if st, err := os.Stat(p); err != nil || !st.IsDir() {
				continue
			}
		}
		l.Entries = append(l.Entries, mk(n, p))
		if len(l.Entries) >= 1000 {
			break
		}
	}
	sort.Slice(l.Entries, func(i, j int) bool {
		a, b := l.Entries[i], l.Entries[j]
		if a.IsProject != b.IsProject {
			return a.IsProject
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	_, err = os.Stat(filepath.Join(abs, "package.json"))
	l.Project = err == nil
	l.Crumbs, l.Parent = m.crumbs(abs)
	return l, nil
}

func (m *Manager) crumbs(abs string) ([]Crumb, string) {
	var root string
	for _, r := range m.Roots {
		rr, err := filepath.EvalSymlinks(r)
		if err == nil && (abs == rr || strings.HasPrefix(abs, rr+string(os.PathSeparator))) && len(rr) > len(root) {
			root = rr
		}
	}
	if root == "" {
		return nil, ""
	}
	cs := []Crumb{{Name: root, Path: root}}
	rel, _ := filepath.Rel(root, abs)
	cur := root
	if rel != "." {
		for _, part := range strings.Split(rel, string(os.PathSeparator)) {
			cur = filepath.Join(cur, part)
			cs = append(cs, Crumb{Name: part, Path: cur})
		}
	}
	parent := ""
	if len(cs) > 1 {
		parent = cs[len(cs)-2].Path
	} else if len(m.Roots) > 1 {
		parent = "" // back to the roots list
	}
	return cs, parent
}
