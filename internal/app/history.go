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
	Dir      string                `json:"dir"`
	KPI      KPI                   `json:"kpi"` // the projects together
	Projects []ProjectHistory      `json:"projects"`
	Events   []history.Event       `json:"events"`
	Agents   []Agent               `json:"agents"`
	Work     []history.WorkSession `json:"work"` // tasks AI agents took on (get_overview → start_tasks → complete_task)
}

// ProjectHistory lists the scans of one project, newest first.
type ProjectHistory struct {
	Dir   string     `json:"dir"`
	Name  string     `json:"name"`
	KPI   KPI        `json:"kpi"`
	Scans []ScanView `json:"scans"`
	// Git: commits that changed the lockfile or package.json (last 90 days) and
	// uncommitted lockfile changes, shown in the same timeline as the scans
	Git *history.GitLog `json:"git,omitempty"`
}

// KPI sums up how a project is doing over time, from its scan history.
type KPI struct {
	OpenUrgent   int          `json:"openUrgent"`          // malware, critical/high or "do now" findings open now
	MTTRHours    float64      `json:"mttrHours"`           // mean time from first seen to gone (last 90 days); 0 = none fixed yet
	FixedN       int          `json:"fixedN"`              // fixes the mean is taken over
	OldestDays   int          `json:"oldestDays"`          // age of the oldest important open finding
	OldestPkg    string       `json:"oldestPkg,omitempty"` // which one
	OldestSev    string       `json:"oldestSev,omitempty"` // its severity or kind
	OldestDir    string       `json:"oldestDir,omitempty"` // its project (folders)
	WeekNew      int          `json:"weekNew"`             // new findings in the last 7 days
	WeekFixed    int          `json:"weekFixed"`           // gone in the last 7 days
	Weeks        []WeekStat   `json:"weeks"`               // last 8 weeks, oldest first
	Trend        []TrendPoint `json:"trend"`               // urgent count per scan, last 30 days
	AcceptedSoon int          `json:"acceptedSoon"`        // accepted risks that end within 14 days
	LastScan     *time.Time   `json:"lastScan,omitempty"`
}

type WeekStat struct {
	Start time.Time `json:"start"`
	New   int       `json:"new"`
	Fixed int       `json:"fixed"`
}

type TrendPoint struct {
	At     time.Time `json:"at"`
	Urgent int       `json:"urgent"`
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

// History returns the history of dir: a folder of projects, or with only set
// just the project at dir (a monorepo root is both).
func (m *Manager) History(dir string, only bool) (*History, error) {
	h := &History{Dir: dir, Projects: []ProjectHistory{}, Events: []history.Event{}, Agents: []Agent{}, Work: []history.WorkSession{}}
	if m.ro != nil || dir == "" {
		return h, nil
	}
	if dir != All {
		dir = filepath.Clean(dir)
	}
	for _, e := range m.under(dir) {
		if only && e.Dir != dir {
			continue
		}
		ph := ProjectHistory{Dir: e.Dir, Name: e.Name, Scans: []ScanView{}}
		scans := m.Store.History.Scans(e.Dir)
		ph.KPI = kpiOf(scans, time.Now())
		ph.KPI.AcceptedSoon = m.acceptedSoon(e.Dir)
		for i := 0; i < len(scans) && i < showScans; i++ {
			var prev *history.Scan
			if i+1 < len(scans) {
				prev = &scans[i+1]
			}
			v := ScanView{Scan: scans[i], Diff: history.Compare(prev, &scans[i])}
			v.Items = nil // the diff says what matters; keeps the answer small
			ph.Scans = append(ph.Scans, v)
		}
		ph.Git = m.gitLog(e.Dir)
		h.Projects = append(h.Projects, ph)
	}
	h.KPI = sumKPI(h.Projects)
	if ev := m.Store.History.Events(scope(dir), 200); ev != nil {
		h.Events = ev
	}
	if only { // leave out what agents did in the projects nested inside this one
		var nested []string
		for _, e := range m.under(dir) {
			if e.Dir != dir {
				nested = append(nested, e.Dir)
			}
		}
		keep := []history.Event{}
		for _, e := range h.Events {
			in := false
			for _, n := range nested {
				in = in || store.Within(e.Project, n)
			}
			if !in {
				keep = append(keep, e)
			}
		}
		h.Events = keep
	}
	h.Agents = agents(h.Events)
	for _, w := range m.Store.History.Sessions(scope(dir)) {
		if !only || filepath.Clean(w.Project) == dir {
			h.Work = append(h.Work, w)
		}
	}
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

// All asks History for every project (the overall dashboard).
const All = "*"

func scope(dir string) string {
	if dir == All {
		return ""
	}
	return dir
}

func (m *Manager) under(dir string) []store.Entry {
	var out []store.Entry
	for _, e := range m.Store.Projects() {
		if dir == All || store.Within(e.Dir, dir) {
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

// important: what the KPIs count as needing attention
func sevRank(s string) int {
	return map[string]int{"malware": 5, "critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1}[s]
}

func important(it history.Item) bool {
	return it.Kind == "malware" || it.Kind == "removed" || it.Sev == "critical" || it.Sev == "high" ||
		it.Group == "now_easy" || it.Group == "now_code"
}

// kpiOf walks the scans (newest first) from the oldest one: a finding is open
// from the first scan that shows it until the first scan without it.
func kpiOf(scans []history.Scan, now time.Time) KPI {
	k := KPI{Weeks: []WeekStat{}, Trend: []TrendPoint{}}
	if len(scans) == 0 {
		return k
	}
	at := scans[0].At
	k.LastScan = &at
	week := func(t time.Time) time.Time {
		t = t.UTC().Truncate(24 * time.Hour)
		return t.AddDate(0, 0, -((int(t.Weekday()) + 6) % 7)) // Monday
	}
	this := week(now)
	for i := 7; i >= 0; i-- {
		k.Weeks = append(k.Weeks, WeekStat{Start: this.AddDate(0, 0, -7*i)})
	}
	bump := func(t time.Time, fixed bool) {
		for i := range k.Weeks {
			if !t.Before(k.Weeks[i].Start) && t.Before(k.Weeks[i].Start.AddDate(0, 0, 7)) {
				if fixed {
					k.Weeks[i].Fixed++
				} else {
					k.Weeks[i].New++
				}
			}
		}
		if now.Sub(t) <= 7*24*time.Hour {
			if fixed {
				k.WeekFixed++
			} else {
				k.WeekNew++
			}
		}
	}
	open := map[string]time.Time{}
	var last map[string]history.Item
	var total time.Duration
	for i := len(scans) - 1; i >= 0; i-- {
		s := scans[i]
		cur := map[string]history.Item{}
		for _, it := range s.Items {
			cur[it.Key] = it
		}
		first := i == len(scans)-1
		for key, it := range cur {
			if _, ok := open[key]; !ok {
				open[key] = s.At
				if !first && important(it) {
					bump(s.At, false)
				}
			}
		}
		for key, since := range open {
			if _, ok := cur[key]; ok {
				continue
			}
			if important(last[key]) {
				bump(s.At, true)
				if now.Sub(s.At) <= 90*24*time.Hour {
					total += s.At.Sub(since)
					k.FixedN++
				}
			}
			delete(open, key)
		}
		last = cur
		if now.Sub(s.At) <= 30*24*time.Hour {
			k.Trend = append(k.Trend, TrendPoint{At: s.At, Urgent: s.Summary.NowEasy + s.Summary.NowCode})
		}
	}
	if k.FixedN > 0 {
		k.MTTRHours = total.Hours() / float64(k.FixedN)
	}
	var oldest time.Time
	for key, since := range open {
		it := last[key]
		if !important(it) || it.Group == "accepted" {
			continue
		}
		k.OpenUrgent++
		sev := it.Sev
		if it.Kind == "malware" {
			sev = "malware"
		}
		// same age: the more severe one (map order must not decide what is shown)
		if oldest.IsZero() || since.Before(oldest) || since.Equal(oldest) && (sevRank(sev) > sevRank(k.OldestSev) || sevRank(sev) == sevRank(k.OldestSev) && it.Pkg < k.OldestPkg) {
			oldest, k.OldestPkg, k.OldestSev = since, it.Pkg, sev
		}
	}
	// a Node.js security release or end of life is an open task too (the
	// overview counts it); it is open since the first scan in a row that said so
	if s := scans[0]; s.NodeNeed == "now" {
		since := s.At
		for _, p := range scans[1:] {
			if p.NodeNeed != "now" || p.Node != s.Node {
				break
			}
			since = p.At
		}
		k.OpenUrgent++
		if oldest.IsZero() || since.Before(oldest) || since.Equal(oldest) && sevRank("high") > sevRank(k.OldestSev) {
			oldest, k.OldestPkg, k.OldestSev = since, "Node.js "+s.Node, "high"
		}
	}
	if !oldest.IsZero() {
		k.OldestDays = int(now.Sub(oldest).Hours() / 24)
	}
	return k
}

// sumKPI adds up the projects of a folder.
func sumKPI(ps []ProjectHistory) KPI {
	k := KPI{Weeks: []WeekStat{}, Trend: []TrendPoint{}}
	var hours float64
	for _, p := range ps {
		x := p.KPI
		k.OpenUrgent += x.OpenUrgent
		k.WeekNew += x.WeekNew
		k.WeekFixed += x.WeekFixed
		k.AcceptedSoon += x.AcceptedSoon
		hours += x.MTTRHours * float64(x.FixedN)
		k.FixedN += x.FixedN
		if x.OldestPkg != "" && (k.OldestPkg == "" || x.OldestDays > k.OldestDays || x.OldestDays == k.OldestDays && sevRank(x.OldestSev) > sevRank(k.OldestSev)) {
			k.OldestDays, k.OldestPkg, k.OldestSev, k.OldestDir = x.OldestDays, x.OldestPkg, x.OldestSev, p.Dir
		}
		if x.LastScan != nil && (k.LastScan == nil || x.LastScan.After(*k.LastScan)) {
			k.LastScan = x.LastScan
		}
		if len(k.Weeks) == 0 {
			k.Weeks = append(k.Weeks, x.Weeks...)
		} else {
			for i := range k.Weeks {
				if i < len(x.Weeks) {
					k.Weeks[i].New += x.Weeks[i].New
					k.Weeks[i].Fixed += x.Weeks[i].Fixed
				}
			}
		}
	}
	if k.FixedN > 0 {
		k.MTTRHours = hours / float64(k.FixedN)
	}
	return k
}

// acceptedSoon counts accepted risks of dir that end within 14 days.
func (m *Manager) acceptedSoon(dir string) int {
	n := 0
	for _, a := range m.Store.Acceptances(dir) {
		if a.Dir == dir && time.Until(a.Until) > 0 && time.Until(a.Until) < 14*24*time.Hour {
			n++
		}
	}
	return n
}

// gitDays and gitCommits bound how far back the git history is read.
const (
	gitDays    = 90
	gitCommits = 300
)

type gitCached struct {
	sig string
	log history.GitLog
}

// gitLog reads the project's git history, again only when a commit, a checkout
// or the lockfile changed since the last time.
func (m *Manager) gitLog(dir string) *history.GitLog {
	p := m.Store.Report(dir)
	if p == nil {
		return nil
	}
	sig := history.GitSignature(dir, p.Lockfile)
	m.gitMu.Lock()
	c, ok := m.gitCache[dir]
	m.gitMu.Unlock()
	if ok && c.sig == sig {
		return &c.log
	}
	l := history.ReadGitLog(dir, p.Lockfile, time.Now().AddDate(0, 0, -gitDays), gitCommits)
	m.gitMu.Lock()
	if m.gitCache == nil {
		m.gitCache = map[string]gitCached{}
	}
	m.gitCache[dir] = gitCached{sig, l}
	m.gitMu.Unlock()
	return &l
}
