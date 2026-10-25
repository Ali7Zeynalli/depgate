// Package decide turns a parsed project plus public data into DepGate's
// decision cards: ① do I need to update, ② does it affect my code, the
// safest target version, the fix strategy and a priority score.
package decide

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/lockfile"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/semver"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
)

// Data bundles the shared data sources (one per run, shared by all projects).
type Data struct {
	// GitHubLeft caps release-note lookups per scan (unauthenticated GitHub allows 60 an hour)
	GitHubLeft int32
	F          sources.Fetcher
	OSV        *sources.OSV
	Node       *sources.NodeData
	KEV        map[string]bool

	mu    sync.Mutex
	pkgs  map[string]*pkgEntry
	mans  map[string]*manEntry
	epss  map[string]float64
	epssQ map[string]bool
}

type pkgEntry struct {
	once sync.Once
	info *sources.PkgInfo
	err  error
}

type manEntry struct {
	once sync.Once
	m    *sources.Manifest
	err  error
}

func NewData(f sources.Fetcher) *Data {
	return &Data{GitHubLeft: 25, F: f, OSV: sources.NewOSV(f), pkgs: map[string]*pkgEntry{}, mans: map[string]*manEntry{}, epss: map[string]float64{}, epssQ: map[string]bool{}}
}

// Pkg returns the cached version list of a package.
func (d *Data) Pkg(ctx context.Context, name string) (*sources.PkgInfo, error) {
	d.mu.Lock()
	e, ok := d.pkgs[name]
	if !ok {
		e = &pkgEntry{}
		d.pkgs[name] = e
	}
	d.mu.Unlock()
	e.once.Do(func() { e.info, e.err = sources.Package(ctx, d.F, name) })
	return e.info, e.err
}

// Manifest returns the cached registry document of name@version.
func (d *Data) Manifest(ctx context.Context, name, version string) (*sources.Manifest, error) {
	k := name + "@" + version
	d.mu.Lock()
	e, ok := d.mans[k]
	if !ok {
		e = &manEntry{}
		d.mans[k] = e
	}
	d.mu.Unlock()
	e.once.Do(func() { e.m, e.err = sources.Version(ctx, d.F, name, version) })
	return e.m, e.err
}

// Options tune decisions.
type Options struct {
	CooldownDays int
	Now          time.Time
}

// Input is one parsed project.
type Input struct {
	Lock        *lockfile.Result
	Manifest    *lockfile.Manifest
	NodeVersion string // resolved Node x.y.z of the project ("" unknown) — for engines checks
	Mgr         string // npm | pnpm | yarn (berry) | yarn1 | bun — for printing commands
}

// ManagerOf maps a lockfile result to the command flavour.
func ManagerOf(r *lockfile.Result) string {
	if r.Kind == "yarn" {
		return "yarn1"
	}
	if r.Manager == "" {
		return "npm"
	}
	return r.Manager
}

type instance struct {
	pkg     lockfile.Package
	ver     semver.Version
	vulns   []*sources.Vuln
	removed bool // npm no longer serves this version (unpublished or taken down)
}

// HolderID marks a package npm replaced with a 0.0.1-security placeholder.
const HolderID = "NPM-SECURITY-PLACEHOLDER"

// Packages produces findings for all packages of one project.
func Packages(ctx context.Context, d *Data, in Input, opt Options) ([]report.Finding, []string) {
	var errs []string
	addErr := func(e error) {
		if e != nil {
			errs = append(errs, e.Error())
		}
	}
	// 1. unique instances with valid semver versions
	byKey := map[string]*instance{}
	var insts []*instance
	for _, p := range in.Lock.Packages {
		v, err := semver.Parse(p.Version)
		if err != nil {
			continue
		}
		k := p.Name + "@" + v.String()
		if ex, ok := byKey[k]; ok {
			ex.pkg.Direct = ex.pkg.Direct || p.Direct
			ex.pkg.Dev = ex.pkg.Dev && p.Dev
			if ex.pkg.Range == "" {
				ex.pkg.Range = p.Range
			}
			ex.pkg.Parents = mergeUniq(ex.pkg.Parents, p.Parents)
			continue
		}
		in := &instance{pkg: p, ver: v}
		byKey[k] = in
		insts = append(insts, in)
	}
	sort.Slice(insts, func(i, j int) bool {
		if insts[i].pkg.Name != insts[j].pkg.Name {
			return insts[i].pkg.Name < insts[j].pkg.Name
		}
		return semver.Less(insts[i].ver, insts[j].ver)
	})

	// 2. OSV
	qs := make([]sources.Query, len(insts))
	for i, it := range insts {
		qs[i] = sources.Query{Name: it.pkg.Name, Version: it.ver.String()}
	}
	ids, err := d.OSV.Batch(ctx, qs)
	addErr(err)
	var need []string
	seen := map[string]bool{}
	for _, l := range ids {
		for _, id := range l {
			if !seen[id] {
				seen[id] = true
				need = append(need, id)
			}
		}
	}
	vulns := map[string]*sources.Vuln{}
	var vmu sync.Mutex
	parallel(need, 8, func(id string) {
		v, err := d.OSV.Get(ctx, id)
		vmu.Lock()
		defer vmu.Unlock()
		if err != nil {
			errs = append(errs, err.Error())
			return
		}
		if v.Withdrawn == "" {
			vulns[id] = v
		}
	})
	for i, l := range ids {
		if i >= len(insts) {
			break
		}
		for _, id := range l {
			if v := vulns[id]; v != nil {
				insts[i].vulns = append(insts[i].vulns, v)
			}
		}
	}

	// 2b. npm registry advisories — the source of `npm audit`. It reads the GitHub
	// Advisory Database directly (malware included), so it often knows about a
	// package before OSV has imported the record.
	reqs := map[string][]string{}
	for _, it := range insts {
		reqs[it.pkg.Name] = append(reqs[it.pkg.Name], it.ver.String())
	}
	if adv, err := sources.NpmBulk(ctx, d.F, reqs); err != nil {
		addErr(err)
	} else {
		for _, it := range insts {
			for _, a := range adv[it.pkg.Name] {
				v := sources.FromNpm(it.pkg.Name, a)
				if Affects(v, it.pkg.Name, it.ver) && !knownVuln(it.vulns, v) {
					it.vulns = append(it.vulns, v)
				}
			}
		}
	}

	// 2c. versions npm no longer serves: a removed malicious version leaves the
	// lockfile pointing at nothing, often before any advisory exists. Only public
	// packages count (workspace and private packages are not on deps.dev).
	parallel(insts, 16, func(it *instance) {
		for _, v := range it.vulns {
			if v.IsMalware() {
				return
			}
		}
		if _, err := d.Manifest(ctx, it.pkg.Name, it.ver.String()); !errors.Is(err, sources.ErrNotFound) {
			return
		}
		info, err := d.Pkg(ctx, it.pkg.Name)
		if err != nil || info == nil || len(info.Versions) == 0 {
			return
		}
		vmu.Lock()
		defer vmu.Unlock()
		if isHolder(info) {
			h := &sources.Vuln{ID: HolderID, Summary: "npm replaced " + it.pkg.Name + " with a security placeholder (0.0.1-security)", NpmRange: ">=0.0.0-0", Malicious: true, From: "npm", Link: "https://www.npmjs.com/package/" + it.pkg.Name}
			h.DatabaseSpecific.Severity = "CRITICAL"
			var af sources.Affected
			af.Package.Ecosystem, af.Package.Name = "npm", it.pkg.Name
			h.Affected = []sources.Affected{af}
			it.vulns = append(it.vulns, h)
			return
		}
		it.removed = true
	})

	// 3. EPSS for all CVEs found
	var cves []string
	for _, v := range vulns {
		cves = append(cves, v.CVEs()...)
	}
	d.loadEPSS(ctx, cves, addErr)

	graph := buildGraph(in.Lock.Packages)
	var out []report.Finding
	var omu sync.Mutex
	var vulnInsts []*instance
	directInsts := map[string]*instance{}
	for _, it := range insts {
		if len(it.vulns) > 0 {
			vulnInsts = append(vulnInsts, it)
		}
		if it.pkg.Direct {
			if ex, ok := directInsts[it.pkg.Name]; !ok || semver.Less(ex.ver, it.ver) {
				directInsts[it.pkg.Name] = it
			}
		}
	}
	for _, it := range insts {
		if it.removed && len(it.vulns) == 0 {
			f, err := removedFinding(ctx, d, it, in, graph, opt)
			addErr(err)
			out = append(out, f)
		}
	}
	parallel(vulnInsts, 8, func(it *instance) {
		f, ferrs := vulnFinding(ctx, d, it, in, graph, opt)
		omu.Lock()
		out = append(out, f)
		errs = append(errs, ferrs...)
		omu.Unlock()
	})

	// 4. updates / deprecations for direct packages without a vulnerability card
	hasCard := map[string]bool{}
	for _, f := range out {
		hasCard[f.Pkg+"@"+f.Current] = true
	}
	var directs []*instance
	for _, it := range directInsts {
		if !hasCard[it.pkg.Name+"@"+it.ver.String()] {
			directs = append(directs, it)
		}
	}
	parallel(directs, 8, func(it *instance) {
		f, err := updateFinding(ctx, d, it, in, opt)
		omu.Lock()
		defer omu.Unlock()
		if err != nil {
			errs = append(errs, err.Error())
			return
		}
		out = append(out, f)
	})

	sort.SliceStable(out, func(i, j int) bool {
		gi, gj := groupRank(out[i].Group), groupRank(out[j].Group)
		if gi != gj {
			return gi < gj
		}
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].Pkg < out[j].Pkg
	})
	return out, dedupe(errs)
}

// knownVuln reports whether v (from npm) is already covered by an OSV record.
func knownVuln(have []*sources.Vuln, v *sources.Vuln) bool {
	for _, x := range have {
		if x.ID == v.ID || (v.IsMalware() && x.IsMalware()) {
			return true
		}
		for _, a := range x.Aliases {
			if a == v.ID {
				return true
			}
		}
	}
	return false
}

func groupRank(g report.Group) int {
	switch g {
	case report.GroupNowEasy:
		return 0
	case report.GroupNowCode:
		return 1
	case report.GroupPlan:
		return 2
	}
	return 3
}

func (d *Data) loadEPSS(ctx context.Context, cves []string, addErr func(error)) {
	d.mu.Lock()
	var q []string
	for _, c := range cves {
		if !d.epssQ[c] {
			d.epssQ[c] = true
			q = append(q, c)
		}
	}
	d.mu.Unlock()
	if len(q) == 0 {
		return
	}
	sort.Strings(q)
	m, err := sources.EPSS(ctx, d.F, q)
	if err != nil {
		addErr(err)
	}
	d.mu.Lock()
	for k, v := range m {
		d.epss[k] = v
	}
	d.mu.Unlock()
}

func (d *Data) epssOf(v *sources.Vuln) float64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	best := 0.0
	for _, c := range v.CVEs() {
		if e := d.epss[c]; e > best {
			best = e
		}
	}
	return best
}

func (d *Data) kevOf(v *sources.Vuln) bool {
	for _, c := range v.CVEs() {
		if d.KEV[c] {
			return true
		}
	}
	return false
}

// ---------- helpers ----------

func parallel[T any](items []T, n int, fn func(T)) {
	if len(items) == 0 {
		return
	}
	ch := make(chan T)
	var wg sync.WaitGroup
	for i := 0; i < min(n, len(items)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range ch {
				fn(it)
			}
		}()
	}
	for _, it := range items {
		ch <- it
	}
	close(ch)
	wg.Wait()
}

func mergeUniq(a, b []string) []string {
	m := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if !m[s] {
			m[s] = true
			out = append(out, s)
		}
	}
	return out
}

func dedupe(s []string) []string {
	m := map[string]bool{}
	var out []string
	for _, x := range s {
		if !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	return out
}

// graph maps a package name to its parent names and records direct names.
type graph struct {
	parents map[string][]string
	direct  map[string]bool
	reqs    map[string]map[string]string // parent name -> its requires (merged over versions)
}

func buildGraph(pkgs []lockfile.Package) *graph {
	g := &graph{parents: map[string][]string{}, direct: map[string]bool{}, reqs: map[string]map[string]string{}}
	for _, p := range pkgs {
		if p.Direct {
			g.direct[p.Name] = true
		}
		g.parents[p.Name] = mergeUniq(g.parents[p.Name], p.Parents)
		if len(p.Requires) > 0 {
			if g.reqs[p.Name] == nil {
				g.reqs[p.Name] = map[string]string{}
			}
			for k, v := range p.Requires {
				g.reqs[p.Name][k] = v
			}
		}
	}
	return g
}

// chain returns the shortest path direct -> ... -> name (BFS upward).
// first are the parents of this particular instance (a name can be installed
// several times with different parents); they are used for the first step.
func (g *graph) chain(name string, first []string) []string {
	if g.direct[name] && len(first) == 0 {
		return []string{name}
	}
	prev := map[string]string{name: ""}
	q := []string{name}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		ps := g.parents[cur]
		if cur == name && len(first) > 0 {
			ps = first
		}
		for _, p := range ps {
			if _, ok := prev[p]; ok {
				continue
			}
			prev[p] = cur
			if g.direct[p] {
				path := []string{p}
				for c := cur; c != ""; c = prev[c] {
					path = append(path, c)
				}
				return path
			}
			q = append(q, p)
		}
	}
	return []string{name}
}

func pct(f float64) string { return fmt.Sprintf("%.0f%%", f*100) }

func joinNonEmpty(sep string, parts ...string) string {
	var out []string
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}
