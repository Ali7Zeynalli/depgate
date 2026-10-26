package lockfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// MinVersion resolves a declared range to its lowest matching version for approximate mode.
// The CLI sets it to semver-based logic; default strips ^ ~ >= = v and returns the remainder if it looks like x.y.z.
var MinVersion = func(rng string) (string, bool) {
	s := strings.TrimSpace(rng)
	s = strings.TrimLeft(s, "^~>=v ")
	if xyz.MatchString(s) {
		return s, true
	}
	return "", false
}

var xyz = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// lockNames in detection preference order. bun.lockb is last: it is only
// reported (Parse fails with a hint) when no text lockfile exists.
var lockNames = []struct{ file, kind string }{
	{"pnpm-lock.yaml", "pnpm"},
	{"package-lock.json", "npm"},
	{"npm-shrinkwrap.json", "npm"},
	{"yarn.lock", "yarn"},
	{"bun.lock", "bun"},
	{"bun.lockb", "bun"},
}

// ReadManifest reads dir/package.json.
func ReadManifest(dir string) (*Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, "package.json"), err)
	}
	return &m, nil
}

// Detect finds the lockfile for the project in dir. It looks in dir first and
// then in ancestor directories that are workspace roots (package.json with
// "workspaces", or pnpm-workspace.yaml), stopping at a git repository root.
// file is relative to dir; ("none", "") when nothing is found.
func Detect(dir string) (kind, file string) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	kind, path := detectAbs(abs)
	if path == "" {
		return "none", ""
	}
	rel, err := filepath.Rel(abs, path)
	if err != nil {
		rel = path
	}
	return kind, rel
}

func detectAbs(dir string) (kind, path string) {
	for cur, first := dir, true; ; first = false {
		if first || isWorkspaceRoot(cur) {
			if k, p := detectHere(cur); p != "" {
				return k, p
			}
		}
		if exists(filepath.Join(cur, ".git")) {
			return "none", ""
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "none", ""
		}
		cur = parent
	}
}

func detectHere(dir string) (kind, path string) {
	for _, l := range lockNames {
		p := filepath.Join(dir, l.file)
		if !isFile(p) {
			continue
		}
		k := l.kind
		if k == "yarn" && isYarnBerry(p) {
			k = "yarn-berry"
		}
		return k, p
	}
	return "", ""
}

func isWorkspaceRoot(dir string) bool {
	if isFile(filepath.Join(dir, "pnpm-workspace.yaml")) {
		return true
	}
	m, err := ReadManifest(dir)
	return err == nil && m.Workspaces != nil
}

func isYarnBerry(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	return strings.Contains(string(buf[:n]), "\n__metadata:") || strings.HasPrefix(string(buf[:n]), "__metadata:")
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// Parse detects and parses the lockfile of the project in dir.
func Parse(dir string) (*Result, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	man, err := ReadManifest(abs)
	if err != nil {
		return nil, err
	}
	kind, path := detectAbs(abs)
	res := &Result{Kind: kind}
	if path == "" {
		res.Kind = "none"
		if err := parseNoLock(abs, man, res); err != nil {
			return nil, err
		}
		res.Manager = managerOf(res.Kind, man)
		return res, nil
	}
	res.File, _ = filepath.Rel(abs, path)
	res.Manager = managerOf(kind, man)
	lockDir := filepath.Dir(path)
	member, _ := filepath.Rel(lockDir, abs)
	member = filepath.ToSlash(member)
	if member == "." {
		member = ""
	}
	if filepath.Base(path) == "bun.lockb" {
		return nil, fmt.Errorf("%s: binary bun.lockb cannot be read; run `bun install --save-text-lockfile` to create bun.lock", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pkgs, err := ParseData(kind, data, man, member)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	res.Packages = pkgs
	if res.Packages == nil {
		res.Packages = []Package{}
	}
	return res, nil
}

// ParseData parses lockfile content of the given kind (as Detect names it) for
// the workspace member at member ("" = the lockfile's own folder). Used for
// lockfiles read from git history.
func ParseData(kind string, data []byte, man *Manifest, member string) ([]Package, error) {
	if man == nil {
		man = &Manifest{}
	}
	switch kind {
	case "npm":
		return parseNpm(data, man, member)
	case "pnpm":
		return parsePnpm(data, member)
	case "yarn":
		return parseYarnV1(data, man, member)
	case "yarn-berry":
		return parseYarnBerry(data, man, member)
	case "bun":
		return parseBun(data, member)
	}
	return nil, fmt.Errorf("unknown lockfile kind %q", kind)
}

// KindOf returns the lockfile kind of a lockfile path by its name ("" unknown);
// for yarn.lock, berry is told apart by its content.
func KindOf(name string, data []byte) string {
	switch filepath.Base(name) {
	case "package-lock.json", "npm-shrinkwrap.json":
		return "npm"
	case "pnpm-lock.yaml":
		return "pnpm"
	case "bun.lock":
		return "bun"
	case "yarn.lock":
		if strings.Contains(string(data[:min(len(data), 4096)]), "__metadata:") {
			return "yarn-berry"
		}
		return "yarn"
	}
	return ""
}

func managerOf(kind string, man *Manifest) string {
	if man != nil && man.PackageManager != "" {
		name := man.PackageManager
		if i := strings.Index(name[1:], "@"); i >= 0 {
			name = name[:i+1]
		}
		switch name {
		case "npm", "pnpm", "yarn", "bun":
			return name
		}
	}
	switch kind {
	case "pnpm", "bun", "yarn":
		return kind
	case "yarn-berry":
		return "yarn"
	}
	return "npm"
}

// ---------------------------------------------------------------------------
// shared dependency graph

type gnode struct {
	id       string
	name     string // real package name
	version  string
	requires map[string]string // real name -> range
	children []string          // resolved node ids
	scripts  bool
	devHint  int8 // 0 unknown, 1 dev, 2 prod (from lockfile flags)
	local    bool // workspace member / link: traversed but never emitted
}

type rootDep struct {
	name string // real name
	rng  string
	id   string // resolved node id
	dev  bool
}

type graph struct {
	nodes map[string]*gnode
	order []string
}

func newGraph() *graph { return &graph{nodes: map[string]*gnode{}} }

func (g *graph) add(n *gnode) *gnode {
	if ex, ok := g.nodes[n.id]; ok {
		return ex
	}
	g.nodes[n.id] = n
	g.order = append(g.order, n.id)
	return n
}

// finish turns the graph into packages. roots are the dependencies of the
// project being parsed (they get Direct/Range and drive prod/dev
// reachability). With restrict (lockfiles covering several importers), only
// nodes reachable from roots are emitted, and Parents only name emitted
// packages, so each workspace member reports just its own tree.
func (g *graph) finish(roots []rootDep, restrict bool) []Package {
	reach := func(dev bool) map[string]bool {
		seen := map[string]bool{}
		var q []string
		for _, r := range roots {
			if r.dev == dev && r.id != "" && g.nodes[r.id] != nil && !seen[r.id] {
				seen[r.id] = true
				q = append(q, r.id)
			}
		}
		for len(q) > 0 {
			id := q[0]
			q = q[1:]
			for _, c := range g.nodes[id].children {
				if !seen[c] && g.nodes[c] != nil {
					seen[c] = true
					q = append(q, c)
				}
			}
		}
		return seen
	}
	prod, dev := reach(false), reach(true)
	emit := func(id string) bool {
		n := g.nodes[id]
		if n == nil || n.local || n.name == "" || n.version == "" {
			return false
		}
		return !restrict || prod[id] || dev[id]
	}
	parents := map[string][]string{}
	for _, id := range g.order {
		if !emit(id) {
			continue
		}
		for _, c := range g.nodes[id].children {
			parents[c] = append(parents[c], g.nodes[id].name)
		}
	}
	directBy := map[string]rootDep{}
	for _, r := range roots {
		if r.id == "" {
			continue
		}
		if ex, ok := directBy[r.id]; ok && !ex.dev {
			continue
		}
		directBy[r.id] = r
	}

	byKey := map[string]*Package{}
	var keys []string
	for _, id := range g.order {
		if !emit(id) {
			continue
		}
		n := g.nodes[id]
		p := Package{Name: n.name, Version: n.version, Scripts: n.scripts}
		if r, ok := directBy[id]; ok {
			p.Direct, p.Range = true, r.rng
		}
		switch {
		case prod[id]:
		case dev[id]:
			p.Dev = true
		default:
			p.Dev = n.devHint == 1
		}
		if len(n.requires) > 0 {
			p.Requires = map[string]string{}
			for k, v := range n.requires {
				p.Requires[k] = v
			}
		}
		p.Parents = uniqSorted(parents[id])
		k := p.Name + "@" + p.Version
		ex, ok := byKey[k]
		if !ok {
			cp := p
			byKey[k] = &cp
			keys = append(keys, k)
			continue
		}
		ex.Direct = ex.Direct || p.Direct
		if ex.Range == "" {
			ex.Range = p.Range
		}
		ex.Dev = ex.Dev && p.Dev
		ex.Scripts = ex.Scripts || p.Scripts
		ex.Parents = uniqSorted(append(ex.Parents, p.Parents...))
		for k, v := range p.Requires {
			if ex.Requires == nil {
				ex.Requires = map[string]string{}
			}
			if _, has := ex.Requires[k]; !has {
				ex.Requires[k] = v
			}
		}
	}
	out := make([]Package, 0, len(keys))
	for _, k := range keys {
		out = append(out, *byKey[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}

func uniqSorted(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	m := map[string]bool{}
	var out []string
	for _, x := range s {
		if x != "" && !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// splitAlias resolves an npm alias spec: ("x", "npm:real@^1") -> ("real", "^1").
// Anything else is returned unchanged.
func splitAlias(name, rng string) (string, string) {
	if !strings.HasPrefix(rng, "npm:") {
		return name, rng
	}
	rest := rng[4:]
	if i := strings.LastIndex(rest, "@"); i > 0 {
		return rest[:i], rest[i+1:]
	}
	return rest, ""
}

// manifestRoots lists a manifest's deps as roots (id left empty). Optional
// deps count as prod. A name in both dependencies and devDependencies is prod.
func manifestRoots(man *Manifest) []rootDep {
	if man == nil {
		return nil
	}
	return depRoots(man.Dependencies, man.OptionalDependencies, man.DevDependencies)
}

func depRoots(deps, opt, dev map[string]string) []rootDep {
	var out []rootDep
	seen := map[string]bool{}
	add := func(m map[string]string, isDev bool) {
		names := make([]string, 0, len(m))
		for k := range m {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, rootDep{name: k, rng: m[k], dev: isDev})
		}
	}
	add(deps, false)
	add(opt, false)
	add(dev, true)
	return out
}

// mergeReq merges dependency maps into name->range, resolving aliases.
func mergeReq(ms ...map[string]string) map[string]string {
	var out map[string]string
	for _, m := range ms {
		for k, v := range m {
			if out == nil {
				out = map[string]string{}
			}
			rn, rr := splitAlias(k, v)
			out[rn] = rr
		}
	}
	return out
}

var errNoMember = errors.New("workspace member not found in lockfile")
