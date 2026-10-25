package lockfile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// parseNoLock fills res for a project without a lockfile: real versions from
// node_modules when it exists, otherwise approximate versions from ranges.
func parseNoLock(dir string, man *Manifest, res *Result) error {
	nm := filepath.Join(dir, "node_modules")
	if st, err := os.Stat(nm); err == nil && st.IsDir() {
		res.File = "node_modules"
		res.Packages = parseNodeModules(nm, man)
		return nil
	}
	res.Approximate = true
	res.Packages = []Package{}
	for _, r := range manifestRoots(man) {
		name, rng := splitAlias(r.name, r.rng)
		if !strings.HasPrefix(r.rng, "npm:") && strings.Contains(rng, ":") {
			continue // workspace:, file:, link:, git+…, github:
		}
		if strings.Contains(rng, "/") {
			continue // user/repo shorthand, paths
		}
		v, ok := MinVersion(rng)
		if !ok {
			continue
		}
		res.Packages = append(res.Packages, Package{Name: name, Version: v, Direct: true, Dev: r.dev, Range: rng})
	}
	return nil
}

type nmManifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Scripts              map[string]string `json:"scripts"`
}

// parseNodeModules reads node_modules/<name>/package.json (including scoped
// packages) and one level of nested node_modules, then links them like npm's
// resolution algorithm does.
func parseNodeModules(nm string, man *Manifest) []Package {
	g := newGraph()
	var keys []string
	rawDeps := map[string][]string{} // install names, for resolution
	read := func(key, dir string) {
		b, err := os.ReadFile(filepath.Join(dir, "package.json"))
		if err != nil {
			return
		}
		var m nmManifest
		if json.Unmarshal(b, &m) != nil || m.Version == "" {
			return
		}
		name := m.Name
		if name == "" {
			name = npmKeyName(key)
		}
		n := &gnode{id: key, name: name, version: m.Version, requires: mergeReq(m.Dependencies, m.OptionalDependencies)}
		for _, s := range []string{"preinstall", "install", "postinstall"} {
			if strings.TrimSpace(m.Scripts[s]) != "" {
				n.scripts = true
			}
		}
		g.add(n)
		keys = append(keys, key)
		rawDeps[key] = append(sortedKeys(m.Dependencies), sortedKeys(m.OptionalDependencies)...)
	}
	var scan func(prefix, dir string, depth int)
	scan = func(prefix, dir string, depth int) {
		for _, pkgDir := range listPackageDirs(dir) {
			rel, _ := filepath.Rel(dir, pkgDir)
			key := prefix + "node_modules/" + filepath.ToSlash(rel)
			read(key, pkgDir)
			if depth > 0 {
				sub := filepath.Join(pkgDir, "node_modules")
				if st, err := os.Stat(sub); err == nil && st.IsDir() {
					scan(key+"/", sub, depth-1)
				}
			}
		}
	}
	scan("", nm, 1)

	resolve := func(from, dep string) string {
		for base, ok := from, true; ok; base, ok = npmParentDir(base) {
			k := "node_modules/" + dep
			if base != "" {
				k = base + "/node_modules/" + dep
			}
			if g.nodes[k] != nil {
				return k
			}
		}
		return ""
	}
	for _, k := range keys {
		n := g.nodes[k]
		for _, d := range rawDeps[k] {
			if c := resolve(k, d); c != "" {
				n.children = append(n.children, c)
			}
		}
	}
	roots := manifestRoots(man)
	for i := range roots {
		raw := roots[i].name
		roots[i].name, roots[i].rng = splitAlias(raw, roots[i].rng)
		roots[i].id = resolve("", raw)
	}
	return g.finish(roots, false)
}

// listPackageDirs returns package directories directly under a node_modules
// directory, descending into @scope folders and skipping .bin/.cache etc.
func listPackageDirs(nm string) []string {
	ents, err := os.ReadDir(nm)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		p := filepath.Join(nm, name)
		if !isDirFollow(p) {
			continue
		}
		if strings.HasPrefix(name, "@") {
			sub, err := os.ReadDir(p)
			if err != nil {
				continue
			}
			for _, s := range sub {
				if sp := filepath.Join(p, s.Name()); !strings.HasPrefix(s.Name(), ".") && isDirFollow(sp) {
					out = append(out, sp)
				}
			}
			continue
		}
		out = append(out, p)
	}
	return out
}

func isDirFollow(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}
