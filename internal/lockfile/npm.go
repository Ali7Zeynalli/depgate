package lockfile

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type npmEntry struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Link                 bool              `json:"link"`
	Dev                  bool              `json:"dev"`
	Optional             bool              `json:"optional"`
	DevOptional          bool              `json:"devOptional"`
	HasInstallScript     bool              `json:"hasInstallScript"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type npmV1Entry struct {
	Version      string                 `json:"version"`
	Dev          bool                   `json:"dev"`
	Requires     map[string]string      `json:"requires"`
	Dependencies map[string]*npmV1Entry `json:"dependencies"`
}

type npmLock struct {
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]*npmEntry   `json:"packages"`
	Dependencies    map[string]*npmV1Entry `json:"dependencies"`
}

func parseNpm(data []byte, man *Manifest, member string) ([]Package, error) {
	var lf npmLock
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, err
	}
	if len(lf.Packages) > 0 {
		return parseNpmPackages(lf.Packages, man, member)
	}
	if lf.LockfileVersion >= 2 && len(lf.Dependencies) == 0 {
		return nil, nil
	}
	return parseNpmV1(lf.Dependencies, man), nil
}

// npmKeyName returns the install name of a "packages" key
// ("node_modules/a/node_modules/@s/b" -> "@s/b").
func npmKeyName(key string) string {
	i := strings.LastIndex(key, "node_modules/")
	if i < 0 {
		return ""
	}
	return key[i+len("node_modules/"):]
}

// npmParentDir is the next directory to search when resolving from base.
func npmParentDir(base string) (string, bool) {
	if base == "" {
		return "", false
	}
	if i := strings.LastIndex(base, "/node_modules/"); i >= 0 {
		return base[:i], true
	}
	return "", true
}

func parseNpmPackages(pk map[string]*npmEntry, man *Manifest, member string) ([]Package, error) {
	g := newGraph()
	keys := make([]string, 0, len(pk))
	for k := range pk {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// follow a key through "link": true entries to its real location
	follow := func(k string) string {
		for i := 0; i < 8; i++ {
			e := pk[k]
			if e == nil || !e.Link {
				return k
			}
			k = e.Resolved
		}
		return k
	}
	resolve := func(from, dep string) string {
		for base, ok := from, true; ok; base, ok = npmParentDir(base) {
			k := "node_modules/" + dep
			if base != "" {
				k = base + "/node_modules/" + dep
			}
			if _, has := pk[k]; has {
				return follow(k)
			}
		}
		return ""
	}

	for _, k := range keys {
		e := pk[k]
		if e == nil || e.Link {
			continue
		}
		local := k == "" || !strings.Contains(k, "node_modules/")
		name := e.Name
		if name == "" {
			name = npmKeyName(k)
		}
		n := &gnode{id: k, name: name, version: e.Version, local: local, scripts: e.HasInstallScript}
		if strings.HasPrefix(e.Resolved, "file:") || e.Version == "" {
			n.local = true
		}
		if e.Dev {
			n.devHint = 1
		} else if !e.DevOptional {
			n.devHint = 2
		}
		// a workspace member's devDependencies are reached only through its
		// importer roots, never when another member depends on it
		raw := []map[string]string{e.Dependencies, e.OptionalDependencies}
		if !local {
			n.requires = mergeReq(e.Dependencies, e.OptionalDependencies)
		}
		seen := map[string]bool{}
		for _, m := range raw {
			for _, d := range sortedKeys(m) {
				if seen[d] {
					continue
				}
				seen[d] = true
				if c := resolve(k, d); c != "" {
					n.children = append(n.children, c)
				}
			}
		}
		g.add(n)
	}

	importer := func(path string) []rootDep {
		e := pk[path]
		var roots []rootDep
		if e != nil {
			roots = depRoots(e.Dependencies, e.OptionalDependencies, e.DevDependencies)
		} else if path == "" {
			roots = manifestRoots(man)
		}
		for i := range roots {
			raw := roots[i].name
			roots[i].name, roots[i].rng = splitAlias(raw, roots[i].rng)
			roots[i].id = resolve(path, raw) // a workspace sibling is traversed, not emitted
		}
		return roots
	}

	if member != "" {
		if _, ok := pk[member]; !ok {
			return nil, fmt.Errorf("%w: %q", errNoMember, member)
		}
	}
	importers := 0
	for _, k := range keys {
		if pk[k] != nil && !pk[k].Link && !strings.Contains(k, "node_modules/") {
			importers++
		}
	}
	return g.finish(importer(member), member != "" || importers > 1), nil
}

func parseNpmV1(deps map[string]*npmV1Entry, man *Manifest) []Package {
	g := newGraph()
	// index: path ("a", "a/b") -> entry; path segments are install names
	type item struct {
		path string
		e    *npmV1Entry
	}
	var all []item
	var walk func(prefix string, m map[string]*npmV1Entry)
	walk = func(prefix string, m map[string]*npmV1Entry) {
		for _, name := range sortedKeysE(m) {
			p := name
			if prefix != "" {
				p = prefix + "\x00" + name
			}
			all = append(all, item{p, m[name]})
			walk(p, m[name].Dependencies)
		}
	}
	walk("", deps)
	idx := map[string]*npmV1Entry{}
	for _, it := range all {
		idx[it.path] = it.e
	}
	resolve := func(from, dep string) string {
		base := from
		for {
			k := dep
			if base != "" {
				k = base + "\x00" + dep
			}
			if _, ok := idx[k]; ok {
				return k
			}
			if base == "" {
				return ""
			}
			if i := strings.LastIndex(base, "\x00"); i >= 0 {
				base = base[:i]
			} else {
				base = ""
			}
		}
	}
	for _, it := range all {
		segs := strings.Split(it.path, "\x00")
		name := segs[len(segs)-1]
		ver := it.e.Version
		if strings.HasPrefix(ver, "npm:") {
			name, ver = splitAlias(name, ver)
		}
		n := &gnode{id: it.path, name: name, version: ver}
		if strings.HasPrefix(ver, "file:") || strings.Contains(ver, "://") || strings.HasPrefix(ver, "git") {
			n.local = true
		}
		if it.e.Dev {
			n.devHint = 1
		} else {
			n.devHint = 2
		}
		if len(it.e.Requires) > 0 {
			n.requires = mergeReq(it.e.Requires)
			for _, d := range sortedKeys(it.e.Requires) {
				if c := resolve(it.path, d); c != "" {
					n.children = append(n.children, c)
				}
			}
		}
		g.add(n)
	}
	roots := manifestRoots(man)
	for i := range roots {
		raw := roots[i].name
		roots[i].name, roots[i].rng = splitAlias(raw, roots[i].rng)
		roots[i].id = resolve("", raw)
	}
	return g.finish(roots, false)
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysE(m map[string]*npmV1Entry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
