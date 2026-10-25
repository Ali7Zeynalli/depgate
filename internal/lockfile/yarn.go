package lockfile

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// yarnEntry is one resolved package in yarn.lock (v1 or berry).
type yarnEntry struct {
	descriptors []string // "name@range" keys pointing at this entry
	name        string   // real package name
	version     string
	deps        map[string]string // install name -> range/descriptor range
	optDeps     map[string]string
	workspace   bool
}

// ---------------------------------------------------------------- yarn v1

func parseYarnV1(data []byte, man *Manifest, member string) ([]Package, error) {
	var entries []*yarnEntry
	var cur *yarnEntry
	var block map[string]string
	for num, raw := range strings.Split(string(data), "\n") {
		raw = strings.TrimRight(raw, "\r")
		t := strings.TrimLeft(raw, " ")
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		indent := len(raw) - len(t)
		switch {
		case indent == 0:
			if !strings.HasSuffix(t, ":") {
				return nil, fmt.Errorf("line %d: expected entry header, got %q", num+1, t)
			}
			cur = &yarnEntry{}
			block = nil
			for _, d := range strings.Split(strings.TrimSuffix(t, ":"), ",") {
				d = yarnUnquote(strings.TrimSpace(d))
				if d != "" {
					cur.descriptors = append(cur.descriptors, d)
				}
			}
			entries = append(entries, cur)
		case cur == nil:
			return nil, fmt.Errorf("line %d: indented line before any entry", num+1)
		case indent <= 2:
			block = nil
			if strings.HasSuffix(t, ":") {
				switch strings.TrimSuffix(t, ":") {
				case "dependencies":
					cur.deps = map[string]string{}
					block = cur.deps
				case "optionalDependencies":
					cur.optDeps = map[string]string{}
					block = cur.optDeps
				default:
					block = map[string]string{} // ignored block
				}
				continue
			}
			k, v := yarnKV(t)
			if k == "version" {
				cur.version = v
			}
		default:
			if block != nil {
				k, v := yarnKV(t)
				block[k] = v
			}
		}
	}
	for _, e := range entries {
		if len(e.descriptors) > 0 {
			e.name, _ = yarnSplitDescriptor(e.descriptors[0])
			if rn, rr := yarnSplitDescriptor(e.descriptors[0]); strings.HasPrefix(rr, "npm:") {
				e.name, _ = splitAlias(rn, rr)
			}
		}
		for _, d := range e.descriptors {
			if _, r := yarnSplitDescriptor(d); strings.HasPrefix(r, "file:") || strings.HasPrefix(r, "link:") {
				e.workspace = true
			}
		}
	}
	lookup := func(name, rng string) string { return name + "@" + rng }
	return yarnFinish(entries, man, member, lookup)
}

func yarnUnquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if u, err := strconv.Unquote(s); err == nil {
			return u
		}
		return s[1 : len(s)-1]
	}
	return s
}

// yarnKV splits `key "value"` / `"@s/key" value`.
func yarnKV(t string) (string, string) {
	var k, rest string
	if strings.HasPrefix(t, "\"") {
		if i := strings.Index(t[1:], "\""); i >= 0 {
			k, rest = t[1:i+1], t[i+2:]
		}
	} else if i := strings.IndexByte(t, ' '); i >= 0 {
		k, rest = t[:i], t[i+1:]
	} else {
		k = t
	}
	return k, yarnUnquote(strings.TrimSpace(rest))
}

// yarnSplitDescriptor splits "name@range" ("@scope/name@range") at the first
// "@" after the scope.
func yarnSplitDescriptor(d string) (name, rng string) {
	i := strings.IndexByte(d[min(1, len(d)):], '@')
	if i < 0 {
		return d, ""
	}
	i++
	return d[:i], d[i+1:]
}

// ---------------------------------------------------------------- berry

func parseYarnBerry(data []byte, man *Manifest, member string) ([]Package, error) {
	docs, err := parseYAMLDocs(string(data))
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return nil, errors.New("empty yarn.lock")
	}
	doc := yMap(docs[len(docs)-1])
	var entries []*yarnEntry
	for _, key := range sortedAnyKeys(doc) {
		if key == "__metadata" {
			continue
		}
		m := yMap(doc[key])
		e := &yarnEntry{version: yStr(m["version"])}
		for _, d := range strings.Split(key, ",") {
			if d = strings.TrimSpace(d); d != "" {
				e.descriptors = append(e.descriptors, d)
			}
		}
		res := yStr(m["resolution"])
		if res == "" && len(e.descriptors) > 0 {
			res = e.descriptors[0]
		}
		e.name, _ = yarnSplitDescriptor(res)
		_, rr := yarnSplitDescriptor(res)
		e.workspace = strings.HasPrefix(rr, "workspace:") || strings.HasPrefix(rr, "link:") ||
			strings.HasPrefix(rr, "portal:") || strings.HasPrefix(rr, "file:")
		e.deps = yStrMap(m["dependencies"])
		e.optDeps = yStrMap(m["optionalDependencies"])
		entries = append(entries, e)
	}
	lookup := func(name, rng string) string {
		if !berryHasProtocol(rng) {
			rng = "npm:" + rng
		}
		return name + "@" + rng
	}
	return yarnFinish(entries, man, member, lookup)
}

func berryHasProtocol(r string) bool {
	i := strings.IndexByte(r, ':')
	if i <= 0 {
		return false
	}
	for _, c := range r[:i] {
		if !(c >= 'a' && c <= 'z' || c == '+') {
			return false
		}
	}
	return true
}

// berryRange shows a berry range the way package.json declares it.
func berryRange(r string) string {
	if strings.HasPrefix(r, "npm:") {
		rest := r[4:]
		// keep alias specs "npm:real@^1"
		if strings.LastIndexByte(rest, '@') > 0 {
			return r
		}
		return rest
	}
	return r
}

// yarnFinish builds the graph for both yarn flavours. lookup turns an install
// name and range into a descriptor key.
func yarnFinish(entries []*yarnEntry, man *Manifest, member string, lookup func(name, rng string) string) ([]Package, error) {
	g := newGraph()
	byDesc := map[string]string{}
	for i, e := range entries {
		id := strconv.Itoa(i)
		for _, d := range e.descriptors {
			byDesc[d] = id
		}
	}
	for i, e := range entries {
		n := &gnode{id: strconv.Itoa(i), name: e.name, version: e.version, local: e.workspace}
		for _, m := range []map[string]string{e.deps, e.optDeps} {
			for _, dn := range sortedKeys(m) {
				rng := m[dn]
				if !e.workspace {
					if n.requires == nil {
						n.requires = map[string]string{}
					}
					rn, rr := splitAlias(dn, berryRange(rng))
					n.requires[rn] = rr
				}
				if c, ok := byDesc[lookup(dn, rng)]; ok {
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
		if c, ok := byDesc[lookup(raw, (manifestRange(man, raw)))]; ok {
			roots[i].id = c
		}
	}
	workspaces := 0
	for _, e := range entries {
		if e.workspace {
			workspaces++
		}
	}
	return g.finish(roots, member != "" || workspaces > 1), nil
}

func manifestRange(man *Manifest, name string) string {
	for _, m := range []map[string]string{man.Dependencies, man.OptionalDependencies, man.DevDependencies} {
		if r, ok := m[name]; ok {
			return r
		}
	}
	return ""
}
