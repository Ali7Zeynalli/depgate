package lockfile

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// bun.lock (Bun 1.2+) is JSON with comments and trailing commas.
//
//	{"lockfileVersion": 1,
//	 "workspaces": {"": {"name": "app", "dependencies": {...}, "devDependencies": {...}},
//	                "apps/web": {...}},
//	 "packages": {"react": ["react@18.2.0", "", {"dependencies": {...}}, "sha512-..."],
//	              "foo/bar": ["bar@1.0.0", ...]}}   // nested: "<parent path>/<name>"
type bunLock struct {
	LockfileVersion int                          `json:"lockfileVersion"`
	Workspaces      map[string]bunWorkspace      `json:"workspaces"`
	Packages        map[string][]json.RawMessage `json:"packages"`
	TrustedDeps     []string                     `json:"trustedDependencies"`
}

type bunWorkspace struct {
	Name                 string            `json:"name"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type bunMeta struct {
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func parseBun(data []byte, member string) ([]Package, error) {
	var lf bunLock
	if err := json.Unmarshal(jsoncToJSON(data), &lf); err != nil {
		return nil, err
	}
	g := newGraph()
	keys := sortedRawKeys(lf.Packages)
	// resolve dep name from package key path: try "<key>/<dep>", then walk up
	resolve := func(from, dep string) string {
		base := from
		for {
			k := dep
			if base != "" {
				k = base + "/" + dep
			}
			if _, ok := lf.Packages[k]; ok {
				return k
			}
			if base == "" {
				return ""
			}
			base = bunParentKey(base)
		}
	}
	for _, k := range keys {
		arr := lf.Packages[k]
		if len(arr) == 0 {
			continue
		}
		var ident string
		if json.Unmarshal(arr[0], &ident) != nil {
			continue
		}
		name, ver := yarnSplitDescriptor(ident)
		n := &gnode{id: k, name: name, version: ver}
		if strings.Contains(ver, ":") { // workspace:, file:, link:, github:, git+…
			n.local = true
		}
		var meta bunMeta
		for _, raw := range arr[1:] {
			if len(raw) > 0 && raw[0] == '{' {
				_ = json.Unmarshal(raw, &meta)
				break
			}
		}
		n.requires = mergeReq(meta.Dependencies, meta.OptionalDependencies)
		if n.local {
			n.requires = nil
		}
		for _, m := range []map[string]string{meta.Dependencies, meta.OptionalDependencies} {
			for _, d := range sortedKeys(m) {
				if c := resolve(k, d); c != "" {
					n.children = append(n.children, c)
				}
			}
		}
		g.add(n)
	}
	// "ui": ["ui@workspace:packages/ui"] -> the deps of workspace packages/ui
	for _, k := range keys {
		n := g.nodes[k]
		if n == nil || !strings.HasPrefix(n.version, "workspace:") {
			continue
		}
		w, ok := lf.Workspaces[strings.TrimPrefix(n.version, "workspace:")]
		if !ok {
			continue
		}
		for _, m := range []map[string]string{w.Dependencies, w.OptionalDependencies} {
			for _, d := range sortedKeys(m) {
				if c := resolve("", d); c != "" {
					n.children = append(n.children, c)
				}
			}
		}
	}
	for _, t := range lf.TrustedDeps {
		for _, k := range keys {
			if n := g.nodes[k]; n != nil && n.name == t {
				n.scripts = true
			}
		}
	}
	if _, ok := lf.Workspaces[member]; !ok && member != "" {
		return nil, fmt.Errorf("%w: %q", errNoMember, member)
	}
	importer := func(w bunWorkspace) []rootDep {
		roots := depRoots(w.Dependencies, w.OptionalDependencies, w.DevDependencies)
		for i := range roots {
			raw := roots[i].name
			roots[i].name, roots[i].rng = splitAlias(raw, roots[i].rng)
			roots[i].id = resolve("", raw) // a workspace sibling is traversed, not emitted
		}
		return roots
	}
	return g.finish(importer(lf.Workspaces[member]), member != "" || len(lf.Workspaces) > 1), nil
}

// bunParentKey drops the last package name from a nested key
// ("next/@swc/helpers" -> "next", "a/b" -> "a", "@s/a" -> "").
func bunParentKey(k string) string {
	parts := strings.Split(k, "/")
	// regroup scoped names
	var names []string
	for i := 0; i < len(parts); i++ {
		if strings.HasPrefix(parts[i], "@") && i+1 < len(parts) {
			names = append(names, parts[i]+"/"+parts[i+1])
			i++
			continue
		}
		names = append(names, parts[i])
	}
	if len(names) <= 1 {
		return ""
	}
	return strings.Join(names[:len(names)-1], "/")
}

// jsoncToJSON removes // and /* */ comments and trailing commas outside strings.
func jsoncToJSON(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			if c == '\\' && i+1 < len(b) {
				i++
				out = append(out, b[i])
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			if i < len(b) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++
		case c == ',':
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue
			}
			// a comment may sit between the comma and the closer
			if j+1 < len(b) && b[j] == '/' && (b[j+1] == '/' || b[j+1] == '*') {
				if bunNextSignificant(b, j) == '}' || bunNextSignificant(b, j) == ']' {
					continue
				}
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}

// bunNextSignificant returns the next byte that is not whitespace or comment.
func bunNextSignificant(b []byte, i int) byte {
	for i < len(b) {
		switch {
		case b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r':
			i++
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i += 2
		default:
			return b[i]
		}
	}
	return 0
}

func sortedRawKeys(m map[string][]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
