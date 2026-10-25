package lockfile

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

// pnpm lockfile flavours by major lockfileVersion: 5 (5.x), 6 (6.x), 9 (7+/9.x).
func pnpmMajor(v string) int {
	v = strings.Trim(v, "'\" ")
	if i := strings.IndexByte(v, '.'); i >= 0 {
		v = v[:i]
	}
	n, _ := strconv.Atoi(v)
	return n
}

func parsePnpm(data []byte, member string) ([]Package, error) {
	docs, err := parseYAMLDocs(string(data))
	if err != nil {
		return nil, err
	}
	// pnpm 9.7+ may prepend an "env" document; the real lockfile is the last one.
	var doc map[string]any
	for _, d := range docs {
		if m := yMap(d); m != nil && m["lockfileVersion"] != nil {
			doc = m
		}
	}
	if doc == nil {
		return nil, errors.New("not a pnpm lockfile (no lockfileVersion)")
	}
	major := pnpmMajor(yStr(doc["lockfileVersion"]))
	if major == 0 {
		return nil, fmt.Errorf("unsupported pnpm lockfileVersion %q", yStr(doc["lockfileVersion"]))
	}
	pk := &pnpmParser{major: major, g: newGraph()}

	packages := yMap(doc["packages"])
	snapshots := yMap(doc["snapshots"])
	nodesSrc, useSnap := packages, major >= 7 && snapshots != nil
	if useSnap {
		nodesSrc = snapshots
	}
	for _, key := range sortedAnyKeys(nodesSrc) {
		id := pnpmNorm(key)
		e := yMap(nodesSrc[key])
		meta := e
		if useSnap {
			meta = yMap(packages[pnpmStripPeers(id, major)])
		}
		name, ver := pk.splitID(id)
		if n := yStr(meta["name"]); n != "" {
			name = n
		}
		if v := yStr(meta["version"]); v != "" {
			ver = v
		}
		if name == "" || ver == "" {
			continue
		}
		n := &gnode{id: id, name: name, version: ver}
		n.scripts = yBool(meta["requiresBuild"]) || yBool(e["requiresBuild"])
		if d := yStr(meta["dev"]); d == "true" {
			n.devHint = 1
		} else if d == "false" {
			n.devHint = 2
		}
		deps := yStrMap(e["dependencies"])
		opt := yStrMap(e["optionalDependencies"])
		for _, m := range []map[string]string{deps, opt} {
			for _, dn := range sortedKeys(m) {
				cid, real, ok := pk.ref(dn, m[dn])
				if !ok {
					continue
				}
				if n.requires == nil {
					n.requires = map[string]string{}
				}
				// pnpm records resolved versions, not the declared ranges
				_, cv := pk.splitID(cid)
				n.requires[real] = cv
				n.children = append(n.children, cid)
			}
		}
		pk.g.add(n)
	}

	// importers
	importers := yMap(doc["importers"])
	if importers == nil {
		importers = map[string]any{".": doc}
	}
	want := member
	if want == "" {
		want = "."
	}
	if _, ok := importers[want]; !ok {
		if member != "" {
			return nil, fmt.Errorf("%w: %q", errNoMember, member)
		}
	}
	// importers become local nodes so "link:" deps on workspace siblings are
	// followed into the sibling's own (prod) dependencies
	pk.importers = importers
	for _, imp := range sortedAnyKeys(importers) {
		n := &gnode{id: "importer:" + imp, local: true}
		for _, r := range pk.importer(yMap(importers[imp]), imp) {
			if !r.dev && r.id != "" {
				n.children = append(n.children, r.id)
			}
		}
		pk.g.add(n)
	}
	roots := pk.importer(yMap(importers[want]), want)
	return pk.g.finish(roots, member != "" || len(importers) > 1), nil
}

type pnpmParser struct {
	major     int
	g         *graph
	importers map[string]any
}

func pnpmNorm(id string) string { return strings.TrimPrefix(id, "/") }

// pnpmStripPeers removes the peer-dependency suffix of a version or id:
// "18.2.0(react@18.2.0)" -> "18.2.0"; v5 "1.0.0_react@18.2.0" -> "1.0.0".
func pnpmStripPeers(s string, major int) string {
	if i := strings.IndexByte(s, '('); i >= 0 {
		s = s[:i]
	}
	if major < 6 {
		if i := strings.IndexByte(s, '_'); i >= 0 {
			s = s[:i]
		}
	}
	return s
}

// splitID returns name and peer-less version of a normalized package id.
func (p *pnpmParser) splitID(id string) (name, ver string) {
	id = pnpmStripPeers(id, p.major)
	if p.major < 6 {
		i := strings.LastIndexByte(id, '/')
		if i <= 0 {
			return "", ""
		}
		return id[:i], id[i+1:]
	}
	i := strings.LastIndexByte(id, '@')
	if i <= 0 {
		return "", ""
	}
	name, ver = id[:i], id[i+1:]
	if strings.Contains(ver, "/") || strings.Contains(ver, ":") {
		return "", "" // tarball / git ids carry name+version in fields instead
	}
	return name, ver
}

// ref converts a dependency reference (name + resolved version string) into
// a node id and the real package name. ok=false for link:/file: and other
// local references.
func (p *pnpmParser) ref(name, v string) (id, real string, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "link:") || strings.HasPrefix(v, "file:") {
		return "", "", false
	}
	base := pnpmStripPeers(v, p.major)
	full := strings.LastIndexByte(base, '@') > 0
	if p.major < 7 {
		full = strings.HasPrefix(v, "/")
	}
	if full {
		id = pnpmNorm(v)
	} else if p.major < 6 {
		id = name + "/" + v
	} else {
		id = name + "@" + v
	}
	n := p.g.nodes[id]
	if n == nil {
		if rn, _ := p.splitID(id); rn != "" {
			return id, rn, true
		}
		return "", "", false
	}
	return id, n.name, true
}

// importer reads one importer's dependency sections.
func (p *pnpmParser) importer(m map[string]any, self string) []rootDep {
	specs := yStrMap(m["specifiers"]) // v5
	var out []rootDep
	seen := map[string]bool{}
	for _, sec := range []struct {
		key string
		dev bool
	}{{"dependencies", false}, {"optionalDependencies", false}, {"devDependencies", true}} {
		deps := yMap(m[sec.key])
		for _, dn := range sortedAnyKeys(deps) {
			if seen[dn] {
				continue
			}
			seen[dn] = true
			var spec, ver string
			if e := yMap(deps[dn]); e != nil {
				spec, ver = yStr(e["specifier"]), yStr(e["version"])
			} else {
				spec, ver = specs[dn], yStr(deps[dn])
			}
			real, rng := splitAlias(dn, spec)
			r := rootDep{name: real, rng: rng, dev: sec.dev}
			if strings.HasPrefix(ver, "link:") {
				target := path.Clean(path.Join(self, strings.TrimPrefix(ver, "link:")))
				if _, ok := p.importers[target]; ok {
					r.id = "importer:" + target
					out = append(out, r)
				}
				continue
			}
			id, rn, ok := p.ref(dn, ver)
			if !ok {
				continue // local file
			}
			r.id = id
			if !strings.HasPrefix(spec, "npm:") {
				r.name = rn
			}
			out = append(out, r)
		}
	}
	return out
}

func sortedAnyKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
