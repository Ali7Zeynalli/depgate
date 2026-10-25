// Package sourcestest provides an in-memory Fetcher that imitates OSV,
// deps.dev, the npm registry, nodejs.org, CISA KEV and EPSS for tests and demos.
package sourcestest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/sources"
)

type Version struct {
	V          string
	Age        time.Duration
	Deprecated string
}

type Fake struct {
	Now       time.Time
	Vulns     map[string]*sources.Vuln
	Versions  map[string][]Version
	Manifest  map[string]map[string]any // "name@ver"
	EPSS      map[string]float64
	KEV       []string
	Node      []sources.NodeRelease
	Schedule  map[string]sources.NodeLine
	NpmAdv    map[string][]sources.NpmAdvisory // npm bulk advisory answers by package
	Removed   map[string]bool                  // "name@ver" npm no longer serves
	NodeCore  map[string]sources.NodeVuln      // Node.js security WG core vulnerabilities
	Releases  map[string][]sources.Release     // GitHub releases by "owner/repo"
	EOL       map[string][]map[string]any      // endoflife.date cycles (original API format) by product
	NginxHTML string                           // nginx.org security advisories page
	OSVQuery  map[string][]string              // OSV /v1/query answers by "ecosystem|name|version"
	// Match decides whether a vuln applies to name@version (set to decide.Affects by callers).
	Match func(v *sources.Vuln, name, version string) bool

	mu sync.Mutex
}

func New(now time.Time) *Fake {
	return &Fake{Now: now, Vulns: map[string]*sources.Vuln{}, Versions: map[string][]Version{}, Manifest: map[string]map[string]any{}, EPSS: map[string]float64{}, Schedule: map[string]sources.NodeLine{}, NpmAdv: map[string][]sources.NpmAdvisory{}, Removed: map[string]bool{}, NodeCore: map[string]sources.NodeVuln{}, Releases: map[string][]sources.Release{}, EOL: map[string][]map[string]any{}, OSVQuery: map[string][]string{}}
}

// Old returns versions published long ago (past any cooldown).
func Old(vs ...string) []Version {
	out := make([]Version, len(vs))
	for i, v := range vs {
		out[i] = Version{V: v, Age: 365 * 24 * time.Hour}
	}
	return out
}

// Vuln registers a SEMVER-range advisory.
func (f *Fake) Vuln(id, pkg, severity, introduced, fixed, summary string, aliases ...string) {
	b, _ := json.Marshal(map[string]any{
		"id": id, "summary": summary, "aliases": aliases,
		"database_specific": map[string]string{"severity": severity},
		"affected": []any{map[string]any{
			"package": map[string]string{"ecosystem": "npm", "name": pkg},
			"ranges":  []any{map[string]any{"type": "SEMVER", "events": events(introduced, fixed)}},
		}},
	})
	var v sources.Vuln
	_ = json.Unmarshal(b, &v)
	f.Vulns[id] = &v
}

// Malware registers an OpenSSF malicious-package record for exact versions.
func (f *Fake) Malware(id, pkg string, versions ...string) {
	b, _ := json.Marshal(map[string]any{
		"id": id, "summary": "Malicious code in " + pkg + " (npm)",
		"affected": []any{map[string]any{"package": map[string]string{"ecosystem": "npm", "name": pkg}, "versions": versions}},
	})
	var v sources.Vuln
	_ = json.Unmarshal(b, &v)
	f.Vulns[id] = &v
}

func events(introduced, fixed string) []map[string]string {
	ev := []map[string]string{{"introduced": introduced}}
	if fixed != "" {
		ev = append(ev, map[string]string{"fixed": fixed})
	}
	return ev
}

func (f *Fake) Do(ctx context.Context, method, u string, body []byte, _ map[string]string, _ time.Duration) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case strings.HasSuffix(u, "/querybatch"):
		var req struct {
			Queries []struct {
				Package struct{ Name string } `json:"package"`
				Version string                `json:"version"`
			} `json:"queries"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return nil, err
		}
		type res struct {
			Vulns []map[string]string `json:"vulns,omitempty"`
		}
		out := struct {
			Results []res `json:"results"`
		}{}
		for _, q := range req.Queries {
			var r res
			for id, v := range f.Vulns {
				if f.Match != nil && f.Match(v, q.Package.Name, q.Version) {
					r.Vulns = append(r.Vulns, map[string]string{"id": id})
				}
			}
			out.Results = append(out.Results, r)
		}
		return json.Marshal(out)
	case strings.HasSuffix(u, "api.osv.dev/v1/query"):
		var q struct {
			Package struct{ Name, Ecosystem string } `json:"package"`
			Version string                           `json:"version"`
		}
		if err := json.Unmarshal(body, &q); err != nil {
			return nil, err
		}
		var vs []map[string]string
		for _, id := range f.OSVQuery[q.Package.Ecosystem+"|"+q.Package.Name+"|"+q.Version] {
			vs = append(vs, map[string]string{"id": id})
		}
		return json.Marshal(map[string]any{"vulns": vs})
	case strings.HasPrefix(u, "https://nginx.org/"):
		if f.NginxHTML == "" {
			return nil, sources.ErrNotFound
		}
		return []byte(f.NginxHTML), nil
	case strings.Contains(u, "api.osv.dev/v1/vulns/"):
		id, _ := url.PathUnescape(u[strings.LastIndex(u, "/")+1:])
		if v, ok := f.Vulns[id]; ok {
			return json.Marshal(v)
		}
		return nil, sources.ErrNotFound
	case strings.Contains(u, "nodejs.org/dist/index.json"):
		return json.Marshal(f.Node)
	case strings.Contains(u, "nodejs/Release"):
		return json.Marshal(f.Schedule)
	case strings.Contains(u, "known_exploited"):
		var vs []map[string]string
		for _, c := range f.KEV {
			vs = append(vs, map[string]string{"cveID": c})
		}
		return json.Marshal(map[string]any{"vulnerabilities": vs})
	case strings.Contains(u, "api.first.org"):
		var data []map[string]string
		for _, c := range strings.Split(strings.SplitN(u, "cve=", 2)[1], ",") {
			if s, ok := f.EPSS[c]; ok {
				data = append(data, map[string]string{"cve": c, "epss": fmt.Sprint(s)})
			}
		}
		return json.Marshal(map[string]any{"data": data})
	case strings.Contains(u, "api.deps.dev"):
		name, _ := url.PathUnescape(u[strings.LastIndex(u, "/packages/")+len("/packages/"):])
		vs, ok := f.Versions[name]
		if !ok {
			return nil, sources.ErrNotFound
		}
		var items []map[string]any
		for i, v := range vs {
			items = append(items, map[string]any{
				"versionKey": map[string]string{"version": v.V}, "publishedAt": f.Now.Add(-v.Age).Format(time.RFC3339),
				"isDefault": i == len(vs)-1, "isDeprecated": v.Deprecated != "", "deprecatedReason": v.Deprecated,
			})
		}
		return json.Marshal(map[string]any{"versions": items})
	case strings.HasSuffix(u, "/-/npm/v1/security/advisories/bulk"):
		var req map[string][]string
		if err := json.Unmarshal(body, &req); err != nil {
			return nil, err
		}
		out := map[string][]sources.NpmAdvisory{}
		for name := range req {
			if a, ok := f.NpmAdv[name]; ok {
				out[name] = a
			}
		}
		return json.Marshal(out)
	case strings.HasPrefix(u, "https://endoflife.date/api/"):
		if strings.Contains(u, "/v1/") {
			return nil, sources.ErrNotFound // tests use the original format
		}
		cs, ok := f.EOL[strings.TrimSuffix(strings.TrimPrefix(u, "https://endoflife.date/api/"), ".json")]
		if !ok {
			return nil, sources.ErrNotFound
		}
		return json.Marshal(cs)
	case strings.Contains(u, "api.github.com/repos/"):
		repo := strings.TrimSuffix(strings.SplitN(strings.TrimPrefix(u, "https://api.github.com/repos/"), "/releases", 2)[0], "/")
		return json.Marshal(f.Releases[repo])
	case strings.Contains(u, "nodejs/security-wg"):
		return json.Marshal(f.NodeCore)
	case strings.Contains(u, "registry.npmjs.org"):
		rest := strings.TrimPrefix(u, "https://registry.npmjs.org/")
		i := strings.LastIndex(rest, "/")
		name, _ := url.PathUnescape(rest[:i])
		ver := rest[i+1:]
		if f.Removed[name+"@"+ver] {
			return nil, sources.ErrNotFound
		}
		if m, ok := f.Manifest[name+"@"+ver]; ok {
			return json.Marshal(m)
		}
		return json.Marshal(map[string]any{"name": name, "version": ver})
	}
	return nil, fmt.Errorf("sourcestest: unexpected %s %s", method, u)
}
