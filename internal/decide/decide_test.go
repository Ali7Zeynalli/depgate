package decide

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/lockfile"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/semver"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
)

var now = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

// fake serves deps.dev, npm registry, OSV and EPSS from in-memory tables.
type fake struct {
	mu       sync.Mutex
	vulns    map[string]*sources.Vuln  // id -> record
	versions map[string][]fakeVer      // package -> versions
	mans     map[string]map[string]any // "name@ver" -> registry doc
	epss     map[string]float64        // cve -> score
	npm      map[string][]sources.NpmAdvisory
	removed  map[string]bool // "name@ver" -> 404 on the registry
	calls    map[string]int
}

type fakeVer struct {
	v   string
	age time.Duration
	dep string
}

func newFake() *fake {
	return &fake{vulns: map[string]*sources.Vuln{}, versions: map[string][]fakeVer{}, mans: map[string]map[string]any{}, epss: map[string]float64{}, npm: map[string][]sources.NpmAdvisory{}, removed: map[string]bool{}, calls: map[string]int{}}
}

func old(vs ...string) []fakeVer {
	var out []fakeVer
	for _, v := range vs {
		out = append(out, fakeVer{v: v, age: 200 * 24 * time.Hour})
	}
	return out
}

func (f *fake) vuln(id, pkg, sev string, introduced, fixed string) *sources.Vuln {
	v := &sources.Vuln{ID: id, Summary: id + " summary", Aliases: []string{"CVE-2026-" + strings.TrimPrefix(id, "GHSA-")}}
	v.DatabaseSpecific.Severity = sev
	var a sources.Affected
	a.Package.Ecosystem, a.Package.Name = "npm", pkg
	r := sources.OSVRange{Type: "SEMVER"}
	r.Events = append(r.Events, struct {
		Introduced   string `json:"introduced,omitempty"`
		Fixed        string `json:"fixed,omitempty"`
		LastAffected string `json:"last_affected,omitempty"`
	}{Introduced: introduced})
	if fixed != "" {
		r.Events = append(r.Events, struct {
			Introduced   string `json:"introduced,omitempty"`
			Fixed        string `json:"fixed,omitempty"`
			LastAffected string `json:"last_affected,omitempty"`
		}{Fixed: fixed})
	}
	a.Ranges = []sources.OSVRange{r}
	v.Affected = []sources.Affected{a}
	f.vulns[id] = v
	return v
}

func (f *fake) Do(ctx context.Context, method, u string, body []byte, _ map[string]string, _ time.Duration) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[u]++
	switch {
	case strings.HasSuffix(u, "/querybatch"):
		var req struct {
			Queries []struct {
				Package struct{ Name string } `json:"package"`
				Version string                `json:"version"`
			} `json:"queries"`
		}
		_ = json.Unmarshal(body, &req)
		type res struct {
			Vulns []map[string]string `json:"vulns"`
		}
		var out struct {
			Results []res `json:"results"`
		}
		for _, q := range req.Queries {
			var r res
			v := semver.MustParse(q.Version)
			for id, rec := range f.vulns {
				if Affects(rec, q.Package.Name, v) {
					r.Vulns = append(r.Vulns, map[string]string{"id": id})
				}
			}
			out.Results = append(out.Results, r)
		}
		return json.Marshal(out)
	case strings.Contains(u, "api.osv.dev/v1/vulns/"):
		id, _ := url.PathUnescape(u[strings.LastIndex(u, "/")+1:])
		if v, ok := f.vulns[id]; ok {
			return json.Marshal(v)
		}
		return nil, sources.ErrNotFound
	case strings.Contains(u, "api.first.org"):
		var data []map[string]string
		for _, c := range strings.Split(strings.SplitN(u, "cve=", 2)[1], ",") {
			if s, ok := f.epss[c]; ok {
				data = append(data, map[string]string{"cve": c, "epss": fmt.Sprint(s)})
			}
		}
		return json.Marshal(map[string]any{"data": data})
	case strings.Contains(u, "api.deps.dev"):
		name, _ := url.PathUnescape(u[strings.LastIndex(u, "/packages/")+len("/packages/"):])
		vs, ok := f.versions[name]
		if !ok {
			return nil, sources.ErrNotFound
		}
		var items []map[string]any
		latest := ""
		for _, v := range vs {
			if pv := semver.MustParse(v.v); !pv.IsPrerelease() && (latest == "" || semver.Less(semver.MustParse(latest), pv)) {
				latest = v.v
			}
		}
		for _, v := range vs {
			items = append(items, map[string]any{
				"versionKey": map[string]string{"version": v.v}, "publishedAt": now.Add(-v.age).Format(time.RFC3339),
				"isDefault": v.v == latest, "isDeprecated": v.dep != "", "deprecatedReason": v.dep,
			})
		}
		return json.Marshal(map[string]any{"versions": items})
	case strings.HasSuffix(u, "/security/advisories/bulk"):
		var req map[string][]string
		_ = json.Unmarshal(body, &req)
		out := map[string][]sources.NpmAdvisory{}
		for n := range req {
			if a, ok := f.npm[n]; ok {
				out[n] = a
			}
		}
		return json.Marshal(out)
	case strings.Contains(u, "registry.npmjs.org"):
		rest := strings.TrimPrefix(u, "https://registry.npmjs.org/")
		i := strings.LastIndex(rest, "/")
		name, _ := url.PathUnescape(rest[:i])
		ver := rest[i+1:]
		if f.removed[name+"@"+ver] {
			return nil, sources.ErrNotFound
		}
		if m, ok := f.mans[name+"@"+ver]; ok {
			return json.Marshal(m)
		}
		return json.Marshal(map[string]any{"name": name, "version": ver})
	}
	return nil, fmt.Errorf("fake: unexpected %s %s", method, u)
}

func lock(mgr string, pkgs ...lockfile.Package) *lockfile.Result {
	return &lockfile.Result{Kind: mgr, Manager: mgr, File: "lock", Packages: pkgs}
}

func run(t *testing.T, f *fake, in Input) map[string]report.Finding {
	t.Helper()
	d := NewData(f)
	d.KEV = map[string]bool{}
	if in.Mgr == "" {
		in.Mgr = ManagerOf(in.Lock)
	}
	fs, errs := Packages(context.Background(), d, in, Options{CooldownDays: 3, Now: now})
	for _, e := range errs {
		t.Logf("error: %s", e)
	}
	out := map[string]report.Finding{}
	for _, x := range fs {
		out[x.Pkg+"@"+x.Current] = x
	}
	return out
}

func TestDirectVulnSafestMinimum(t *testing.T) {
	f := newFake()
	f.vuln("GHSA-next1", "next", "HIGH", "15.0.0", "15.1.9")
	f.versions["next"] = append(old("15.1.2", "15.1.8", "15.1.9", "16.0.3"), fakeVer{v: "15.1.10", age: time.Hour})
	got := run(t, f, Input{Lock: lock("pnpm", lockfile.Package{Name: "next", Version: "15.1.2", Direct: true, Range: "^15.1.0"})})
	x := got["next@15.1.2"]
	if x.Target != "15.1.9" || x.Need != report.NeedNow || x.Impact != report.ImpactNo || x.Group != report.GroupNowEasy {
		t.Fatalf("got target=%s need=%s impact=%s group=%s", x.Target, x.Need, x.Impact, x.Group)
	}
	if x.Fix == nil || x.Fix.Command != "pnpm up next@15.1.9" || x.Latest != "16.0.3" {
		t.Fatalf("fix=%+v latest=%s", x.Fix, x.Latest)
	}
	if x.Priority != 35 {
		t.Fatalf("priority %d", x.Priority)
	}
}

func TestFixOnlyInNewMajor(t *testing.T) {
	f := newFake()
	f.vuln("GHSA-ax1", "axios", "CRITICAL", "0", "1.12.0")
	f.versions["axios"] = old("0.27.2", "0.28.1", "1.12.0", "1.12.2")
	got := run(t, f, Input{Lock: lock("npm", lockfile.Package{Name: "axios", Version: "0.27.2", Direct: true})})
	x := got["axios@0.27.2"]
	if x.Target != "1.12.0" || x.Impact != report.ImpactYes || x.Group != report.GroupNowCode {
		t.Fatalf("got %+v", x)
	}
	if !contains(x.Why, "major") {
		t.Fatalf("why lacks major note: %v", x.Why)
	}
}

func TestCooldownWarning(t *testing.T) {
	f := newFake()
	f.vuln("GHSA-c1", "left-pad", "HIGH", "0", "1.3.1")
	f.versions["left-pad"] = append(old("1.3.0"), fakeVer{v: "1.3.1", age: 5 * time.Hour})
	got := run(t, f, Input{Lock: lock("npm", lockfile.Package{Name: "left-pad", Version: "1.3.0", Direct: true})})
	x := got["left-pad@1.3.0"]
	if x.Target != "1.3.1" || len(x.Warnings) == 0 || !strings.Contains(x.Warnings[0].Az, "5 saat") || !strings.Contains(x.Warnings[0].En, "5 hours") {
		t.Fatalf("got target %s warnings %v", x.Target, x.Warnings)
	}
}

func TestTransitiveRelock(t *testing.T) {
	f := newFake()
	f.vuln("GHSA-x1", "xlib", "HIGH", "1.0.0", "1.2.5")
	f.versions["xlib"] = old("1.2.0", "1.2.5", "1.3.0")
	got := run(t, f, Input{Lock: lock("npm",
		lockfile.Package{Name: "app-parent", Version: "2.0.0", Direct: true, Requires: map[string]string{"xlib": "^1.2.0"}},
		lockfile.Package{Name: "xlib", Version: "1.2.0", Parents: []string{"app-parent"}},
	)})
	x := got["xlib@1.2.0"]
	if x.Fix == nil || x.Fix.Strategy != "relock" || x.Fix.Command != "npm update xlib" || x.Impact != report.ImpactNo {
		t.Fatalf("got fix %+v impact %s", x.Fix, x.Impact)
	}
	if strings.Join(x.Chain, ">") != "app-parent>xlib" {
		t.Fatalf("chain %v", x.Chain)
	}
}

func TestTransitiveParentUpgrade(t *testing.T) {
	f := newFake()
	f.vuln("GHSA-y1", "ylib", "HIGH", "0", "3.0.0")
	f.versions["ylib"] = old("2.0.0", "2.9.0", "3.0.0")
	f.versions["qpar"] = old("1.0.0", "1.0.5", "1.1.0", "2.0.0")
	f.mans["qpar@1.0.5"] = map[string]any{"name": "qpar", "version": "1.0.5", "dependencies": map[string]string{"ylib": "^2.0.0"}}
	f.mans["qpar@1.1.0"] = map[string]any{"name": "qpar", "version": "1.1.0", "dependencies": map[string]string{"ylib": "^3.0.0"}}
	got := run(t, f, Input{Lock: lock("pnpm",
		lockfile.Package{Name: "qpar", Version: "1.0.0", Direct: true, Requires: map[string]string{"ylib": "^2.0.0"}},
		lockfile.Package{Name: "ylib", Version: "2.0.0", Parents: []string{"qpar"}},
	)})
	x := got["ylib@2.0.0"]
	if x.Fix == nil || x.Fix.Strategy != "parent" || x.Fix.Command != "pnpm up qpar@1.1.0" || x.Impact != report.ImpactNo {
		t.Fatalf("got fix %+v impact %s", x.Fix, x.Impact)
	}
}

func TestTransitiveOverride(t *testing.T) {
	f := newFake()
	f.vuln("GHSA-z1", "zlib2", "MODERATE", "0", "1.1.0")
	f.versions["zlib2"] = old("1.0.0", "1.1.0")
	f.versions["rpar"] = old("3.0.0")
	got := run(t, f, Input{Lock: lock("yarn-berry",
		lockfile.Package{Name: "rpar", Version: "3.0.0", Direct: true, Requires: map[string]string{"mid": "^1"}},
		lockfile.Package{Name: "mid", Version: "1.0.0", Parents: []string{"rpar"}, Requires: map[string]string{"zlib2": "~1.0.0"}},
		lockfile.Package{Name: "zlib2", Version: "1.0.0", Parents: []string{"mid"}},
	)})
	x := got["zlib2@1.0.0"]
	if x.Fix == nil || x.Fix.Strategy != "override" || x.Impact != report.ImpactMaybe || x.Need != report.NeedSoon {
		t.Fatalf("got fix %+v impact %s need %s", x.Fix, x.Impact, x.Need)
	}
	if !strings.Contains(x.Fix.Snippet, `"zlib2": "1.1.0"`) {
		t.Fatalf("snippet %s", x.Fix.Snippet)
	}
}

func TestMalwareRevert(t *testing.T) {
	f := newFake()
	mal := &sources.Vuln{ID: "MAL-2026-1", Summary: "Malicious code in evil-pkg"}
	var a sources.Affected
	a.Package.Ecosystem, a.Package.Name = "npm", "evil-pkg"
	a.Versions = []string{"1.0.1"}
	mal.Affected = []sources.Affected{a}
	f.vulns[mal.ID] = mal
	f.versions["evil-pkg"] = old("1.0.0", "1.0.1")
	got := run(t, f, Input{Lock: lock("npm", lockfile.Package{Name: "evil-pkg", Version: "1.0.1", Direct: true})})
	x := got["evil-pkg@1.0.1"]
	if x.Kind != "malware" || x.Priority != 100 || x.Target != "1.0.0" || x.Need != report.NeedNow {
		t.Fatalf("got %+v", x)
	}
}

func TestDevStepDownAndEPSS(t *testing.T) {
	f := newFake()
	f.vuln("GHSA-d1", "devtool", "HIGH", "0", "2.0.1")
	f.epss["CVE-2026-d1"] = 0.4
	f.versions["devtool"] = old("2.0.0", "2.0.1")
	got := run(t, f, Input{Lock: lock("npm", lockfile.Package{Name: "devtool", Version: "2.0.0", Direct: true, Dev: true})})
	x := got["devtool@2.0.0"]
	if x.Need != report.NeedSoon {
		t.Fatalf("need %s", x.Need)
	}
	if x.Priority != 35+6-15 {
		t.Fatalf("priority %d", x.Priority)
	}
	if x.Fix.Command != "npm install -D devtool@2.0.1" {
		t.Fatalf("cmd %s", x.Fix.Command)
	}
}

func TestUpdatesAndSupplyChainSignals(t *testing.T) {
	f := newFake()
	f.versions["react"] = old("18.2.0", "18.3.1", "19.0.0")
	f.versions["chalk"] = old("5.3.0", "5.4.0")
	f.mans["chalk@5.3.0"] = map[string]any{"name": "chalk", "version": "5.3.0", "_npmUser": map[string]string{"name": "sindre"}, "dist": map[string]any{"attestations": map[string]string{"url": "x"}}}
	f.mans["chalk@5.4.0"] = map[string]any{"name": "chalk", "version": "5.4.0", "_npmUser": map[string]string{"name": "stranger"}, "scripts": map[string]string{"postinstall": "node x.js"}}
	f.versions["lodash"] = old("4.17.21")
	f.versions["request"] = []fakeVer{{v: "2.88.2", age: 2000 * 24 * time.Hour, dep: "request has been deprecated"}}
	got := run(t, f, Input{Lock: lock("npm",
		lockfile.Package{Name: "react", Version: "18.2.0", Direct: true},
		lockfile.Package{Name: "chalk", Version: "5.3.0", Direct: true},
		lockfile.Package{Name: "lodash", Version: "4.17.21", Direct: true},
		lockfile.Package{Name: "request", Version: "2.88.2", Direct: true},
	)})
	if x := got["react@18.2.0"]; x.Group != report.GroupOptional || x.Target != "18.3.1" || !contains(x.Why, "19.0.0") {
		t.Fatalf("react %+v", x)
	}
	c := got["chalk@5.3.0"]
	if len(c.Warnings) != 3 {
		t.Fatalf("chalk warnings %v", c.Warnings)
	}
	if x := got["lodash@4.17.21"]; x.Group != report.GroupOK {
		t.Fatalf("lodash %+v", x)
	}
	if x := got["request@2.88.2"]; x.Kind != "deprecated" || x.Group != report.GroupNowCode {
		t.Fatalf("request %+v", x)
	}
}

func TestPeerAndEngines(t *testing.T) {
	f := newFake()
	f.vuln("GHSA-p1", "ui-kit", "HIGH", "0", "3.0.1")
	f.versions["ui-kit"] = old("3.0.0", "3.0.1")
	f.mans["ui-kit@3.0.1"] = map[string]any{"name": "ui-kit", "version": "3.0.1", "peerDependencies": map[string]string{"react": "^19.0.0"}, "engines": map[string]string{"node": ">=22"}}
	got := run(t, f, Input{NodeVersion: "20.11.0", Lock: lock("npm",
		lockfile.Package{Name: "ui-kit", Version: "3.0.0", Direct: true},
		lockfile.Package{Name: "react", Version: "18.3.1", Direct: true},
	)})
	x := got["ui-kit@3.0.0"]
	if x.Impact != report.ImpactYes || len(x.ImpactWhy) < 3 {
		t.Fatalf("impact %s why %v", x.Impact, x.ImpactWhy)
	}
}

func TestEvalNode(t *testing.T) {
	nd := &sources.NodeData{
		Releases: []sources.NodeRelease{
			{Version: "v24.22.1", LTS: "Krypton", Security: true},
			{Version: "v22.23.4", LTS: "Jod", Security: true},
			{Version: "v22.22.0", LTS: "Jod"},
			{Version: "v22.20.0", LTS: "Jod"},
			{Version: "v20.19.9", LTS: "Iron"},
			{Version: "v18.20.8", LTS: "Hydrogen"},
		},
		Schedule: map[int]sources.NodeLine{
			18: {LTS: "2022-10-25", End: "2025-04-30"},
			20: {LTS: "2023-10-24", End: "2026-04-30"},
			22: {LTS: "2024-10-29", End: "2027-04-30"},
			24: {LTS: "2025-10-28", End: "2028-04-30"},
		},
	}
	n := EvalNode([]report.NodeSource{{File: "Dockerfile", Value: "node:22.20.0-alpine3.20"}, {File: ".nvmrc", Value: "22"}}, nd, now)
	if n.Need != report.NeedNow || n.Impact != report.ImpactNo || n.SecurityFix != "22.23.4" || n.Command != "FROM node:22.23.4-alpine3.20   # Dockerfile" || n.Mismatch {
		t.Fatalf("22: %+v", n)
	}
	n = EvalNode([]report.NodeSource{{File: ".nvmrc", Value: "v18.20.8"}}, nd, now)
	if n.Need != report.NeedNow || n.Impact != report.ImpactYes || n.NextLTS != 22 || !strings.HasPrefix(n.Command, "nvm install 22.23.4") {
		t.Fatalf("18: %+v", n)
	}
	n = EvalNode([]report.NodeSource{{File: "Dockerfile", Value: "node:24"}, {File: ".nvmrc", Value: "22.23.4"}}, nd, now)
	if !n.Mismatch {
		t.Fatalf("mismatch not detected: %+v", n)
	}
}

func TestCVSS(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N": 5.3,
		"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H": 5.5,
	}
	for v, want := range cases {
		if got, ok := sources.CVSS3Base(v); !ok || got != want {
			t.Errorf("%s: got %v want %v", v, got, want)
		}
	}
}

func contains(ss []i18n.T, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s.Az, sub) && strings.Contains(s.En, sub) {
			return true
		}
	}
	return false
}

func TestPnpmRelockReadsRangeFromRegistry(t *testing.T) {
	f := newFake()
	f.vuln("GHSA-pn1", "follow-redirects", "MODERATE", "0", "1.15.9")
	f.versions["follow-redirects"] = old("1.15.6", "1.15.9")
	f.mans["axios@1.6.8"] = map[string]any{"name": "axios", "version": "1.6.8", "dependencies": map[string]string{"follow-redirects": "^1.15.6"}}
	l := lock("pnpm",
		lockfile.Package{Name: "axios", Version: "1.6.8", Direct: true, Requires: map[string]string{"follow-redirects": "1.15.6"}},
		lockfile.Package{Name: "follow-redirects", Version: "1.15.6", Parents: []string{"axios"}},
	)
	got := run(t, f, Input{Lock: l})
	x := got["follow-redirects@1.15.6"]
	if x.Fix == nil || x.Fix.Strategy != "relock" || x.Fix.Command != "pnpm update --depth Infinity follow-redirects" {
		t.Fatalf("fix %+v", x.Fix)
	}
}

func npmAdv(ghsa, title, sev, rng string, cwe ...string) sources.NpmAdvisory {
	return sources.NpmAdvisory{ID: 1, URL: "https://github.com/advisories/" + ghsa, Title: title, Severity: sev, VulnerableVersions: rng, CWE: cwe}
}

// npm knows an advisory OSV has not imported yet: it must still be reported, once.
func TestNpmAdvisoryNotYetInOSV(t *testing.T) {
	f := newFake()
	f.vuln("GHSA-aaaa", "lib", "HIGH", "0", "1.2.0")
	f.npm["lib"] = []sources.NpmAdvisory{
		npmAdv("GHSA-aaaa", "already in OSV", "high", "<1.2.0"),
		npmAdv("GHSA-bbbb", "only in npm", "critical", ">=1.0.0 <1.3.0"),
		npmAdv("GHSA-cccc", "other versions", "high", "<0.5.0"),
	}
	f.versions["lib"] = old("1.1.0", "1.2.0", "1.3.0")
	got := run(t, f, Input{Lock: lock("npm", lockfile.Package{Name: "lib", Version: "1.1.0", Direct: true, Range: "^1.1.0"})})
	x := got["lib@1.1.0"]
	ids := []string{}
	for _, a := range x.Advisories {
		ids = append(ids, a.ID)
	}
	if strings.Join(ids, ",") != "GHSA-bbbb,GHSA-aaaa" || x.Severity != "critical" || x.Target != "1.3.0" {
		t.Fatalf("advisories %v severity %s target %s", ids, x.Severity, x.Target)
	}
}

// GitHub malware advisories (CWE-506) arrive through npm before OSV.
func TestNpmMalware(t *testing.T) {
	f := newFake()
	f.npm["evil"] = []sources.NpmAdvisory{npmAdv("GHSA-mmmm", "Malware in evil", "critical", "=2.0.1", "CWE-506")}
	f.versions["evil"] = old("2.0.0", "2.0.1")
	x := run(t, f, Input{Lock: lock("npm", lockfile.Package{Name: "evil", Version: "2.0.1", Direct: true})})["evil@2.0.1"]
	if x.Kind != "malware" || x.Target != "2.0.0" || !contains(x.Why, "GitHub Advisory / npm") {
		t.Fatalf("got %+v", x)
	}
}

// npm audit skips prereleases (JFrog, 2025); DepGate must not.
func TestPrereleaseMatched(t *testing.T) {
	f := newFake()
	f.npm["pre"] = []sources.NpmAdvisory{npmAdv("GHSA-pppp", "bad beta", "high", "<2.0.1")}
	f.versions["pre"] = old("2.0.0-beta.1", "2.0.1")
	x := run(t, f, Input{Lock: lock("npm", lockfile.Package{Name: "pre", Version: "2.0.0-beta.1", Direct: true})})["pre@2.0.0-beta.1"]
	if x.Kind != "vuln" || len(x.Advisories) != 1 {
		t.Fatalf("prerelease not matched: %+v", x)
	}
}

func TestRemovedVersion(t *testing.T) {
	f := newFake()
	f.versions["gone"] = old("1.0.0", "1.0.1", "1.0.2", "2.0.0")
	f.removed["gone@1.0.1"] = true
	f.versions["@acme/local"] = nil // workspace / private: unknown to deps.dev
	delete(f.versions, "@acme/local")
	f.removed["@acme/local@1.0.0"] = true
	got := run(t, f, Input{Lock: lock("npm",
		lockfile.Package{Name: "gone", Version: "1.0.1", Direct: true},
		lockfile.Package{Name: "@acme/local", Version: "1.0.0", Direct: true})})
	x := got["gone@1.0.1"]
	if x.Kind != "removed" || x.Target != "1.0.2" || x.Need != report.NeedNow {
		t.Fatalf("got %+v", x)
	}
	if y := got["@acme/local@1.0.0"]; y.Kind == "removed" {
		t.Fatal("private/workspace package reported as removed")
	}
}

func TestSecurityPlaceholder(t *testing.T) {
	f := newFake()
	f.versions["taken"] = old("0.0.1-security")
	f.removed["taken@1.4.0"] = true
	x := run(t, f, Input{Lock: lock("npm", lockfile.Package{Name: "taken", Version: "1.4.0", Direct: true})})["taken@1.4.0"]
	if x.Kind != "malware" || x.Priority != 100 || !contains(x.Why, "0.0.1-security") {
		t.Fatalf("got %+v", x)
	}
}

func TestNodeCoreVulns(t *testing.T) {
	nd := &sources.NodeData{
		Releases: []sources.NodeRelease{{Version: "v22.23.4", LTS: "Jod"}, {Version: "v22.20.0", LTS: "Jod"}},
		Schedule: map[int]sources.NodeLine{22: {LTS: "2024-10-29", End: "2027-04-30"}},
		Core: []sources.NodeVuln{
			{ID: "1", CVE: []string{"CVE-2026-1111"}, Vulnerable: "22.x", Patched: "^22.21.0", Description: "path traversal", Severity: "HIGH", Environment: []string{"all"}},
			{ID: "2", CVE: []string{"CVE-2026-2222"}, Vulnerable: "20.x", Patched: "^20.19.0", Description: "other line"},
		},
	}
	n := EvalNode([]report.NodeSource{{File: ".nvmrc", Value: "22.20.0"}}, nd, now)
	if len(n.Vulns) != 1 || n.Vulns[0].CVE[0] != "CVE-2026-1111" || n.SecurityFix != "22.23.4" || n.Need != report.NeedNow || !contains(n.Why, "CVE-2026-1111") {
		t.Fatalf("got %+v", n)
	}
	if n := EvalNode([]report.NodeSource{{File: ".nvmrc", Value: "22.23.4"}}, nd, now); len(n.Vulns) != 0 {
		t.Fatalf("patched version still reported: %+v", n.Vulns)
	}
}

func TestBundleReact(t *testing.T) {
	f := newFake()
	f.versions["react"] = old("18.2.0", "18.3.1", "19.2.0")
	f.versions["react-dom"] = old("18.2.0", "18.3.1", "19.2.0")
	f.versions["@types/react"] = old("18.2.0", "18.3.12", "19.2.2")
	in := Input{Lock: lock("npm",
		lockfile.Package{Name: "react", Version: "18.2.0", Direct: true},
		lockfile.Package{Name: "react-dom", Version: "18.2.0", Direct: true},
		lockfile.Package{Name: "@types/react", Version: "18.2.0", Direct: true, Dev: true})}
	in.Mgr = "npm"
	d := NewData(f)
	d.KEV = map[string]bool{}
	fs, _ := Packages(context.Background(), d, in, Options{CooldownDays: 3, Now: now})
	bs := Bundles(context.Background(), d, in, fs, Options{CooldownDays: 3, Now: now})
	if len(bs) != 1 || bs[0].ID != "react" || bs[0].Target != "18.3.1" {
		t.Fatalf("bundles %+v", bs)
	}
	if bs[0].Command != "npm install react@18.3.1 react-dom@18.3.1" {
		t.Fatalf("command %q", bs[0].Command)
	}
	warned := 0
	for _, x := range fs {
		if contains(x.Warnings, "React") {
			warned++
		}
	}
	if warned < 2 {
		t.Fatalf("member cards not pointed at the bundle (%d)", warned)
	}
}

func TestBundleNestDriftAndScope(t *testing.T) {
	f := newFake()
	for _, n := range []string{"@nestjs/core", "@nestjs/common", "@nestjs/platform-express", "@nestjs/testing"} {
		f.versions[n] = old("11.1.0", "11.1.6")
	}
	f.versions["@nestjs/config"] = old("4.0.2")
	in := Input{Mgr: "pnpm", Lock: lock("pnpm",
		lockfile.Package{Name: "@nestjs/core", Version: "11.1.6", Direct: true},
		lockfile.Package{Name: "@nestjs/common", Version: "11.1.0", Direct: true},
		lockfile.Package{Name: "@nestjs/platform-express", Version: "11.1.6", Direct: true},
		lockfile.Package{Name: "@nestjs/testing", Version: "11.1.0", Direct: true, Dev: true},
		lockfile.Package{Name: "@nestjs/config", Version: "4.0.2", Direct: true})}
	d := NewData(f)
	bs := Bundles(context.Background(), d, in, nil, Options{CooldownDays: 3, Now: now})
	if len(bs) != 1 || bs[0].Command != "pnpm up @nestjs/common@11.1.6 @nestjs/testing@11.1.6" {
		t.Fatalf("bundles %+v", bs)
	}
	for _, it := range bs[0].Items {
		if it.Pkg == "@nestjs/config" {
			t.Fatal("independently versioned package put into the lockstep group")
		}
	}
}

func TestBundleAlignedIsQuiet(t *testing.T) {
	f := newFake()
	f.versions["react"] = old("19.2.0")
	f.versions["react-dom"] = old("19.2.0")
	in := Input{Mgr: "npm", Lock: lock("npm",
		lockfile.Package{Name: "react", Version: "19.2.0", Direct: true},
		lockfile.Package{Name: "react-dom", Version: "19.2.0", Direct: true})}
	if bs := Bundles(context.Background(), NewData(f), in, nil, Options{CooldownDays: 3, Now: now}); len(bs) != 0 {
		t.Fatalf("aligned family reported: %+v", bs)
	}
}
