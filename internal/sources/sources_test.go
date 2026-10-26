package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixtures answers requests with files from testdata (see testdata/README.md).
type fixtures struct {
	t     *testing.T
	files map[string]string // URL (or "POST "+URL) → file; "" = 404; "!" = 500
	mu    sync.Mutex
	calls []call
}

type call struct {
	method, url string
	body        []byte
}

func (f *fixtures) Do(_ context.Context, method, u string, body []byte, _ map[string]string, _ time.Duration) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, call{method, u, body})
	f.mu.Unlock()
	name, ok := f.files[method+" "+u]
	if !ok {
		name, ok = f.files[u]
	}
	switch {
	case !ok:
		f.t.Fatalf("unexpected request %s %s", method, u)
	case name == "":
		return nil, ErrNotFound
	case name == "!":
		return nil, errors.New("HTTP 500")
	}
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		f.t.Fatal(err)
	}
	return b, nil
}

func (f *fixtures) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

var ctx = context.Background()

// ---------- OSV ----------

func TestOSVRecordFromGitHubAdvisoryDatabase(t *testing.T) {
	f := &fixtures{t: t, files: map[string]string{osvBase + "/vulns/GHSA-f82v-jwr5-mffw": "osv-GHSA-f82v-jwr5-mffw.json"}}
	o := NewOSV(f)
	v, err := o.Get(ctx, "GHSA-f82v-jwr5-mffw")
	if err != nil {
		t.Fatal(err)
	}
	if sev, score := v.SeverityLevel(); sev != "critical" || score != 9.1 {
		t.Errorf("severity %s %.1f, want critical 9.1", sev, score)
	}
	if c := v.CVEs(); len(c) != 1 || c[0] != "CVE-2025-29927" {
		t.Errorf("CVEs %v", c)
	}
	if len(v.DatabaseSpecific.CWEIDs) == 0 || v.Summary == "" || v.IsMalware() {
		t.Errorf("record %+v", v.DatabaseSpecific)
	}
	for ver, want := range map[string]string{"14.2.3": "14.2.25", "15.1.0": "15.2.3", "12.0.1": "12.3.5", "15.2.3": ""} {
		if got := v.FixedFor("next", ver); got != want {
			t.Errorf("FixedFor(next, %s) = %q, want %q", ver, got, want)
		}
	}
	if v.FixedFor("react", "14.2.3") != "" {
		t.Error("another package must not match")
	}
	if v.URL() != "https://github.com/advisories/GHSA-f82v-jwr5-mffw" {
		t.Errorf("URL %s", v.URL())
	}
	if _, err := o.Get(ctx, "GHSA-f82v-jwr5-mffw"); err != nil || f.count() != 1 {
		t.Errorf("second Get must come from memory (calls %d)", f.count())
	}
}

func TestOSVBatchAndQuery(t *testing.T) {
	f := &fixtures{t: t, files: map[string]string{"POST " + osvBase + "/querybatch": "osv-querybatch.json", "POST " + osvBase + "/query": "osv-query.json"}}
	o := NewOSV(f)
	ids, err := o.Batch(ctx, []Query{{"next", "14.2.3"}, {"left-pad", "1.3.0"}, {"evil", "1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 3 || len(ids[0]) != 2 || ids[0][0] != "GHSA-f82v-jwr5-mffw" || len(ids[1]) != 0 || ids[2][0] != "MAL-2025-46966" {
		t.Fatalf("batch ids %v", ids)
	}
	var req osvBatchReq
	_ = json.Unmarshal(f.calls[0].body, &req)
	if len(req.Queries) != 3 || req.Queries[0].Package.Ecosystem != "npm" || req.Queries[0].Package.Name != "next" || req.Queries[0].Version != "14.2.3" {
		t.Fatalf("batch request %s", f.calls[0].body)
	}
	// more than 1000 packages: split into requests of 1000
	big := make([]Query, 1500)
	for i := range big {
		big[i] = Query{fmt.Sprint("p", i), "1.0.0"}
	}
	before := f.count()
	if _, err := o.Batch(ctx, big); err != nil || f.count()-before != 2 {
		t.Fatalf("1500 queries: %v, %d requests", err, f.count()-before)
	}

	got, err := o.Query(ctx, "Go", "github.com/caddyserver/caddy/v2", "2.7.6")
	if err != nil || len(got) != 2 || got[1] != "GO-2025-3412" {
		t.Fatalf("query %v %v", got, err)
	}
	if !strings.Contains(string(f.calls[len(f.calls)-1].body), `"ecosystem":"Go"`) {
		t.Fatalf("query body %s", f.calls[len(f.calls)-1].body)
	}
}

func TestOSVBadAnswers(t *testing.T) {
	f := &fixtures{t: t, files: map[string]string{"POST " + osvBase + "/querybatch": "npm-express-4.19.2.json", "POST " + osvBase + "/query": "!"}}
	o := NewOSV(f)
	if ids, err := o.Batch(ctx, []Query{{"x", "1.0.0"}}); err == nil && len(ids[0]) != 0 {
		t.Fatal("a non-OSV answer must not produce findings")
	}
	if _, err := o.Query(ctx, "npm", "x", "1"); err == nil {
		t.Fatal("a server error must be reported, not hidden")
	}
}

func TestSeverityLevel(t *testing.T) {
	mk := func(db, vector, id string) *Vuln {
		v := &Vuln{ID: id}
		v.DatabaseSpecific.Severity = db
		if vector != "" {
			v.Severity = []osvSev{{Type: "CVSS_V3", Score: vector}}
		}
		return v
	}
	for _, c := range []struct {
		v    *Vuln
		want string
	}{
		{mk("MEDIUM", "", "GHSA-1"), "moderate"},
		{mk("", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "GHSA-2"), "high"}, // 7.5
		{mk("", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "GHSA-3"), "critical"},
		{mk("", "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "GHSA-4"), "low"},
		{mk("", "", "GHSA-5"), "moderate"},     // unknown: shown, not hidden
		{mk("", "", "MAL-2025-1"), "critical"}, // malware
	} {
		if got, _ := c.v.SeverityLevel(); got != c.want {
			t.Errorf("%s: %s, want %s", c.v.ID, got, c.want)
		}
	}
}

func TestCVSS3Base(t *testing.T) {
	for vec, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N": 9.1,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L": 5.0,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H": 9.1,
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	} {
		got, ok := CVSS3Base(vec)
		if !ok || got != want {
			t.Errorf("%s = %.1f %v, want %.1f", vec, got, ok, want)
		}
	}
	for _, bad := range []string{"", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CVSS:3.1/AV:N/AC:L", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"} {
		if _, ok := CVSS3Base(bad); ok {
			t.Errorf("%q must not parse", bad)
		}
	}
}

// ---------- npm advisories (what npm audit uses) ----------

func TestNpmBulkAdvisories(t *testing.T) {
	f := &fixtures{t: t, files: map[string]string{"POST " + npmBulkURL: "npm-bulk.json"}}
	got, err := NpmBulk(ctx, f, map[string][]string{"express": {"4.19.2"}, "next": {"14.2.3"}, "flatmap-stream": {"0.1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	ex := got["express"]
	if len(ex) != 1 || ex[0].GHSA() != "GHSA-qw6h-vgh9-j6wx" || ex[0].Severity != "low" || ex[0].VulnerableVersions != "<4.20.0" || ex[0].Malicious() {
		t.Fatalf("express %+v", ex)
	}
	if len(got["next"]) < 10 {
		t.Fatalf("next: %d advisories", len(got["next"]))
	}
	mal := got["flatmap-stream"]
	if len(mal) == 0 || !mal[0].Malicious() {
		t.Fatalf("flatmap-stream must be malware: %+v", mal)
	}
	v := FromNpm("express", ex[0])
	if v.ID != "GHSA-qw6h-vgh9-j6wx" || v.NpmRange != "<4.20.0" || v.From != "npm" || v.Affected[0].Package.Name != "express" {
		t.Fatalf("FromNpm %+v", v)
	}
	if sev, score := v.SeverityLevel(); sev != "low" || score != 5.0 {
		t.Errorf("express severity %s %.1f", sev, score)
	}
	if m := FromNpm("flatmap-stream", mal[0]); !m.IsMalware() {
		t.Error("malware lost in FromNpm")
	}
	var body map[string][]string
	_ = json.Unmarshal(f.calls[0].body, &body)
	if body["express"][0] != "4.19.2" {
		t.Fatalf("request %s", f.calls[0].body)
	}
	// more than 500 packages: several requests
	pk := map[string][]string{}
	for i := 0; i < 1001; i++ {
		pk[fmt.Sprint("p", i)] = []string{"1.0.0"}
	}
	before := f.count()
	if _, err := NpmBulk(ctx, f, pk); err != nil || f.count()-before != 3 {
		t.Fatalf("1001 packages: %v, %d requests", err, f.count()-before)
	}
}

// ---------- npm registry and deps.dev ----------

func TestRegistryManifests(t *testing.T) {
	f := &fixtures{t: t, files: map[string]string{
		"https://registry.npmjs.org/express/4.19.2":  "npm-express-4.19.2.json",
		"https://registry.npmjs.org/esbuild/0.25.0":  "npm-esbuild-0.25.0.json",
		"https://registry.npmjs.org/zod/4.1.12":      "npm-zod-4.1.12.json",
		"https://registry.npmjs.org/@types%2Fnode/x": "", // the registry accepts the encoded scope
	}}
	ex, err := Version(ctx, f, "express", "4.19.2")
	if err != nil {
		t.Fatal(err)
	}
	if ex.Name != "express" || ex.Description == "" || len(ex.InstallScripts()) != 0 || ex.HasProvenance() || ex.Engines["node"] == "" || !strings.Contains(ex.RepoURL(), "expressjs/express") || len(ex.Deps) == 0 {
		t.Fatalf("express %+v", ex)
	}
	es, _ := Version(ctx, f, "esbuild", "0.25.0")
	if s := es.InstallScripts(); len(s) != 1 || s[0] != "postinstall" {
		t.Fatalf("esbuild install scripts %v", s)
	}
	if z, _ := Version(ctx, f, "zod", "4.1.12"); !z.HasProvenance() {
		t.Fatal("zod 4.1.12 has npm provenance")
	}
	if _, err := Version(ctx, f, "@types/node", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("scoped name / 404: %v", err)
	}
}

func TestPackageVersions(t *testing.T) {
	dd := "https://api.deps.dev/v3/systems/npm/packages/left-pad"
	f := &fixtures{t: t, files: map[string]string{dd: "depsdev-left-pad.json"}}
	pi, err := Package(ctx, f, "left-pad")
	if err != nil {
		t.Fatal(err)
	}
	if pi.Default != "1.3.0" || len(pi.Versions) != 2 || !pi.Versions[1].Deprecated || pi.Versions[1].Reason == "" || pi.Versions[1].Published.Year() != 2018 {
		t.Fatalf("deps.dev %+v", pi)
	}
	// deps.dev down: the npm registry answers (no publish dates)
	f.files[dd] = "!"
	f.files["https://registry.npmjs.org/left-pad"] = "npm-packument-left-pad.json"
	pi, err = Package(ctx, f, "left-pad")
	if err != nil || pi.Default != "1.3.0" || len(pi.Versions) < 10 || !pi.Versions[0].Deprecated || !pi.Versions[0].Published.IsZero() {
		t.Fatalf("fallback %+v %v", pi, err)
	}
	// an unknown package is not looked up elsewhere
	f.files[dd] = ""
	if _, err := Package(ctx, f, "left-pad"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404: %v", err)
	}
}

// ---------- endoflife.date, Node.js, CISA KEV, EPSS ----------

func TestEndOfLife(t *testing.T) {
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	f := &fixtures{t: t, files: map[string]string{
		eolAPI + "v1/products/nodejs/":     "eol-v1-nodejs.json",
		eolAPI + "v1/products/postgresql/": "",
		eolAPI + "postgresql.json":         "eol-v0-postgresql.json",
	}}
	cs, err := Cycles(ctx, f, "nodejs")
	if err != nil || len(cs) != 2 {
		t.Fatalf("nodejs %v %v", cs, err)
	}
	if c := cs[0]; c.Name != "24" || c.Code != "krypton" || !c.LTS || c.Latest != "24.11.0" || c.EOL.Year() != 2028 || c.Ended(now) {
		t.Errorf("24: %+v", c)
	}
	if !cs[1].Ended(now) {
		t.Error("18 has ended")
	}
	cs, err = Cycles(ctx, f, "postgresql") // v1 missing: the original API
	if err != nil || len(cs) != 3 {
		t.Fatalf("postgresql %v %v", cs, err)
	}
	if cs[0].Ended(now) || !cs[1].Ended(now) || cs[1].Latest != "12.22" || cs[2].Code != "bookworm" || !cs[2].LTS || cs[2].Ended(now) {
		t.Errorf("postgresql %+v", cs)
	}
}

func TestNodeReleases(t *testing.T) {
	f := &fixtures{t: t, files: map[string]string{
		"https://nodejs.org/dist/index.json":                                  "node-dist-index.json",
		"https://raw.githubusercontent.com/nodejs/Release/main/schedule.json": "node-schedule.json",
		nodeCoreURL: "node-core-index.json",
	}}
	nd, err := Node(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(nd.Releases) != 3 || nd.Releases[0].Codename() != "Krypton" || nd.Releases[2].Codename() != "" || !nd.Releases[1].Security {
		t.Fatalf("releases %+v", nd.Releases)
	}
	if l, ok := nd.Schedule[22]; !ok || l.End == "" || l.Codename != "Jod" {
		t.Fatalf("schedule v22 %+v", l)
	}
	if len(nd.Core) != 3 || nd.Core[0].ID == "" || nd.Core[0].Vulnerable == "" || len(nd.Core[0].CVE) == 0 {
		t.Fatalf("core vulns %+v", nd.Core)
	}
	// the schedule and the core list are optional
	f.files["https://raw.githubusercontent.com/nodejs/Release/main/schedule.json"] = "!"
	f.files[nodeCoreURL] = "!"
	if nd, err := Node(ctx, f); err != nil || len(nd.Schedule) != 0 || nd.Core != nil {
		t.Fatalf("optional parts: %v", err)
	}
}

func TestKEVAndEPSS(t *testing.T) {
	kevURL := "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	f := &fixtures{t: t, files: map[string]string{kevURL: "kev.json"}}
	k, err := KEV(ctx, f)
	if err != nil || !k["CVE-2025-29927"] || !k["CVE-2021-44228"] || k["CVE-2000-0001"] {
		t.Fatalf("KEV %v %v", k, err)
	}
	cves := []string{"CVE-2025-29927", "CVE-2024-0001"}
	for i := 0; i < 150; i++ {
		cves = append(cves, fmt.Sprintf("CVE-2026-%04d", i))
	}
	f.files["https://api.first.org/data/v1/epss?cve="+strings.Join(cves[:100], ",")] = "epss.json"
	f.files["https://api.first.org/data/v1/epss?cve="+strings.Join(cves[100:], ",")] = "epss.json"
	e, err := EPSS(ctx, f, cves)
	if err != nil || e["CVE-2025-29927"] < 0.92 || e["CVE-2025-29927"] > 0.93 || e["CVE-2024-0001"] == 0 {
		t.Fatalf("EPSS %v %v", e, err)
	}
}
