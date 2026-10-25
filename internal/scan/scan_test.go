package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/decide"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/semver"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
	"github.com/Ali7Zeynalli/depgate/internal/sources/sourcestest"
)

var now = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

// Demo builds the fake network used by the end-to-end test (and the UI demo).
func Demo() *sourcestest.Fake {
	f := sourcestest.New(now)
	f.Match = func(v *sources.Vuln, name, ver string) bool {
		sv, err := semver.Parse(ver)
		return err == nil && decide.Affects(v, name, sv)
	}
	f.Vuln("GHSA-demo-next", "next", "HIGH", "14.0.0", "14.2.25", "Authorization bypass in Next.js middleware", "CVE-2025-29927")
	f.Vuln("GHSA-demo-follow", "follow-redirects", "MODERATE", "0", "1.15.9", "follow-redirects leaks Proxy-Authorization header", "CVE-2024-28849")
	f.Vuln("GHSA-demo-semver", "semver", "HIGH", "7.0.0", "7.6.3", "semver ReDoS in range parsing")
	f.Versions["semver"] = sourcestest.Old("6.3.1", "7.6.0", "7.6.3", "7.7.2")
	f.Vuln("GHSA-demo-express", "express", "MODERATE", "0", "5.0.0", "express open redirect (fixed only in 5.x)", "CVE-2024-29041")
	f.Malware("MAL-2026-demo", "debug", "4.3.4")
	f.EPSS["CVE-2025-29927"] = 0.92
	f.KEV = []string{"CVE-2025-29927"}
	f.Versions["next"] = append(sourcestest.Old("14.2.3", "14.2.24", "14.2.25", "15.5.6"), sourcestest.Version{V: "14.2.26", Age: 6 * time.Hour})
	f.Versions["follow-redirects"] = sourcestest.Old("1.15.6", "1.15.9", "1.15.11")
	f.Versions["express"] = sourcestest.Old("4.19.2", "4.21.2", "5.0.0", "5.1.0")
	f.Versions["debug"] = sourcestest.Old("4.3.3", "4.3.4", "4.4.1")
	f.Versions["axios"] = sourcestest.Old("1.6.8", "1.12.2")
	f.Versions["react"] = sourcestest.Old("18.2.0", "18.3.1", "19.2.0")
	f.Versions["react-dom"] = sourcestest.Old("18.2.0", "18.3.1", "19.2.0")
	f.Versions["typescript"] = sourcestest.Old("5.4.5", "5.9.3")
	f.Versions["make-dir"] = sourcestest.Old("3.1.0", "4.0.0", "5.1.0")
	f.Versions["lodash"] = sourcestest.Old("4.17.21")
	f.Versions["nodemon"] = sourcestest.Old("3.1.0", "3.1.10")
	f.Versions["@types/node"] = sourcestest.Old("20.12.7", "20.19.0", "24.0.0")
	f.Manifest["axios@1.6.8"] = map[string]any{"name": "axios", "version": "1.6.8", "dependencies": map[string]string{"follow-redirects": "^1.15.6"}}
	f.Manifest["express@5.0.0"] = map[string]any{"name": "express", "version": "5.0.0", "engines": map[string]string{"node": ">= 18"}}
	f.Node = []sources.NodeRelease{
		{Version: "v24.22.1", LTS: "Krypton", Security: true},
		{Version: "v22.23.4", LTS: "Jod", Security: true},
		{Version: "v22.20.0", LTS: "Jod"},
		{Version: "v20.19.9", LTS: "Iron"},
	}
	f.Schedule = map[string]sources.NodeLine{
		"v20": {LTS: "2023-10-24", End: "2026-04-30"},
		"v22": {LTS: "2024-10-29", End: "2027-04-30"},
		"v24": {LTS: "2025-10-28", End: "2028-04-30"},
	}
	return f
}

func copyFixture(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join("..", "..", "testdata", "lockfiles", name)
	dst := t.TempDir()
	for _, fn := range []string{"package.json", "package-lock.json"} {
		b, err := os.ReadFile(filepath.Join(src, fn))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, fn), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(dst, "Dockerfile"), []byte("FROM node:22.20.0-bookworm-slim\n"), 0o644)
	return dst
}

func TestEndToEnd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := copyFixture(t, "npm-v3")
	rep := Run(context.Background(), Demo(), []string{dir}, Options{Version: "test", Now: now})
	if len(rep.Errors) > 0 {
		t.Fatalf("errors: %v", rep.Errors)
	}
	p := rep.Projects[0]
	by := map[string]report.Finding{}
	for _, f := range p.Findings {
		by[f.Pkg+"@"+f.Current] = f
	}
	check := func(key, kind string, group report.Group, target string) report.Finding {
		t.Helper()
		f, ok := by[key]
		if !ok {
			t.Fatalf("%s missing; have %v", key, keys(by))
		}
		if f.Kind != kind || f.Group != group || f.Target != target {
			t.Fatalf("%s: kind=%s group=%s target=%s (want %s %s %s) why=%v", key, f.Kind, f.Group, f.Target, kind, group, target, f.Why)
		}
		return f
	}
	n := check("next@14.2.3", "vuln", report.GroupNowEasy, "14.2.25")
	if n.Priority != 35+25+14 { // high + KEV + EPSS 0.92*15
		t.Fatalf("next priority %d", n.Priority)
	}
	fr := check("follow-redirects@1.15.6", "vuln", report.GroupNowEasy, "1.15.9")
	if fr.Fix.Strategy != "relock" {
		t.Fatalf("follow-redirects fix %+v", fr.Fix)
	}
	check("semver@7.6.0", "vuln", report.GroupNowEasy, "7.6.3")
	ex := check("express@4.19.2", "vuln", report.GroupNowCode, "5.0.0")
	if ex.Impact != report.ImpactYes {
		t.Fatalf("express impact %s", ex.Impact)
	}
	mal := check("debug@4.3.4", "malware", report.GroupNowEasy, "4.3.3")
	if strings.Join(mal.Chain, ">") != "nodemon>debug" {
		t.Fatalf("debug chain %v", mal.Chain)
	}
	if mal.Direct || mal.Fix.Strategy != "override" || mal.Priority != 100 {
		t.Fatalf("debug %+v", mal)
	}
	check("react@18.2.0", "update", report.GroupOptional, "18.3.1")
	check("lodash@4.17.21", "current", report.GroupOK, "")
	check("make-dir@3.1.0", "update", report.GroupPlan, "5.1.0")

	if p.Node == nil || p.Node.Need != report.NeedNow || p.Node.SecurityFix != "22.23.4" {
		t.Fatalf("node %+v", p.Node)
	}
	if p.Summary.Malware != 1 || p.Summary.NowCode != 1 {
		t.Fatalf("summary %+v", p.Summary)
	}
	// JSON contract
	b, _ := json.Marshal(rep)
	var back map[string]any
	_ = json.Unmarshal(b, &back)
	if back["schema"] != "depgate/report@1" {
		t.Fatalf("schema %v", back["schema"])
	}
	if os.Getenv("DEPGATE_DEMO_OUT") != "" {
		_ = os.WriteFile(os.Getenv("DEPGATE_DEMO_OUT"), b, 0o644)
	}
}

func keys(m map[string]report.Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Every human-facing sentence must exist in both languages.
func TestBilingual(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	rep := Run(context.Background(), Demo(), []string{copyFixture(t, "npm-v3")}, Options{Version: "test", Now: now})
	b, _ := json.Marshal(rep)
	var v any
	_ = json.Unmarshal(b, &v)
	n := 0
	var walk func(x any, path string)
	walk = func(x any, path string) {
		switch m := x.(type) {
		case map[string]any:
			az, okA := m["az"]
			en, okE := m["en"]
			if okA || okE {
				if (az == "") != (en == "") {
					t.Errorf("%s: one language missing: az=%q en=%q", path, az, en)
				}
				if az != "" && az == en {
					t.Errorf("%s: not translated: %q", path, az)
				}
				n++
				return
			}
			for k, c := range m {
				walk(c, path+"."+k)
			}
		case []any:
			for i, c := range m {
				walk(c, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	walk(v, "report")
	if n < 20 {
		t.Fatalf("only %d bilingual sentences found", n)
	}
}

func TestSourcesRecorded(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	rep := Run(context.Background(), Demo(), []string{copyFixture(t, "npm-v3")}, Options{Version: "test", Now: now})
	if len(rep.Sources) != 7 || len(rep.Projects[0].Sources) != 7 {
		t.Fatalf("sources %+v", rep.Sources)
	}
	used := map[string]int{}
	for _, s := range rep.Sources {
		used[s.ID] = s.Requests
		if s.Name == "" || s.URL == "" || s.Use.Az == "" || s.Use.En == "" {
			t.Fatalf("incomplete source %+v", s)
		}
	}
	for _, id := range []string{"osv", "npmaudit", "node", "kev", "depsdev"} {
		if used[id] == 0 {
			t.Errorf("%s not recorded: %v", id, used)
		}
	}
}
