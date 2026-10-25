package scan

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/sources"
)

// TestCompareNpmAudit checks DepGate against `npm audit` on a project with
// known-vulnerable dependencies, using the real network. Every advisory npm
// audit reports must also be in DepGate's report; extra ones (from OSV) are
// listed. Run with:
//
//	DEPGATE_LIVE=1 go test -run TestCompareNpmAudit -v ./internal/scan
func TestCompareNpmAudit(t *testing.T) {
	if os.Getenv("DEPGATE_LIVE") == "" {
		t.Skip("set DEPGATE_LIVE=1 (needs network and npm)")
	}
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not installed")
	}
	dir := t.TempDir()
	pkg := `{"name":"depgate-live","version":"1.0.0","private":true,"dependencies":{
	  "lodash":"4.17.15","minimist":"1.2.5","axios":"0.21.1","node-fetch":"2.6.0","express":"4.17.1",
	  "jsonwebtoken":"8.5.1","ws":"7.4.5","semver":"5.7.1","handlebars":"4.7.6","marked":"0.3.19"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0o644); err != nil {
		t.Fatal(err)
	}
	npm := func(args ...string) []byte {
		cmd := exec.Command("npm", args...)
		cmd.Dir = dir
		out, _ := cmd.Output() // npm audit exits 1 when it finds something
		return out
	}
	npm("install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund")
	if _, err := os.Stat(filepath.Join(dir, "package-lock.json")); err != nil {
		t.Fatal("npm could not create the lockfile")
	}
	var audit struct {
		Vulnerabilities map[string]struct {
			Via []json.RawMessage `json:"via"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(npm("audit", "--json"), &audit); err != nil {
		t.Fatalf("npm audit: %v", err)
	}
	want := map[string]bool{} // pkg GHSA
	for name, v := range audit.Vulnerabilities {
		for _, raw := range v.Via {
			var via struct{ URL string }
			if json.Unmarshal(raw, &via) == nil && strings.Contains(via.URL, "/GHSA-") {
				want[name+" "+via.URL[strings.LastIndex(via.URL, "/")+1:]] = true
			}
		}
	}
	if len(want) == 0 {
		t.Fatal("npm audit found nothing — test project is wrong")
	}

	rep := Run(context.Background(), sources.NewHTTP(t.TempDir(), false, "test"), []string{dir}, Options{Version: "test", Now: time.Now()})
	got := map[string]bool{}
	for _, f := range rep.Projects[0].Findings {
		for _, a := range f.Advisories {
			got[f.Pkg+" "+a.ID] = true
			for _, al := range a.Aliases {
				got[f.Pkg+" "+al] = true
			}
		}
	}
	var missing, extra []string
	for k := range want {
		if !got[k] {
			missing = append(missing, k)
		}
	}
	for _, f := range rep.Projects[0].Findings {
		for _, a := range f.Advisories {
			k := f.Pkg + " " + a.ID
			hit := want[k]
			for _, al := range a.Aliases {
				hit = hit || want[f.Pkg+" "+al]
			}
			if !hit {
				extra = append(extra, k)
			}
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	t.Logf("npm audit: %d advisories · DepGate: %d matched, %d missing, %d extra (OSV-only)", len(want), len(want)-len(missing), len(missing), len(extra))
	for _, e := range extra {
		t.Logf("  extra: %s", e)
	}
	errs := append(append([]string{}, rep.Errors...), rep.Projects[0].Errors...)
	osvDown := false
	for _, e := range errs {
		t.Logf("  source error: %s", e)
		osvDown = osvDown || strings.HasPrefix(e, "OSV")
	}
	// the same scan without the npm advisory endpoint: how much does OSV alone see?
	osvOnly := Run(context.Background(), noNpm{sources.NewHTTP(t.TempDir(), false, "test")}, []string{dir}, Options{Version: "test", Now: time.Now()})
	seen := 0
	for k := range want {
		pkg, id, _ := strings.Cut(k, " ")
		for _, f := range osvOnly.Projects[0].Findings {
			for _, a := range f.Advisories {
				if f.Pkg == pkg && (a.ID == id || contains(a.Aliases, id)) {
					seen++
				}
			}
		}
	}
	t.Logf("OSV alone: %d of %d", seen, len(want))
	if osvDown {
		t.Log("OSV unreachable — only the npm source was compared")
	} else if seen*10 < len(want)*9 {
		t.Errorf("OSV alone sees only %d of %d npm audit advisories", seen, len(want))
	}
	for _, m := range missing {
		t.Errorf("missing (npm audit has it, DepGate does not): %s", m)
	}
}

type noNpm struct{ sources.Fetcher }

func (n noNpm) Do(ctx context.Context, method, u string, body []byte, h map[string]string, ttl time.Duration) ([]byte, error) {
	if strings.Contains(u, "/security/advisories/bulk") {
		return nil, context.Canceled
	}
	return n.Fetcher.Do(ctx, method, u, body, h, ttl)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
