package decide

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/semver"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
)

// PackageCheck answers "is it safe to add this package to this project?" —
// asked by an AI agent before `npm install`. Texts are English (agents read them).
type PackageCheck struct {
	Pkg        string     `json:"package"`
	Requested  string     `json:"requested,omitempty"` // as asked: exact, range or empty
	Version    string     `json:"version"`             // the version that was checked
	Latest     string     `json:"latest,omitempty"`
	Verdict    string     `json:"verdict"` // ok | caution | block
	Reasons    []string   `json:"reasons"`
	Advisories []CheckAdv `json:"advisories,omitempty"`
	Suggest    string     `json:"suggest,omitempty"` // safest version to install instead (or the same)
	Published  string     `json:"published,omitempty"`
	Scripts    []string   `json:"installScripts,omitempty"`
	Provenance bool       `json:"provenance"`
	Engines    string     `json:"enginesNode,omitempty"`
	Deprecated string     `json:"deprecated,omitempty"`
}

type CheckAdv struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
	URL      string `json:"url,omitempty"`
	Malware  bool   `json:"malware,omitempty"`
}

// CheckInput is what the project already has: its Node version and direct packages.
type CheckInput struct {
	NodeVersion string
	Direct      map[string]string // name -> installed version
}

// CheckPackage checks name@version (version may be empty = latest, or a range).
func CheckPackage(ctx context.Context, d *Data, name, version string, in CheckInput, opt Options) (*PackageCheck, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("package name is required")
	}
	pc := &PackageCheck{Pkg: name, Requested: version, Verdict: "ok", Reasons: []string{}}
	info, err := d.Pkg(ctx, name)
	if err != nil {
		if errors.Is(err, sources.ErrNotFound) {
			pc.Verdict = "block"
			pc.Reasons = append(pc.Reasons, "This package does not exist on the npm registry — check the name (typosquatting is a common attack).")
			return pc, nil
		}
		return nil, err
	}
	pc.Latest = info.Default
	if isHolder(info) {
		pc.Version = info.Default
		pc.Verdict = "block"
		pc.Reasons = append(pc.Reasons, "npm took this package down for security reasons and replaced it with a 0.0.1-security placeholder — it was malicious. Do not install it; if the name is a typo of a real package, use the real one.")
		return pc, nil
	}
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	cooldown := time.Duration(opt.CooldownDays) * 24 * time.Hour

	// resolve the version
	v, err := resolve(info, version)
	if err != nil {
		return nil, err
	}
	pc.Version = v.String()
	var pv *sources.PkgVersion
	for i := range info.Versions {
		if info.Versions[i].Version == pc.Version {
			pv = &info.Versions[i]
		}
	}

	vulns := checkVulns(ctx, d, name, v)
	for _, x := range vulns {
		s, _ := x.SeverityLevel()
		pc.Advisories = append(pc.Advisories, CheckAdv{ID: x.ID, Severity: s, Summary: clipText(firstLine(x.Summary, x.Details), 200), URL: x.URL(), Malware: x.IsMalware()})
	}
	malware := false
	for _, a := range pc.Advisories {
		malware = malware || a.Malware
	}
	block := func(r string) { pc.Verdict = "block"; pc.Reasons = append(pc.Reasons, r) }
	caution := func(r string) {
		if pc.Verdict == "ok" {
			pc.Verdict = "caution"
		}
		pc.Reasons = append(pc.Reasons, r)
	}
	switch {
	case malware:
		block(fmt.Sprintf("%s@%s is recorded as MALWARE — do not install it.", name, pc.Version))
	case len(vulns) > 0:
		top := "moderate"
		for _, a := range pc.Advisories {
			if sevRank[a.Severity] > sevRank[top] {
				top = a.Severity
			}
		}
		msg := fmt.Sprintf("%s@%s has %d known vulnerabilities (highest: %s).", name, pc.Version, len(vulns), top)
		if sevRank[top] >= sevRank["high"] {
			block(msg)
		} else {
			caution(msg)
		}
	}

	man, err := d.Manifest(ctx, name, pc.Version)
	if errors.Is(err, sources.ErrNotFound) {
		block(fmt.Sprintf("%s@%s is no longer served by npm (unpublished or taken down).", name, pc.Version))
	} else if err == nil {
		pc.Scripts = man.InstallScripts()
		pc.Provenance = man.HasProvenance()
		pc.Engines = man.Engines["node"]
		if len(pc.Scripts) > 0 {
			caution(fmt.Sprintf("Runs install scripts (%s) — most supply-chain attacks run there; keep ignore-scripts on unless it needs a native build.", strings.Join(pc.Scripts, ", ")))
		}
		if pc.Engines != "" && in.NodeVersion != "" {
			if r, err := semver.ParseRange(pc.Engines); err == nil {
				if nv, err := semver.Parse(in.NodeVersion); err == nil && !r.Contains(nv) {
					caution(fmt.Sprintf("Needs Node %s; the project uses Node %s.", pc.Engines, in.NodeVersion))
				}
			}
		}
		peers := make([]string, 0, len(man.Peer))
		for p := range man.Peer {
			peers = append(peers, p)
		}
		sort.Strings(peers)
		for _, p := range peers {
			have, ok := in.Direct[p]
			if !ok {
				continue
			}
			r, err1 := semver.ParseRange(man.Peer[p])
			hv, err2 := semver.Parse(have)
			if err1 == nil && err2 == nil && !r.Contains(hv) {
				caution(fmt.Sprintf("Peer conflict: needs %s %s, the project has %s.", p, man.Peer[p], have))
			}
		}
		if man.Deprecated != "" {
			pc.Deprecated = clipText(man.Deprecated, 200)
		}
	}
	if pv != nil {
		if !pv.Published.IsZero() {
			pc.Published = pv.Published.UTC().Format(time.RFC3339)
			if age := opt.Now.Sub(pv.Published); age < cooldown {
				caution(fmt.Sprintf("Published %s ago — compromised releases are usually pulled within hours; prefer a version older than %d days.", age.Round(time.Hour), opt.CooldownDays))
			}
		}
		if pv.Deprecated && pc.Deprecated == "" {
			pc.Deprecated = clipText(pv.Reason, 200)
		}
	}
	if pc.Deprecated != "" {
		caution("Deprecated: " + pc.Deprecated)
	}

	// suggest the safest version: this one if clean, else the newest clean, mature version in its major, else overall
	if pc.Verdict == "ok" {
		pc.Suggest = pc.Version
	} else {
		pc.Suggest = safest(ctx, d, info, v, opt.Now, cooldown)
		if pc.Suggest != "" && pc.Suggest != pc.Version {
			pc.Reasons = append(pc.Reasons, fmt.Sprintf("Safer choice: %s@%s.", name, pc.Suggest))
		}
	}
	if len(pc.Reasons) == 0 {
		pc.Reasons = append(pc.Reasons, "No known vulnerabilities or malware; published long enough ago; no install scripts.")
	}
	return pc, nil
}

func resolve(info *sources.PkgInfo, req string) (semver.Version, error) {
	req = strings.TrimSpace(req)
	if req == "" || req == "latest" {
		if info.Default == "" {
			return semver.Version{}, errors.New("no latest version")
		}
		return semver.Parse(info.Default)
	}
	if v, err := semver.Parse(req); err == nil {
		return v, nil
	}
	r, err := semver.ParseRange(req)
	if err != nil {
		return semver.Version{}, fmt.Errorf("not a version or range: %s", req)
	}
	var vs []semver.Version
	for _, pv := range info.Versions {
		if v, err := semver.Parse(pv.Version); err == nil {
			vs = append(vs, v)
		}
	}
	v, ok := semver.MaxSatisfying(vs, r)
	if !ok {
		return semver.Version{}, fmt.Errorf("no published version matches %s", req)
	}
	return v, nil
}

// checkVulns asks OSV and the npm advisory endpoint about one version.
func checkVulns(ctx context.Context, d *Data, name string, v semver.Version) []*sources.Vuln {
	var out []*sources.Vuln
	if ids, err := d.OSV.Batch(ctx, []sources.Query{{Name: name, Version: v.String()}}); err == nil && len(ids) > 0 {
		for _, id := range ids[0] {
			if x, err := d.OSV.Get(ctx, id); err == nil && x.Withdrawn == "" {
				out = append(out, x)
			}
		}
	}
	if adv, err := sources.NpmBulk(ctx, d.F, map[string][]string{name: {v.String()}}); err == nil {
		for _, a := range adv[name] {
			x := sources.FromNpm(name, a)
			if Affects(x, name, v) && !knownVuln(out, x) {
				out = append(out, x)
			}
		}
	}
	return out
}

func safest(ctx context.Context, d *Data, info *sources.PkgInfo, from semver.Version, now time.Time, cooldown time.Duration) string {
	var cands []semver.Version
	for _, pv := range info.Versions {
		v, err := semver.Parse(pv.Version)
		if err != nil || v.IsPrerelease() || pv.Deprecated || (!pv.Published.IsZero() && now.Sub(pv.Published) < cooldown) {
			continue
		}
		cands = append(cands, v)
	}
	// newest first: same major as asked, then any
	sort.Slice(cands, func(i, j int) bool { return semver.Less(cands[j], cands[i]) })
	for pass := 0; pass < 2; pass++ {
		tried := 0
		for _, v := range cands {
			if pass == 0 && v.Major != from.Major {
				continue
			}
			if tried++; tried > 8 {
				break
			}
			if len(checkVulns(ctx, d, info.Name, v)) > 0 {
				continue
			}
			if _, err := d.Manifest(ctx, info.Name, v.String()); err != nil {
				continue
			}
			return v.String()
		}
	}
	return ""
}

func clipText(s string, n int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s))
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

// isHolder reports a package npm replaced with a security placeholder.
func isHolder(info *sources.PkgInfo) bool {
	if strings.HasSuffix(info.Default, "-security") {
		return true
	}
	if len(info.Versions) == 0 {
		return false
	}
	for _, v := range info.Versions {
		if !strings.HasSuffix(v.Version, "-security") {
			return false
		}
	}
	return true
}
