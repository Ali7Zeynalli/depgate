package decide

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/semver"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
)

var sevRank = map[string]int{"low": 1, "moderate": 2, "high": 3, "critical": 4}
var rankSev = map[int]string{1: "low", 2: "moderate", 3: "high", 4: "critical"}

// Affects reports whether OSV record v marks name@ver as affected.
func Affects(v *sources.Vuln, name string, ver semver.Version) bool {
	if v.NpmRange != "" {
		r, err := semver.ParseRange(v.NpmRange)
		return err == nil && v.Affected[0].Package.Name == name && r.ContainsAll(ver)
	}
	for _, a := range v.Affected {
		if a.Package.Name != name || !strings.EqualFold(a.Package.Ecosystem, "npm") {
			continue
		}
		vs := ver.String()
		for _, x := range a.Versions {
			if x == vs {
				return true
			}
		}
		for _, r := range a.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			var lo *semver.Version
			open := false
			for _, e := range r.Events {
				switch {
				case e.Introduced != "":
					open = true
					lo = nil
					if e.Introduced != "0" {
						if p, err := semver.Parse(e.Introduced); err == nil {
							lo = &p
						}
					}
				case e.Fixed != "" && open:
					if f, err := semver.Parse(e.Fixed); err == nil {
						if (lo == nil || semver.Compare(ver, *lo) >= 0) && semver.Less(ver, f) {
							return true
						}
					}
					open = false
				case e.LastAffected != "" && open:
					if f, err := semver.Parse(e.LastAffected); err == nil {
						if (lo == nil || semver.Compare(ver, *lo) >= 0) && semver.Compare(ver, f) <= 0 {
							return true
						}
					}
					open = false
				}
			}
			if open && (lo == nil || semver.Compare(ver, *lo) >= 0) {
				return true
			}
		}
	}
	return false
}

// fixedAbove returns the lowest "fixed" event above cur across the records (fallback when the version list is unavailable).
func fixedAbove(vs []*sources.Vuln, name string, cur semver.Version) (semver.Version, bool) {
	var best semver.Version
	found := false
	for _, v := range vs {
		var mine semver.Version
		ok := false
		for _, a := range v.Affected {
			if a.Package.Name != name {
				continue
			}
			for _, r := range a.Ranges {
				for _, e := range r.Events {
					if e.Fixed == "" {
						continue
					}
					f, err := semver.Parse(e.Fixed)
					if err != nil || !semver.Less(cur, f) {
						continue
					}
					if !ok || semver.Less(f, mine) {
						mine, ok = f, true
					}
				}
			}
		}
		if !ok {
			return semver.Version{}, false // one record has no fix: nothing fixes all
		}
		if !found || semver.Less(best, mine) {
			best, found = mine, true
		}
	}
	return best, found
}

type cand struct {
	v   semver.Version
	pub time.Time
	dep bool
}

func candidates(info *sources.PkgInfo, cur semver.Version) []cand {
	var out []cand
	if info == nil {
		return nil
	}
	for _, pv := range info.Versions {
		v, err := semver.Parse(pv.Version)
		if err != nil || (v.IsPrerelease() && !cur.IsPrerelease()) {
			continue
		}
		out = append(out, cand{v: v, pub: pv.Published, dep: pv.Deprecated})
	}
	sort.Slice(out, func(i, j int) bool { return semver.Less(out[i].v, out[j].v) })
	return out
}

// pickSafe chooses the safest minimum: the lowest clean version above cur,
// same major (caret semantics) first, older than the cooldown first.
// young reports that the pick is inside the cooldown window.
func pickSafe(cs []cand, cur semver.Version, clean func(semver.Version) bool, cooldown time.Duration, now time.Time) (pick cand, sameMajor, young, ok bool) {
	var pool []cand
	for _, c := range cs {
		if semver.Less(cur, c.v) && clean(c.v) {
			pool = append(pool, c)
		}
	}
	if len(pool) == 0 {
		return cand{}, false, false, false
	}
	mature := func(c cand) bool { return c.pub.IsZero() || now.Sub(c.pub) >= cooldown }
	try := func(f func(cand) bool) (cand, bool) {
		for _, c := range pool { // ascending: first match is the lowest
			if f(c) {
				return c, true
			}
		}
		return cand{}, false
	}
	same := func(c cand) bool { return semver.Diff(cur, c.v) != "major" }
	if c, ok := try(func(c cand) bool { return same(c) && mature(c) && !c.dep }); ok {
		return c, true, false, true
	}
	if c, ok := try(func(c cand) bool { return same(c) && mature(c) }); ok {
		return c, true, false, true
	}
	if c, ok := try(same); ok {
		return c, true, true, true
	}
	if c, ok := try(func(c cand) bool { return mature(c) && !c.dep }); ok {
		return c, false, false, true
	}
	if c, ok := try(mature); ok {
		return c, false, false, true
	}
	c := pool[0]
	return c, false, true, true
}

func vulnFinding(ctx context.Context, d *Data, it *instance, in Input, g *graph, opt Options) (report.Finding, []string) {
	var errs []string
	name, cur := it.pkg.Name, it.ver
	f := report.Finding{
		Pkg: name, Direct: it.pkg.Direct, Dev: it.pkg.Dev, Current: cur.String(), Kind: "vuln",
	}
	if !it.pkg.Direct {
		f.Chain = g.chain(name, it.pkg.Parents)
	}
	cooldown := time.Duration(opt.CooldownDays) * 24 * time.Hour

	// advisories
	sev, malware, kev, epss, maxCVSS := 0, false, false, 0.0, 0.0
	var allMal = true
	for _, v := range it.vulns {
		s, score := v.SeverityLevel()
		a := report.Adv{ID: v.ID, Aliases: v.Aliases, Summary: firstLine(v.Summary, v.Details), Severity: s, CVSS: score, EPSS: d.epssOf(v), KEV: d.kevOf(v), URL: v.URL()}
		if fx, ok := fixedAbove([]*sources.Vuln{v}, name, cur); ok {
			a.Fixed = fx.String()
		}
		if v.IsMalware() {
			malware = true
			a.Severity = "critical"
		} else {
			allMal = false
		}
		f.Advisories = append(f.Advisories, a)
		if sevRank[a.Severity] > sev {
			sev = sevRank[a.Severity]
		}
		kev = kev || a.KEV
		if a.EPSS > epss {
			epss = a.EPSS
		}
		if score > maxCVSS {
			maxCVSS = score
		}
	}
	_ = allMal
	sort.Slice(f.Advisories, func(i, j int) bool { return sevRank[f.Advisories[i].Severity] > sevRank[f.Advisories[j].Severity] })
	f.Severity = rankSev[sev]
	f.Key = "vuln:" + name + "@" + f.Current
	if len(f.Advisories) > 0 {
		f.Title = f.Advisories[0].Summary
	}

	// candidate versions
	info, err := d.Pkg(ctx, name)
	if err != nil {
		errs = append(errs, err.Error())
	}
	cs := candidates(info, cur)
	if info != nil && info.Default != "" {
		f.Latest = info.Default
	}
	clean := func(v semver.Version) bool {
		for _, x := range it.vulns {
			if Affects(x, name, v) {
				return false
			}
		}
		return true
	}

	if malware {
		f.Kind = "malware"
		f.Key = "malware:" + name + "@" + f.Current
		f.Need, f.Priority, f.Severity = report.NeedNow, 100, "critical"
		src, mid := "OpenSSF/OSV", f.Advisories[0].ID
		for _, v := range it.vulns {
			if v.IsMalware() {
				mid = v.ID
				switch {
				case v.ID == HolderID:
					src = "npm registry"
				case v.From == "npm":
					src = "GitHub Advisory / npm"
				}
				break
			}
		}
		if mid == HolderID {
			f.Why = append(f.Why, i18n.F("npm bu paketi təhlükəsizlik səbəbi ilə silib və yerinə 0.0.1-security qoyub — quraşdırdığın versiya zərərli idi", "npm took this package down for security reasons and replaced it with 0.0.1-security — the version you installed was malicious"))
		} else {
			f.Why = append(f.Why, i18n.F("Bu versiya zərərli paket kimi qeydə alınıb (%s: %s)", "This version is recorded as a malicious package (%s: %s)", src, mid))
		}
		f.Why = append(f.Why, i18n.F("Dərhal: node_modules-u sil, npm/GitHub/bulud token-lərini və .env sirlərini dəyiş, CI loglarını yoxla", "Right now: delete node_modules, rotate npm/GitHub/cloud tokens and .env secrets, review CI logs"))
		// clean version: highest clean below, else lowest clean above
		var below *cand
		for i := range cs {
			c := cs[i]
			if semver.Less(c.v, cur) && clean(c.v) && (below == nil || semver.Less(below.v, c.v)) {
				below = &c
			}
		}
		switch {
		case below != nil:
			f.Target = below.v.String()
			f.Fix = &report.Fix{Strategy: "upgrade", Command: installCmd(in.Mgr, name, f.Target, it.pkg.Dev, it.pkg.Direct)}
			f.Impact = impactOfDiff(cur, below.v)
			f.ImpactWhy = append(f.ImpactWhy, i18n.F("Əvvəlki təmiz versiyaya qayıt: %s", "Go back to the previous clean version: %s", f.Target))
		default:
			if p, _, _, ok := pickSafe(cs, cur, clean, cooldown, opt.Now); ok {
				f.Target = p.v.String()
				f.Fix = &report.Fix{Strategy: "upgrade", Command: installCmd(in.Mgr, name, f.Target, it.pkg.Dev, it.pkg.Direct)}
				f.Impact = impactOfDiff(cur, p.v)
			} else {
				f.Fix = &report.Fix{Strategy: "remove", Command: removeCmd(in.Mgr, name), Note: i18n.F("Paketin bütün versiyaları zərərlidir — sil və alternativ tap", "Every version of this package is malicious — remove it and find an alternative")}
				f.Impact = report.ImpactYes
				f.ImpactWhy = append(f.ImpactWhy, i18n.F("Paket tamamilə silinməlidir: onu istifadə edən kodu dəyiş", "The package must be removed: change the code that uses it"))
			}
		}
		if !it.pkg.Direct {
			f.Fix = overrideFix(in.Mgr, name, f.Target)
			if f.Target == "" {
				f.Fix.Note = i18n.F("Zərərli paketi gətirən valideyni (%s) sil və ya dəyiş", "Remove or replace the parent that pulls in the malicious package (%s)", f.Chain[0])
			}
		}
		f.Group = groupOf(f.Need, f.Impact)
		return f, errs
	}

	// severity adjustments
	effSev := sev
	if it.pkg.Dev && effSev > 1 {
		effSev--
		f.Why = append(f.Why, i18n.F("Yalnız devDependencies-dədir (build/test) — production-a getmir, severity bir pillə aşağı salındı", "Only in devDependencies (build/test) — not shipped to production, severity lowered one step"))
	}
	if effSev >= 3 {
		f.Need = report.NeedNow
	} else {
		f.Need = report.NeedSoon
	}
	top := f.Advisories[0]
	f.Why = append([]i18n.T{i18n.F("%s boşluq: %s", "%s vulnerability: %s", top.Severity, top.ID)}, f.Why...)
	if len(f.Advisories) > 1 {
		f.Why = append(f.Why, i18n.F("Cəmi %d advisory bu versiyaya aiddir", "%d advisories affect this version", len(f.Advisories)))
	}
	if kev {
		f.Why = append(f.Why, i18n.F("CISA KEV: real hücumlarda istifadə olunur", "CISA KEV: exploited in real attacks"))
	}
	if epss >= 0.01 {
		f.Why = append(f.Why, i18n.F("EPSS %s: yaxın 30 gündə istismar ehtimalı", "EPSS %s: probability of exploitation in the next 30 days", pct(epss)))
	}
	f.Priority = priority(sev, kev, epss, it.pkg.Dev, in.Lock.Approximate)

	// target
	var target semver.Version
	var haveTarget, sameMajor, young bool
	if p, sm, yg, ok := pickSafe(cs, cur, clean, cooldown, opt.Now); ok {
		target, sameMajor, young, haveTarget = p.v, sm, yg, true
		if yg && !p.pub.IsZero() {
			h := int(opt.Now.Sub(p.pub).Hours())
			f.Warnings = append(f.Warnings, i18n.F("%s cəmi %d saat əvvəl çıxıb (gözləmə müddəti %d gün) — təcili deyilsə bir neçə gün gözlə", "%s was published only %d hours ago (cooldown %d days) — unless urgent, wait a few days", p.v, h, opt.CooldownDays))
		}
	} else if fx, ok := fixedAbove(it.vulns, name, cur); ok && len(cs) == 0 {
		target, haveTarget, sameMajor = fx, true, semver.Diff(cur, fx) != "major"
		f.Warnings = append(f.Warnings, i18n.F("Versiya siyahısı yüklənmədi — hədəf OSV-nin «fixed» məlumatından götürüldü", "Version list unavailable — target taken from OSV's \"fixed\" data"))
	}
	_ = young
	if !haveTarget {
		f.Impact = report.ImpactUnknown
		f.Why = append(f.Why, i18n.F("Hələ bu boşluğu düzəldən versiya yoxdur", "No version fixes this vulnerability yet"))
		if !it.pkg.Direct {
			f.ImpactWhy = append(f.ImpactWhy, i18n.F("Valideyn paketin (%s) alternativini və ya advisory-dəki müvəqqəti həlli yoxla", "Consider an alternative to the parent package (%s) or the workaround in the advisory", f.Chain[0]))
		}
		f.Group = groupOf(f.Need, report.ImpactYes)
		return f, errs
	}
	f.Target = target.String()
	if !sameMajor {
		f.Why = append(f.Why, i18n.F("Düzəliş yalnız yeni major xəttindədir", "The fix is only in a new major version"))
	}

	if it.pkg.Direct {
		f.Fix = &report.Fix{Strategy: "upgrade", Command: installCmd(in.Mgr, name, f.Target, it.pkg.Dev, true)}
		f.Impact = impactOfDiff(cur, target)
		f.ImpactWhy = append(f.ImpactWhy, diffWhy(cur, target))
		errs = append(errs, checkTarget(ctx, d, &f, in, name, cur.String(), f.Target)...)
	} else {
		errs = append(errs, transitiveFix(ctx, d, &f, it, in, g, target, clean, cooldown, opt)...)
	}
	if in.Lock.Approximate {
		f.Warnings = append(f.Warnings, i18n.F("Lockfile yoxdur — versiya təxminidir (aralığın minimumu)", "No lockfile — version is approximate (lowest in range)"))
	}
	f.Group = groupOf(f.Need, f.Impact)
	return f, errs
}

// transitiveFix chooses relock → parent upgrade → override for a transitive package.
func transitiveFix(ctx context.Context, d *Data, f *report.Finding, it *instance, in Input, g *graph, target semver.Version, clean func(semver.Version) bool, cooldown time.Duration, opt Options) []string {
	var errs []string
	name := it.pkg.Name
	mgr := in.Mgr
	// 1. relock: every parent's declared range already accepts the target
	parents := it.pkg.Parents
	if len(parents) == 0 {
		parents = g.parents[name]
	}
	allAccept := len(parents) > 0
	for _, p := range parents {
		rngs := declaredRanges(ctx, d, in, p, name)
		if len(rngs) == 0 {
			allAccept = false
			break
		}
		for _, rng := range rngs {
			r, err := semver.ParseRange(rng)
			if err != nil || !r.Contains(target) {
				allAccept = false
				break
			}
		}
		if !allAccept {
			break
		}
	}
	if allAccept {
		f.Fix = &report.Fix{Strategy: "relock", Command: relockCmd(mgr, name), Note: i18n.F("Valideyn paketlərin aralığı %s versiyasını artıq qəbul edir — yalnız lockfile yenilənir", "The parents' ranges already allow %s — only the lockfile changes", target.String())}
		f.Impact = report.ImpactNo
		f.ImpactWhy = append(f.ImpactWhy, i18n.F("Heç bir package.json dəyişmir; dolayı paket valideynin icazə verdiyi aralıqda yenilənir", "No package.json changes; the transitive package moves within the range its parent allows"))
		return errs
	}
	// 2. upgrade the direct parent when it is the immediate parent
	if len(f.Chain) == 2 {
		parent := f.Chain[0]
		if pcur, ok := installedDirect(in, parent); ok {
			if pt, err := parentUpgrade(ctx, d, parent, pcur, name, clean, cooldown, opt.Now); err == nil && pt != nil {
				f.Fix = &report.Fix{Strategy: "parent", Parent: parent, Command: installCmd(mgr, parent, pt.String(), isDev(in, parent), true),
					Note: i18n.F("%s %s → %s təmiz %s gətirir", "%s %s → %s brings a clean %s", parent, pcur, pt, name)}
				f.Impact = impactOfDiff(pcur, *pt)
				f.ImpactWhy = append(f.ImpactWhy, prefixed(parent+": ", diffWhy(pcur, *pt)))
				errs = append(errs, checkTarget(ctx, d, f, in, parent, pcur.String(), pt.String())...)
				return errs
			} else if err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	// 3. override
	f.Fix = overrideFix(mgr, name, target.String())
	f.Impact = report.ImpactMaybe
	f.ImpactWhy = append(f.ImpactWhy, i18n.F("Override: %s rəsmən %s istəmir — build və testlə yoxla; valideyn yenilənəndə override-ı sil", "Override: %s does not officially ask for %s — verify with build and tests; remove the override once the parent updates", strings.Join(parents, ", "), target))
	return errs
}

// declaredRanges returns the ranges every installed instance of parent declares for child.
// pnpm lockfiles store the resolved version instead of the range, so for an exact
// version the range is read from the registry document of parent@version.
func declaredRanges(ctx context.Context, d *Data, in Input, parent, child string) []string {
	var out []string
	for _, p := range in.Lock.Packages {
		if p.Name != parent {
			continue
		}
		rng, ok := p.Requires[child]
		if !ok {
			continue
		}
		if _, err := semver.Parse(rng); err == nil || in.Lock.Kind == "pnpm" {
			m, err := d.Manifest(ctx, parent, p.Version)
			if err != nil {
				return nil
			}
			r, ok := m.Deps[child]
			if !ok {
				return nil
			}
			rng = r
		}
		out = append(out, rng)
	}
	return out
}

// parentUpgrade finds the lowest mature version of parent (same major first)
// whose declared range for child admits a clean child version.
func parentUpgrade(ctx context.Context, d *Data, parent string, pcur semver.Version, child string, clean func(semver.Version) bool, cooldown time.Duration, now time.Time) (*semver.Version, error) {
	pinfo, err := d.Pkg(ctx, parent)
	if err != nil {
		return nil, err
	}
	cinfo, err := d.Pkg(ctx, child)
	if err != nil {
		return nil, err
	}
	var childClean []semver.Version
	for _, c := range candidates(cinfo, semver.Version{}) {
		if clean(c.v) {
			childClean = append(childClean, c.v)
		}
	}
	pcs := candidates(pinfo, pcur)
	tried := 0
	for pass := 0; pass < 2; pass++ { // pass 0: same major, pass 1: any
		for _, c := range pcs {
			if !semver.Less(pcur, c.v) || (!c.pub.IsZero() && now.Sub(c.pub) < cooldown) {
				continue
			}
			same := semver.Diff(pcur, c.v) != "major"
			if (pass == 0) != same {
				continue
			}
			if tried >= 25 {
				return nil, nil
			}
			tried++
			m, err := d.Manifest(ctx, parent, c.v.String())
			if err != nil {
				continue
			}
			rng, ok := m.Deps[child]
			if !ok {
				v := c.v
				return &v, nil // the new parent no longer depends on child
			}
			r, err := semver.ParseRange(rng)
			if err != nil {
				continue
			}
			if _, ok := semver.MaxSatisfying(childClean, r); ok {
				v := c.v
				return &v, nil
			}
		}
	}
	return nil, nil
}

// checkTarget compares target with current: engines, peers, supply-chain signals.
func checkTarget(ctx context.Context, d *Data, f *report.Finding, in Input, name, cur, target string) []string {
	tm, err := d.Manifest(ctx, name, target)
	if err != nil {
		return []string{err.Error()}
	}
	// engines.node
	if e := tm.Engines["node"]; e != "" && in.NodeVersion != "" {
		if r, err := semver.ParseRange(e); err == nil {
			if nv, err := semver.Parse(in.NodeVersion); err == nil && !r.Contains(nv) {
				f.Impact = report.ImpactYes
				f.ImpactWhy = append(f.ImpactWhy, i18n.F("%s@%s Node %s istəyir, layihədə Node %s — əvvəlcə Node-u yenilə", "%s@%s needs Node %s, the project uses Node %s — upgrade Node first", name, target, e, in.NodeVersion))
			}
		}
	}
	// peers vs installed direct packages
	for peer, rng := range tm.Peer {
		pv, ok := installedDirect(in, peer)
		if !ok {
			continue
		}
		r, err := semver.ParseRange(rng)
		if err != nil || r.Contains(pv) {
			continue
		}
		if f.Impact == report.ImpactNo {
			f.Impact = report.ImpactMaybe
		}
		f.ImpactWhy = append(f.ImpactWhy, i18n.F("Peer münaqişəsi: %s@%s %s %s istəyir, layihədə %s", "Peer conflict: %s@%s wants %s %s, the project has %s", name, target, peer, rng, pv))
	}
	// supply-chain signals
	cm, err := d.Manifest(ctx, name, cur)
	if err != nil {
		return nil
	}
	if s := tm.InstallScripts(); len(s) > 0 && len(cm.InstallScripts()) == 0 {
		f.Warnings = append(f.Warnings, i18n.F("Şübhəli: %s versiyasında yeni install skripti var (%s) — yeniləmədən əvvəl yoxla", "Suspicious: %s adds an install script (%s) — review before updating", target, strings.Join(s, ", ")))
	}
	if cm.HasProvenance() && !tm.HasProvenance() {
		f.Warnings = append(f.Warnings, i18n.F("Şübhəli: %s provenance ilə dərc olunub, %s isə provenance-sızdır", "Suspicious: %s was published with provenance, %s without", cur, target))
	}
	if cm.NpmUser.Name != "" && tm.NpmUser.Name != "" && cm.NpmUser.Name != tm.NpmUser.Name {
		f.Warnings = append(f.Warnings, i18n.F("Diqqət: versiyanı fərqli hesab dərc edib (%s → %s)", "Note: published by a different account (%s → %s)", cm.NpmUser.Name, tm.NpmUser.Name))
	}
	if a, b := normRepo(cm.RepoURL()), normRepo(tm.RepoURL()); a != "" && a != b {
		f.Warnings = append(f.Warnings, i18n.F("Şübhəli: repo linki dəyişib (%s → %s)", "Suspicious: repository URL changed (%s → %s)", a, orDash(b)))
	}
	return nil
}

func normRepo(u string) string {
	u = strings.ToLower(strings.TrimSpace(u))
	for _, p := range []string{"git+", "https://", "http://", "git://", "ssh://", "git@"} {
		u = strings.TrimPrefix(u, p)
	}
	u = strings.Replace(u, "github.com:", "github.com/", 1)
	return strings.TrimSuffix(strings.TrimSuffix(u, "/"), ".git")
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func installedDirect(in Input, name string) (semver.Version, bool) {
	var best semver.Version
	ok := false
	for _, p := range in.Lock.Packages {
		if p.Name != name || !p.Direct {
			continue
		}
		if v, err := semver.Parse(p.Version); err == nil && (!ok || semver.Less(best, v)) {
			best, ok = v, true
		}
	}
	return best, ok
}

func isDev(in Input, name string) bool {
	if in.Manifest == nil {
		return false
	}
	_, prod := in.Manifest.Dependencies[name]
	_, dev := in.Manifest.DevDependencies[name]
	return dev && !prod
}

func impactOfDiff(a, b semver.Version) report.Impact {
	if semver.Diff(a, b) == "major" {
		return report.ImpactYes
	}
	return report.ImpactNo
}

func diffWhy(a, b semver.Version) i18n.T {
	switch semver.Diff(a, b) {
	case "major":
		return i18n.F("%s → %s major yeniləmədir: API dəyişə bilər, miqrasiya bələdçisini oxu", "%s → %s is a major update: the API may change, read the migration guide", a, b)
	case "minor":
		return i18n.F("%s → %s minor yeniləmədir: semver-ə görə geriyə uyğun", "%s → %s is a minor update: backwards compatible per semver", a, b)
	default:
		return i18n.F("%s → %s patch yeniləmədir: yalnız düzəlişlər", "%s → %s is a patch update: fixes only", a, b)
	}
}

func prefixed(p string, t i18n.T) i18n.T { return i18n.T{Az: p + t.Az, En: p + t.En} }

// GroupOf places a finding by its two answers.
func GroupOf(n report.Need, i report.Impact) report.Group { return groupOf(n, i) }

func groupOf(n report.Need, i report.Impact) report.Group {
	switch n {
	case report.NeedNow, report.NeedSoon:
		if i == report.ImpactNo {
			return report.GroupNowEasy
		}
		return report.GroupNowCode
	case report.NeedPlan:
		return report.GroupPlan
	case report.NeedOptional:
		return report.GroupOptional
	}
	return report.GroupOK
}

// priority implements the 0–100 score from the plan.
func priority(sev int, kev bool, epss float64, dev, approx bool) int {
	p := map[int]int{4: 50, 3: 35, 2: 20, 1: 5}[sev]
	if kev {
		p += 25
	}
	p += int(epss*15 + 0.5)
	if dev {
		p -= 15
	}
	if approx {
		p -= 10
	}
	return max(1, min(99, p))
}

func firstLine(parts ...string) string {
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = strings.SplitN(p, "\n", 2)[0]
		if len([]rune(p)) > 160 {
			p = string([]rune(p)[:157]) + "…"
		}
		return p
	}
	return ""
}

// ---------- commands ----------

func installCmd(mgr, name, ver string, dev, direct bool) string {
	spec := name + "@" + ver
	switch mgr {
	case "pnpm":
		return "pnpm up " + spec
	case "yarn":
		return "yarn up " + spec
	case "yarn1":
		return "yarn upgrade " + spec
	case "bun":
		if dev {
			return "bun add -d " + spec
		}
		return "bun add " + spec
	default:
		if dev {
			return "npm install -D " + spec
		}
		return "npm install " + spec
	}
}

func relockCmd(mgr, name string) string {
	switch mgr {
	case "pnpm":
		return "pnpm update --depth Infinity " + name
	case "yarn":
		return "yarn up -R " + name
	case "yarn1":
		return "yarn install   # " + name + "@*"
	case "bun":
		return "bun update " + name
	default:
		return "npm update " + name
	}
}

func removeCmd(mgr, name string) string {
	switch mgr {
	case "pnpm":
		return "pnpm remove " + name
	case "yarn", "yarn1":
		return "yarn remove " + name
	case "bun":
		return "bun remove " + name
	default:
		return "npm uninstall " + name
	}
}

func overrideFix(mgr, name, ver string) *report.Fix {
	if ver == "" {
		ver = "<clean-version>"
	}
	block := func(key string, nested string) string {
		inner := map[string]string{name: ver}
		var v any = inner
		if nested != "" {
			v = map[string]any{nested: inner}
		}
		b, _ := json.MarshalIndent(map[string]any{key: v}, "", "  ")
		return string(b)
	}
	fx := &report.Fix{Strategy: "override", File: "package.json", Note: i18n.F("Müvəqqəti həll: valideyn paket düzəldilmiş versiyanı tələb edəndə override-ı sil", "Temporary fix: remove the override once the parent package requires the fixed version")}
	switch mgr {
	case "pnpm":
		fx.Snippet = block("pnpm", "overrides")
		fx.Command = "pnpm install"
	case "yarn", "yarn1":
		fx.Snippet = block("resolutions", "")
		fx.Command = "yarn install"
	case "bun":
		fx.Snippet = block("overrides", "")
		fx.Command = "bun install"
	default:
		fx.Snippet = block("overrides", "")
		fx.Command = "npm install"
	}
	return fx
}

// removedFinding: the lockfile pins a version npm no longer serves.
func removedFinding(ctx context.Context, d *Data, it *instance, in Input, g *graph, opt Options) (report.Finding, error) {
	name, cur := it.pkg.Name, it.ver
	f := report.Finding{Pkg: name, Direct: it.pkg.Direct, Dev: it.pkg.Dev, Current: cur.String(), Kind: "removed",
		Key: "removed:" + name + "@" + cur.String(), Need: report.NeedNow, Impact: report.ImpactUnknown, Priority: 70, Severity: "high"}
	if !it.pkg.Direct {
		f.Chain = g.chain(name, it.pkg.Parents)
	}
	f.Title = "This version is no longer on the npm registry"
	f.Why = append(f.Why,
		i18n.F("Lockfile-dakı %s artıq npm-də yoxdur: ya müəllif silib, ya da npm təhlükəsizlik səbəbi ilə götürüb", "%s from the lockfile is no longer on npm: either the author unpublished it or npm took it down for security reasons", cur),
		i18n.F("Təmiz quraşdırma (npm ci) alınmayacaq; paketin səhifəsində və GitHub-da səbəbi yoxla", "A clean install (npm ci) will fail; check the package page and its GitHub for the reason"))
	info, err := d.Pkg(ctx, name)
	if err != nil {
		return f, err
	}
	f.Latest = info.Default
	cooldown := time.Duration(opt.CooldownDays) * 24 * time.Hour
	// lowest existing, mature version above cur: same major first, then any
	var sameMajor, other *cand
	for _, c := range candidates(info, cur) {
		if !semver.Less(cur, c.v) || c.dep || (!c.pub.IsZero() && opt.Now.Sub(c.pub) < cooldown) {
			continue
		}
		major := semver.Diff(cur, c.v) == "major"
		if (major && other != nil) || (!major && sameMajor != nil) {
			continue
		}
		if _, err := d.Manifest(ctx, name, c.v.String()); err != nil {
			continue // removed as well
		}
		c := c
		if major {
			other = &c
		} else {
			sameMajor = &c
			break
		}
	}
	pick := sameMajor
	if pick == nil {
		pick = other
	}
	if pick != nil {
		f.Target = pick.v.String()
		f.Impact = impactOfDiff(cur, pick.v)
		f.ImpactWhy = append(f.ImpactWhy, diffWhy(cur, pick.v))
		if it.pkg.Direct {
			f.Fix = &report.Fix{Strategy: "upgrade", Command: installCmd(in.Mgr, name, f.Target, it.pkg.Dev, true)}
		} else {
			f.Fix = &report.Fix{Strategy: "relock", Command: relockCmd(in.Mgr, name), Note: i18n.F("Lockfile-ı yenilə; valideyn paket mövcud versiyanı seçəcək", "Refresh the lockfile; the parent will resolve to an existing version")}
		}
	}
	if in.Lock.Approximate {
		f.Warnings = append(f.Warnings, i18n.F("Lockfile yoxdur — versiya təxminidir", "No lockfile — version is approximate"))
	}
	f.Group = groupOf(f.Need, f.Impact)
	return f, nil
}
