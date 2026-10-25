package decide

import (
	"context"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/semver"
)

// updateFinding produces the card for a direct package without known vulnerabilities:
// deprecated, newer major (plan), newer minor/patch (optional) or up to date.
func updateFinding(ctx context.Context, d *Data, it *instance, in Input, opt Options) (report.Finding, error) {
	name, cur := it.pkg.Name, it.ver
	f := report.Finding{Pkg: name, Direct: true, Dev: it.pkg.Dev, Current: cur.String(), Kind: "current",
		Key: "update:" + name + "@" + cur.String(), Need: report.NeedNone, Impact: report.ImpactNo, Group: report.GroupOK}
	info, err := d.Pkg(ctx, name)
	if err != nil {
		f.Why = append(f.Why, i18n.F("Versiya məlumatı yüklənmədi", "Version data unavailable"))
		f.Impact = report.ImpactUnknown
		return f, err
	}
	f.Latest = info.Default
	cooldown := time.Duration(opt.CooldownDays) * 24 * time.Hour
	cs := candidates(info, cur)
	mature := func(c cand) bool { return c.pub.IsZero() || opt.Now.Sub(c.pub) >= cooldown }

	var curDep string
	for _, pv := range info.Versions {
		if pv.Version == cur.String() && pv.Deprecated {
			curDep = pv.Reason
			if curDep == "" {
				curDep = "—"
			}
		}
	}
	latest, err := semver.Parse(info.Default)
	haveLatest := err == nil && !latest.IsPrerelease()

	// newest mature version in the current major, and newest mature overall (not above dist-tag latest)
	var inMajor, overall *cand
	for i := range cs {
		c := cs[i]
		if !semver.Less(cur, c.v) || !mature(c) || c.dep {
			continue
		}
		if haveLatest && semver.Less(latest, c.v) {
			continue
		}
		if semver.Diff(cur, c.v) != "major" {
			inMajor = &c
		}
		overall = &c
	}

	switch {
	case curDep != "":
		f.Kind, f.Key = "deprecated", "deprecated:"+name+"@"+cur.String()
		f.Need = report.NeedSoon
		f.Why = append(f.Why, i18n.F("Bu versiya deprecated-dir: %s", "This version is deprecated: %s", firstLine(curDep)))
		t := inMajor
		if t == nil {
			t = overall
		}
		if t != nil {
			f.Target = t.v.String()
			f.Fix = &report.Fix{Strategy: "upgrade", Command: installCmd(in.Mgr, name, f.Target, it.pkg.Dev, true)}
			f.Impact = impactOfDiff(cur, t.v)
			f.ImpactWhy = append(f.ImpactWhy, diffWhy(cur, t.v))
		} else {
			f.Impact = report.ImpactYes
			f.ImpactWhy = append(f.ImpactWhy, i18n.F("Daha yeni versiya yoxdur — paket tərk edilib, alternativə keç", "No newer version — the package is abandoned, switch to an alternative"))
		}
	case inMajor != nil:
		f.Kind = "update"
		f.Need = report.NeedOptional
		f.Target = inMajor.v.String()
		f.Fix = &report.Fix{Strategy: "upgrade", Command: installCmd(in.Mgr, name, f.Target, it.pkg.Dev, true)}
		f.Impact = report.ImpactNo
		f.Why = append(f.Why, i18n.F("Eyni major-da daha yeni versiya var", "A newer version exists in the same major"))
		f.ImpactWhy = append(f.ImpactWhy, diffWhy(cur, inMajor.v))
		if overall != nil && semver.Diff(cur, overall.v) == "major" {
			f.Why = append(f.Why, i18n.F("Yeni major da var: %s — ayrıca planla", "A new major exists too: %s — plan it separately", overall.v))
		}
	case overall != nil:
		f.Kind = "update"
		f.Need = report.NeedPlan
		f.Target = overall.v.String()
		f.Fix = &report.Fix{Strategy: "upgrade", Command: installCmd(in.Mgr, name, f.Target, it.pkg.Dev, true)}
		f.Impact = report.ImpactYes
		f.Why = append(f.Why, i18n.F("Yalnız yeni major var — təcili deyil, planla", "Only a new major exists — not urgent, plan it"))
		f.ImpactWhy = append(f.ImpactWhy, diffWhy(cur, overall.v))
	default:
		f.Why = append(f.Why, i18n.F("Ən son versiyadadır", "Up to date"))
		return f, nil
	}
	if f.Target != "" {
		for _, e := range checkTarget(ctx, d, &f, in, name, cur.String(), f.Target) {
			_ = e // registry hiccups on an optional update are not worth reporting
		}
	}
	if in.Lock.Approximate {
		f.Warnings = append(f.Warnings, i18n.F("Lockfile yoxdur — versiya təxminidir", "No lockfile — version is approximate"))
	}
	f.Group = groupOf(f.Need, f.Impact)
	return f, nil
}
