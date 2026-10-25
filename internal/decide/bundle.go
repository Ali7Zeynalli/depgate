package decide

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/semver"
)

// family is a set of packages released in lockstep.
type family struct {
	id, name, leader string
	exact            []string // always the same version as the leader
	scope            string   // packages in this scope that are currently at the leader's version
	major            []string // must share the leader's major (types)
	docs             string
}

var families = []family{
	{id: "react", name: "React", leader: "react", exact: []string{"react-dom", "react-test-renderer", "react-is", "react-server-dom-webpack"}, major: []string{"@types/react", "@types/react-dom"}, docs: "https://react.dev/blog"},
	{id: "next", name: "Next.js", leader: "next", exact: []string{"eslint-config-next", "@next/eslint-plugin-next", "@next/bundle-analyzer", "@next/mdx", "@next/third-parties"}, docs: "https://nextjs.org/docs/app/guides/upgrading"},
	{id: "nestjs", name: "NestJS", leader: "@nestjs/core", exact: []string{"@nestjs/common", "@nestjs/platform-express", "@nestjs/platform-fastify", "@nestjs/microservices", "@nestjs/websockets", "@nestjs/testing", "@nestjs/platform-socket.io", "@nestjs/platform-ws"}, docs: "https://docs.nestjs.com/migration-guide"},
	{id: "angular", name: "Angular", leader: "@angular/core", scope: "@angular/", docs: "https://angular.dev/update-guide"},
	{id: "vue", name: "Vue", leader: "vue", exact: []string{"@vue/compiler-sfc", "@vue/server-renderer", "@vue/runtime-dom", "@vue/reactivity", "@vue/shared"}, docs: "https://vuejs.org/about/releases"},
	{id: "storybook", name: "Storybook", leader: "storybook", scope: "@storybook/", docs: "https://storybook.js.org/docs/migration-guide"},
	{id: "nx", name: "Nx", leader: "nx", scope: "@nx/", docs: "https://nx.dev/docs/guides/tips-n-tricks/advanced-update"},
	{id: "prisma", name: "Prisma", leader: "prisma", exact: []string{"@prisma/client"}, docs: "https://www.prisma.io/docs/orm/more/upgrade-guides"},
	{id: "typescript-eslint", name: "typescript-eslint", leader: "@typescript-eslint/parser", exact: []string{"@typescript-eslint/eslint-plugin", "typescript-eslint"}, scope: "@typescript-eslint/", docs: "https://typescript-eslint.io/users/releases"},
	{id: "tiptap", name: "Tiptap", leader: "@tiptap/core", scope: "@tiptap/", docs: "https://tiptap.dev/docs"},
}

type direct struct {
	ver semver.Version
	dev bool
}

// Bundles finds lockstep families among the direct packages and says how to
// move them together. It also adds a warning to the member findings.
func Bundles(ctx context.Context, d *Data, in Input, findings []report.Finding, opt Options) []report.Bundle {
	dirs := map[string]direct{}
	for _, p := range in.Lock.Packages {
		if !p.Direct {
			continue
		}
		v, err := semver.Parse(p.Version)
		if err != nil {
			continue
		}
		if ex, ok := dirs[p.Name]; !ok || semver.Less(ex.ver, v) {
			dirs[p.Name] = direct{ver: v, dev: p.Dev}
		}
	}
	target := map[string]string{} // pkg -> target suggested by its own finding
	for _, f := range findings {
		if f.Direct && f.Target != "" {
			target[f.Pkg] = f.Target
		}
	}
	var out []report.Bundle
	for _, fm := range families {
		lead, ok := dirs[fm.leader]
		if !ok {
			continue
		}
		// members
		var exact, major []string
		seen := map[string]bool{fm.leader: true}
		for _, n := range fm.exact {
			if _, ok := dirs[n]; ok && !seen[n] {
				exact, seen[n] = append(exact, n), true
			}
		}
		if fm.scope != "" {
			var scoped []string
			for n, x := range dirs {
				if strings.HasPrefix(n, fm.scope) && !seen[n] && semver.Compare(x.ver, lead.ver) == 0 {
					scoped = append(scoped, n)
				}
			}
			sort.Strings(scoped)
			for _, n := range scoped {
				exact, seen[n] = append(exact, n), true
			}
		}
		for _, n := range fm.major {
			if _, ok := dirs[n]; ok {
				major = append(major, n)
			}
		}
		if len(exact)+len(major) == 0 {
			continue
		}

		// where the family should go
		b := report.Bundle{ID: fm.id, Name: fm.name, Docs: fm.docs, Impact: report.ImpactNo}
		t := target[fm.leader]
		if t == "" {
			for _, n := range exact {
				if x := target[n]; x != "" && (t == "" || semver.Compare(mustOrZero(t), mustOrZero(x)) < 0) {
					t = x
				}
			}
		}
		drift := false
		for _, n := range exact {
			drift = drift || semver.Compare(dirs[n].ver, lead.ver) != 0
		}
		if t == "" && !drift {
			continue // all aligned and nothing to update
		}
		reason := i18n.F("%s paketləri birlikdə buraxılır: yalnız birini yeniləmək build-i və ya runtime-ı sındırır", "%s packages are released together: updating only one breaks the build or the runtime", fm.name)
		if t == "" {
			t = lead.ver.String()
			b.Why = append(b.Why, i18n.F("Versiyalar ayrılıb: %s %s-dədir, bəzi yoldaşları isə başqa versiyada", "Versions have drifted: %s is at %s but some of its companions are not", fm.leader, t))
		} else {
			b.Why = append(b.Why, i18n.F("%s → %s yenilənir; yoldaş paketlər də eyni versiyaya keçməlidir", "%s moves to %s; its companion packages must move to the same version", fm.leader, t))
		}
		b.Why = append(b.Why, reason)
		b.Target = t
		tv, err := semver.Parse(t)
		if err != nil {
			continue
		}
		add := func(n string, x direct, to string, note i18n.T) {
			it := report.BundleItem{Pkg: n, Current: x.ver.String(), Dev: x.dev, Note: note}
			if to != "" && to != it.Current {
				it.Target = to
				if imp := impactOfDiff(x.ver, mustOrZero(to)); impRank(imp) > impRank(b.Impact) {
					b.Impact = imp
				}
			}
			b.Items = append(b.Items, it)
		}
		add(fm.leader, lead, t, i18n.T{})
		for _, n := range exact {
			x := dirs[n]
			if has(ctx, d, n, t) {
				add(n, x, t, i18n.T{})
			} else {
				add(n, x, "", i18n.F("%s versiyası bu paketdə yoxdur — öz xəttində qalır, changelog-a bax", "%s does not exist for this package — it keeps its own line, check its changelog", t))
			}
		}
		for _, n := range major {
			x := dirs[n]
			if x.ver.Major == tv.Major {
				add(n, x, "", i18n.T{})
				continue
			}
			if v := newestInMajor(ctx, d, n, tv.Major, opt); v != "" {
				add(n, x, v, i18n.F("Tiplər %d major-a uyğun olmalıdır", "Types must match major %d", tv.Major))
			} else {
				add(n, x, "", i18n.F("%d major üçün tip versiyası tapılmadı", "No types release for major %d yet", tv.Major))
			}
		}
		changes := 0
		var prod, dev []string
		for _, it := range b.Items {
			if it.Target == "" {
				continue
			}
			changes++
			if it.Dev {
				dev = append(dev, it.Pkg+"@"+it.Target)
			} else {
				prod = append(prod, it.Pkg+"@"+it.Target)
			}
		}
		if changes < 2 && !drift {
			continue // a single package moving: its own card is enough
		}
		b.Command = multiCmd(in.Mgr, prod, dev)
		out = append(out, b)
	}
	// point member cards at the bundle
	for _, b := range out {
		in := map[string]bool{}
		for _, it := range b.Items {
			in[it.Pkg] = true
		}
		for i := range findings {
			if findings[i].Direct && in[findings[i].Pkg] {
				findings[i].Warnings = append(findings[i].Warnings, i18n.F("«%s» qrupu ilə birlikdə yenilə — birgə əmr yuxarıdadır", "Update together with the “%s” group — see the combined command above", b.Name))
			}
		}
	}
	return out
}

func impRank(i report.Impact) int {
	return map[report.Impact]int{report.ImpactNo: 0, report.ImpactMaybe: 1, report.ImpactUnknown: 1, report.ImpactYes: 2}[i]
}

// has reports whether name@version exists (deps.dev version list; registry as fallback).
func has(ctx context.Context, d *Data, name, version string) bool {
	if info, err := d.Pkg(ctx, name); err == nil && info != nil {
		for _, v := range info.Versions {
			if v.Version == version {
				return true
			}
		}
		return false
	}
	_, err := d.Manifest(ctx, name, version)
	return err == nil
}

// newestInMajor returns the newest stable, mature version of name in the given major.
func newestInMajor(ctx context.Context, d *Data, name string, major int, opt Options) string {
	info, err := d.Pkg(ctx, name)
	if err != nil || info == nil {
		return ""
	}
	cooldown := time.Duration(opt.CooldownDays) * 24 * time.Hour
	var best *semver.Version
	for _, pv := range info.Versions {
		v, err := semver.Parse(pv.Version)
		if err != nil || v.IsPrerelease() || v.Major != major || pv.Deprecated {
			continue
		}
		if !pv.Published.IsZero() && opt.Now.Sub(pv.Published) < cooldown {
			continue
		}
		if best == nil || semver.Less(*best, v) {
			v := v
			best = &v
		}
	}
	if best == nil {
		return ""
	}
	return best.String()
}

// multiCmd installs several packages in one go, keeping dev dependencies dev.
func multiCmd(mgr string, prod, dev []string) string {
	all := append(append([]string{}, prod...), dev...)
	if len(all) == 0 {
		return ""
	}
	switch mgr {
	case "pnpm":
		return "pnpm up " + strings.Join(all, " ")
	case "yarn":
		return "yarn up " + strings.Join(all, " ")
	case "yarn1":
		return "yarn upgrade " + strings.Join(all, " ")
	}
	base, devFlag := "npm install ", "npm install -D "
	if mgr == "bun" {
		base, devFlag = "bun add ", "bun add -d "
	}
	var parts []string
	if len(prod) > 0 {
		parts = append(parts, base+strings.Join(prod, " "))
	}
	if len(dev) > 0 {
		parts = append(parts, devFlag+strings.Join(dev, " "))
	}
	return strings.Join(parts, " && ")
}

func mustOrZero(s string) semver.Version {
	v, _ := semver.Parse(s)
	return v
}
