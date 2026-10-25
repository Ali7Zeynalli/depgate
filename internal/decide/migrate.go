package decide

import (
	"context"
	"errors"
	"sort"
	"sync/atomic"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/migrate"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/semver"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
)

// Migrations adds, to every direct finding that moves a package, what changes
// in the project's own code: documented breaking changes with the places they
// touch, the official codemod, and (for major moves) the breaking sections of
// the upstream release notes. For packages with a newer major beyond the
// suggested target it also adds a "plan" migration to that major.
func Migrations(ctx context.Context, d *Data, dir string, findings []report.Finding) {
	var proj *migrate.Project
	open := func() *migrate.Project {
		if proj == nil {
			proj = migrate.Open(dir)
		}
		return proj
	}
	for i := range findings {
		f := &findings[i]
		if !f.Direct {
			continue
		}
		cur, err := semver.Parse(f.Current)
		if err != nil {
			continue
		}
		var tos []string
		if f.Target != "" {
			tos = append(tos, f.Target)
		}
		if lv, err := semver.Parse(f.Latest); err == nil && !lv.IsPrerelease() {
			base := cur
			if tv, err := semver.Parse(f.Target); err == nil {
				base = tv
			}
			if lv.Major > base.Major {
				tos = append(tos, f.Latest)
			}
		}
		for j, to := range tos {
			tv, _ := semver.Parse(to)
			m := open().For(f.Pkg, f.Current, to)
			major := tv.Major > cur.Major
			if m == nil && !major {
				continue
			}
			if m == nil {
				m = &report.Migration{To: to}
			}
			m.Plan = j > 0 || to != f.Target
			if major {
				notes(ctx, d, f.Pkg, cur, tv, m)
			}
			if len(m.Steps) == 0 && len(m.Notes) == 0 && m.NotesErr == "" {
				continue
			}
			f.Migrate = append(f.Migrate, *m)
			if !m.Plan && m.Hits > 0 {
				f.ImpactWhy = append([]i18n.T{i18n.F("Kodunda %d yer dəyişməlidir — aşağıdakı siyahıya bax", "%d places in your code need a change — see the list below", m.Hits)}, f.ImpactWhy...)
				if f.Impact != report.ImpactYes {
					f.Impact = report.ImpactYes
					f.Group = GroupOf(f.Need, f.Impact)
				}
			}
		}
	}
}

// notes fills the breaking parts of the releases cur < v <= to.
func notes(ctx context.Context, d *Data, pkg string, cur, to semver.Version, m *report.Migration) {
	man, err := d.Manifest(ctx, pkg, to.String())
	if err != nil {
		return
	}
	repo := sources.GitHubRepo(man.RepoURL())
	if repo == "" {
		return
	}
	if atomic.AddInt32(&d.GitHubLeft, -1) < 0 {
		m.NotesErr = "release-notes limit for this scan reached"
		return
	}
	rels, err := sources.Releases(ctx, d.F, repo)
	if err != nil {
		if errors.Is(err, sources.ErrRateLimited) {
			m.NotesErr = err.Error()
		}
		return
	}
	type rn struct {
		v semver.Version
		n report.ReleaseNote
	}
	var out []rn
	for _, r := range rels {
		if r.Draft || r.Prerelease {
			continue
		}
		vs, ok := sources.ReleaseVersion(r.Tag, pkg)
		if !ok {
			continue
		}
		v, err := semver.Parse(vs)
		if err != nil || v.IsPrerelease() || !semver.Less(cur, v) || semver.Less(to, v) {
			continue
		}
		if b := sources.BreakingPart(r.Body, 1500); b != "" {
			out = append(out, rn{v, report.ReleaseNote{Version: v.String(), URL: r.URL, Breaking: b}})
		}
	}
	sort.Slice(out, func(i, j int) bool { return semver.Less(out[i].v, out[j].v) })
	if len(out) > 10 {
		out = out[len(out)-10:]
	}
	for _, x := range out {
		m.Notes = append(m.Notes, x.n)
	}
}
