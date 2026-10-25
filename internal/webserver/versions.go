package webserver

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/docker"
	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
)

const caddyModule = "github.com/caddyserver/caddy/v2"

var dotted = regexp.MustCompile(`^\d+(\.\d+){0,2}$`)

// image returns "nginx" / "caddy", the version part of the tag and the rest of
// the tag ("-alpine"); ok is false for other images and unpinned tags.
func image(ref string) (prog, ver, rest string, ok bool) {
	if strings.Contains(ref, "@") {
		return "", "", "", false
	}
	name, tag := ref, ""
	if c := strings.LastIndex(ref, ":"); c > strings.LastIndex(ref, "/") {
		name, tag = ref[:c], ref[c+1:]
	}
	name = strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(name, "docker.io/"), "library/"))
	switch name {
	case "nginx", "nginxinc/nginx-unprivileged":
		prog = "nginx"
	case "caddy":
		prog = "caddy"
	default:
		return "", "", "", false
	}
	v, r, _ := strings.Cut(tag, "-")
	v = strings.TrimPrefix(v, "v")
	if !dotted.MatchString(v) {
		return "", "", "", false // latest, stable, mainline, alpine, builder…: floating tags
	}
	if r != "" {
		r = "-" + r
	}
	return prog, v, r, true
}

// Versions checks the nginx and Caddy images of the project: known
// vulnerabilities of the exact version (nginx.org advisories, OSV for Caddy)
// and, for Caddy, a newer release. Lookups that fail are skipped.
func Versions(ctx context.Context, f sources.Fetcher, refs []docker.ImageRef, now time.Time) []report.DockerIssue {
	var out []report.DockerIssue
	var ngxAdv []sources.NginxAdvisory
	ngxLoaded := false
	var ngxCycles []sources.Cycle
	var caddyRel []sources.Release
	caddyLoaded := false
	osv := sources.NewOSV(f)
	seen := map[string]bool{}
	for _, r := range refs {
		prog, ver, rest, ok := image(r.Ref)
		if !ok || seen[r.File+":"+fmt.Sprint(r.Line)] {
			continue
		}
		seen[r.File+":"+fmt.Sprint(r.Line)] = true
		name := r.Ref[:strings.LastIndex(r.Ref, ":")]
		switch prog {
		case "nginx":
			if !ngxLoaded {
				ngxLoaded = true
				ngxAdv, _ = sources.NginxAdvisories(ctx, f)
				ngxCycles, _ = sources.Cycles(ctx, f, "nginx")
			}
			exact := ver
			if strings.Count(ver, ".") < 2 { // "1.27" → newest 1.27.x
				exact = ""
				for _, c := range ngxCycles {
					if c.Name == ver && c.Latest != "" {
						exact = c.Latest
					}
				}
			}
			if exact == "" || len(ngxAdv) == 0 {
				continue
			}
			var hit []sources.NginxAdvisory
			for _, a := range ngxAdv {
				if a.Affects(exact) {
					hit = append(hit, a)
				}
			}
			if len(hit) == 0 {
				continue
			}
			sev := "low"
			var lines []string
			for _, a := range hit {
				s := map[string]string{"major": "high", "high": "high", "medium": "medium"}[a.Severity]
				if s == "" {
					s = "low"
				}
				if rank(s) > rank(sev) {
					sev = s
				}
				if len(lines) < 5 {
					lines = append(lines, strings.Join(a.CVEs, "/")+" ("+a.Severity+") — "+a.Title)
				}
			}
			if len(hit) > len(lines) {
				lines = append(lines, fmt.Sprintf("+%d", len(hit)-len(lines)))
			}
			fix := sources.NginxFix(ngxAdv, exact)
			shown := ver
			if exact != ver {
				shown = ver + " (" + exact + ")"
			}
			is := report.DockerIssue{File: r.File, Line: r.Line, Service: r.Service, Rule: "nginx-vulnerable", Severity: sev,
				Title:  i18n.F("nginx %s: %d məlum zəiflik", "nginx %s: %d known vulnerabilities", shown, len(hit)),
				Detail: i18n.F("nginx.org təhlükəsizlik siyahısına görə: %s.", "According to nginx.org security advisories: %s.", strings.Join(lines, "; "))}
			if fix != "" {
				is.Fix = name + ":" + fixTag(ver, fix) + rest
			}
			out = append(out, is)
		case "caddy":
			if !caddyLoaded {
				caddyLoaded = true
				caddyRel, _ = sources.Releases(ctx, f, "caddyserver/caddy")
			}
			latest, exact := "", ver
			for _, rl := range caddyRel {
				if rl.Draft || rl.Prerelease {
					continue
				}
				v := strings.TrimPrefix(rl.Tag, "v")
				if !dotted.MatchString(v) {
					continue
				}
				if latest == "" || sources.CompareDotted(v, latest) > 0 {
					latest = v
				}
				if strings.Count(ver, ".") < 2 && (v == ver || strings.HasPrefix(v, ver+".")) && (exact == ver || sources.CompareDotted(v, exact) > 0) {
					exact = v
				}
			}
			if strings.Count(exact, ".") < 2 {
				continue // "2" or "2.8" and the releases are unknown
			}
			ids, err := osv.Query(ctx, "Go", caddyModule, exact)
			if err != nil {
				continue
			}
			sev, fix := "", ""
			var lines []string
			for _, id := range ids {
				v, err := osv.Get(ctx, id)
				if err != nil || v.Withdrawn != "" {
					continue
				}
				s, _ := v.SeverityLevel()
				s = map[string]string{"critical": "high", "high": "high", "moderate": "medium", "medium": "medium"}[strings.ToLower(s)]
				if s == "" {
					s = "low"
				}
				if rank(s) > rank(sev) {
					sev = s
				}
				label := v.ID
				if cs := v.CVEs(); len(cs) > 0 {
					label = cs[0]
				}
				if len(lines) < 5 {
					lines = append(lines, label+" — "+firstLine(v.Summary, v.Details))
				}
				if x := v.FixedFor(caddyModule, exact); x != "" && (fix == "" || sources.CompareDotted(x, fix) > 0) {
					fix = x
				}
			}
			shown := ver
			if exact != ver {
				shown = ver + " (" + exact + ")"
			}
			if sev != "" {
				is := report.DockerIssue{File: r.File, Line: r.Line, Service: r.Service, Rule: "caddy-vulnerable", Severity: sev,
					Title:  i18n.F("Caddy %s: %d məlum zəiflik", "Caddy %s: %d known vulnerabilities", shown, len(lines)),
					Detail: i18n.F("OSV.dev (Go vulndb) məlumatına görə: %s.", "According to OSV.dev (Go vulndb): %s.", strings.Join(lines, "; "))}
				if fix != "" {
					is.Fix = name + ":" + fixTag(ver, fix) + rest
				}
				out = append(out, is)
			} else if latest != "" && minorOf(exact) != minorOf(latest) && sources.CompareDotted(exact, latest) < 0 {
				out = append(out, report.DockerIssue{File: r.File, Line: r.Line, Service: r.Service, Rule: "caddy-outdated", Severity: "low",
					Title:  i18n.F("Caddy %s köhnədir (son: %s)", "Caddy %s is behind (latest: %s)", shown, latest),
					Detail: i18n.F("Caddy yalnız son buraxılış xəttinə düzəliş verir; yeniləmədən əvvəl release qeydlərinə bax.", "Caddy only patches its latest release line; read the release notes before upgrading."),
					Fix:    name + ":" + fixTag(ver, latest) + rest})
			}
		}
	}
	return out
}

// fixTag keeps the precision of the original tag: "1.27" → "1.30", "1.27.1" → "1.30.6".
func fixTag(orig, fix string) string {
	n := strings.Count(orig, ".") + 1
	p := strings.Split(fix, ".")
	if n < len(p) {
		p = p[:n]
	}
	return strings.Join(p, ".")
}

func minorOf(v string) string {
	p := strings.SplitN(v, ".", 3)
	if len(p) < 2 {
		return v
	}
	return p[0] + "." + p[1]
}

func rank(s string) int { return map[string]int{"low": 1, "medium": 2, "high": 3}[s] }

func firstLine(xs ...string) string {
	for _, x := range xs {
		if x = strings.TrimSpace(strings.SplitN(x, "\n", 2)[0]); x != "" {
			if len(x) > 140 {
				x = x[:140] + "…"
			}
			return x
		}
	}
	return ""
}
