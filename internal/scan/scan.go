// Package scan runs the whole pipeline for a set of project directories.
package scan

import (
	"context"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/airules"
	"github.com/Ali7Zeynalli/depgate/internal/decide"
	"github.com/Ali7Zeynalli/depgate/internal/docker"
	"github.com/Ali7Zeynalli/depgate/internal/images"
	"github.com/Ali7Zeynalli/depgate/internal/lockfile"
	"github.com/Ali7Zeynalli/depgate/internal/project"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/semver"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
	"github.com/Ali7Zeynalli/depgate/internal/webserver"
)

func init() {
	lockfile.MinVersion = func(rng string) (string, bool) {
		r, err := semver.ParseRange(rng)
		if err != nil {
			return "", false
		}
		v, ok := semver.MinVersion(r)
		if !ok {
			return "", false
		}
		return v.String(), true
	}
}

type Options struct {
	Version      string // tool version
	CooldownDays int
	Offline      bool
	Now          time.Time
	Progress     func(msg string)
}

// Run scans every directory and returns one report.
func Run(ctx context.Context, f sources.Fetcher, dirs []string, opt Options) *report.Report {
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	if opt.CooldownDays <= 0 {
		opt.CooldownDays = 3
	}
	say := func(s string) {
		if opt.Progress != nil {
			opt.Progress(s)
		}
	}
	rep := &report.Report{Schema: report.Schema, Tool: "depgate " + opt.Version, ScannedAt: opt.Now.UTC(), Offline: opt.Offline}
	rec := sources.NewRecorder(f)
	f = rec
	d := decide.NewData(f)
	say("Node.js releases, CISA KEV…")
	if nd, err := sources.Node(ctx, f); err == nil {
		d.Node = nd
	} else {
		rep.Errors = append(rep.Errors, err.Error())
	}
	if kev, err := sources.KEV(ctx, f); err == nil {
		d.KEV = kev
	} else {
		rep.Errors = append(rep.Errors, err.Error())
	}
	for i, dir := range dirs {
		say(progressLine(i, len(dirs), dir))
		rep.Projects = append(rep.Projects, One(ctx, d, dir, opt))
	}
	rep.Sources = Sources(rec.Usage())
	for i := range rep.Projects {
		rep.Projects[i].Sources = rep.Sources
		rep.Projects[i].ScannedAt = rep.ScannedAt
	}
	return rep
}

// Sources turns request counters into the report's source list (whole catalog,
// so the UI can also show sources that were not needed).
func Sources(u map[string]sources.Usage) []report.Source {
	out := make([]report.Source, 0, len(sources.Catalog))
	for _, s := range sources.Catalog {
		x := u[s.ID]
		out = append(out, report.Source{ID: s.ID, Name: s.Name, URL: s.Home, Use: s.Use, Requests: x.Requests, Failed: x.Failed})
	}
	return out
}

func progressLine(i, n int, dir string) string {
	return "[" + strconv.Itoa(i+1) + "/" + strconv.Itoa(n) + "] " + filepath.Base(dir) + "…"
}

// One scans a single project directory.
func One(ctx context.Context, d *decide.Data, dir string, opt Options) report.Project {
	abs, _ := filepath.Abs(dir)
	p := report.Project{Dir: abs, Name: filepath.Base(abs), Findings: []report.Finding{}, Hygiene: []report.Check{}}
	man, err := lockfile.ReadManifest(abs)
	if err != nil {
		p.Errors = append(p.Errors, err.Error())
		return p
	}
	if man.Name != "" {
		p.Name = man.Name
	}
	remote, rel := project.Git(abs)
	p.Repo, p.Path = remote, rel
	p.ID = project.ID(abs, remote, rel)
	root := project.RepoRoot(abs)

	lr, err := lockfile.Parse(abs)
	if err != nil {
		p.Errors = append(p.Errors, err.Error())
		return p
	}
	p.Manager, p.Lockfile, p.Approximate, p.Packages = decide.ManagerOf(lr), lr.File, lr.Approximate, len(lr.Packages)

	srcs := project.NodeSources(abs, root, man.Engines)
	p.Node = decide.EvalNode(srcs, d.Node, opt.Now)
	nodeVer := ""
	mismatch := false
	if p.Node != nil {
		nodeVer, mismatch = p.Node.Version, p.Node.Mismatch
	}
	in := decide.Input{Lock: lr, Manifest: man, NodeVersion: nodeVer, Mgr: decide.ManagerOf(lr)}
	dopt := decide.Options{CooldownDays: opt.CooldownDays, Now: opt.Now}
	findings, errs := decide.Packages(ctx, d, in, dopt)
	p.Findings = findings
	p.Bundles = decide.Bundles(ctx, d, in, p.Findings, dopt)
	decide.Migrations(ctx, d, abs, p.Findings)
	directs := map[string]string{}
	for _, x := range lr.Packages {
		if v, err := semver.Parse(x.Version); x.Direct && err == nil {
			if old, ok := directs[x.Name]; !ok || semver.Less(semver.MustParse(old), v) {
				directs[x.Name] = v.String()
			}
		}
	}
	p.AIRules = airules.Build(directs, nodeVer)
	p.Errors = append(p.Errors, errs...)
	p.Hygiene = project.Hygiene(abs, root, lr.Manager, lr.Kind, mismatch, opt.CooldownDays)
	p.Docker, p.DockerFiles = docker.Scan(abs, root)
	refs := docker.ImageRefs(abs, root)
	p.Docker = append(p.Docker, images.Check(ctx, d.F, refs, opt.Now)...)
	docker.SortIssues(p.Docker)
	p.Server, p.ServerFiles = webserver.Scan(abs, root)
	p.Server = append(p.Server, webserver.Versions(ctx, d.F, refs, opt.Now)...)
	docker.SortIssues(p.Server)
	p.Summary = Summarize(p.Findings)
	sort.SliceStable(p.Errors, func(i, j int) bool { return p.Errors[i] < p.Errors[j] })
	return p
}

// Summarize counts findings per group.
func Summarize(fs []report.Finding) report.Summary { return report.Summarize(fs) }
