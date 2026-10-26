package mcp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/history"
)

// callInfo is filled by a tool while it runs, for the activity log.
type callInfo struct {
	project string
	target  string
	verdict string
}

type infoKey struct{}

func infoOf(ctx context.Context) *callInfo {
	if i, ok := ctx.Value(infoKey{}).(*callInfo); ok {
		return i
	}
	return &callInfo{} // discarded
}

// baseDir is the project folder a request starts from (before any "project" argument).
func (s *Server) baseDir(ctx context.Context) string {
	base := s.Project
	if p, ok := ctx.Value(ctxKey{}).(string); ok && p != "" {
		base = p
	}
	if base == "" {
		base = s.Cwd
	}
	if base != "" && !filepath.IsAbs(base) {
		base = filepath.Join(s.Cwd, base)
	}
	return filepath.Clean(base)
}

// logCall records one tool call in the activity log shown in the UI.
func (s *Server) logCall(ctx context.Context, name string, args map[string]any, info *callInfo, err error) {
	if s.Store == nil {
		return
	}
	c := s.callerOf(ctx)
	e := history.Event{At: time.Now().UTC(), Agent: c.agent, Via: c.via, Tool: name, Project: or(info.project, s.baseDir(ctx)),
		Target: info.target, Verdict: info.verdict, Error: err != nil}
	if name == "list_projects" {
		e.Project = s.baseDir(ctx)
	}
	if e.Target == "" {
		e.Target = clean(or(str(args, "package"), str(args, "name")), 120)
	}
	if err != nil {
		e.Note = clean(err.Error(), 200)
	}
	_ = s.Store.History.AddEvent(e)
}

// logConnect records that an agent opened a session.
func (s *Server) logConnect(ctx context.Context, c caller) {
	if s.Store == nil {
		return
	}
	_ = s.Store.History.AddEvent(history.Event{At: time.Now().UTC(), Agent: c.agent, Via: c.via, Tool: "connect", Project: s.baseDir(ctx)})
}

// sessionID carries the client name, so a stateless server still knows who is
// calling after a restart: <random>.<base64url(name)>.
func sessionID(agent string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString([]byte(agent))
}

func agentFromSession(id string) string {
	_, enc, ok := strings.Cut(id, ".")
	if !ok || len(enc) > 200 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return ""
	}
	return clean(string(b), 90)
}

// agentFromUA turns "claude-code/2.1.4 (cli)" into "claude-code 2.1.4".
func agentFromUA(ua string) string {
	f := strings.Fields(ua)
	if len(f) == 0 {
		return ""
	}
	return clean(strings.Replace(f[0], "/", " ", 1), 60)
}

// ---------- get_history ----------

func runHistory(ctx context.Context, s *Server, args map[string]any) (string, error) {
	t, err := s.resolve(ctx, str(args, "project"))
	if err != nil {
		return "", err
	}
	scans := s.Store.History.Scans(t.dir)
	if len(scans) == 0 {
		return "No scan history for " + t.dir + " yet. Call scan_project.", nil
	}
	n := 5
	if v, ok := args["limit"].(float64); ok && v >= 1 {
		n = min(int(v), 30)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Scan history of %s (newest first, %d stored)\n", t.dir, len(scans))
	for i := 0; i < len(scans) && i < n; i++ {
		cur := scans[i]
		var prev *history.Scan
		if i+1 < len(scans) {
			prev = &scans[i+1]
		}
		d := history.Compare(prev, &cur)
		by := cur.By
		if cur.Agent != "" {
			by += " (" + cur.Agent + ")"
		}
		su := cur.Summary
		fmt.Fprintf(&b, "\n## %s — by %s\nnow: %d (code changes: %d) · plan: %d · malware: %d · critical: %d · high: %d · docker/server: %d\n",
			cur.At.Format(time.RFC3339), by, su.NowEasy+su.NowCode, su.NowCode, su.Plan, su.Malware, su.Critical, su.High, cur.Docker+cur.Server)
		switch {
		case d.First:
			b.WriteString("First scan.\n")
		case d.Same():
			b.WriteString("No findings changed since the scan before.\n")
		default:
			if d.LockChanged {
				b.WriteString("Lockfile changed since the scan before.\n")
			} else if len(d.New) > 0 {
				b.WriteString("Lockfile unchanged: new findings come from new advisories.\n")
			}
			items := func(label string, is []history.Item) {
				for _, it := range is {
					fmt.Fprintf(&b, "- %s: %s %s%s\n", label, it.Kind, spec(it), sevOf(it))
				}
			}
			items("new", d.New)
			items("fixed", d.Fixed)
			items("changed", d.Changed)
		}
		writePkgs(&b, cur.Pkgs)
	}
	if p, err := s.reportOf(ctx, t); err == nil {
		g := history.ReadGitLog(t.dir, p.Lockfile, time.Now().AddDate(0, 0, -90), 300)
		if len(g.Changes) > 0 {
			b.WriteString("\n# Git: commits that changed package.json or the lockfile (newest first)\n")
			for i, c := range g.Changes {
				if i == n {
					fmt.Fprintf(&b, "… %d more\n", len(g.Changes)-n)
					break
				}
				switch {
				case c.Uncommitted:
					fmt.Fprintf(&b, "\n## not committed yet (lockfile on disk differs from HEAD)\n")
				default:
					fmt.Fprintf(&b, "\n## %s %s — %s\n", c.Hash[:7], c.At.Format("2006-01-02"), untrusted(c.Subject, 140))
				}
				if c.Manifest {
					b.WriteString("package.json changed, package versions did not.\n")
				}
				writePkgs(&b, c.Pkgs)
			}
		}
	}
	return b.String(), nil
}

// writePkgs lists the package versions that changed in a scan (direct ones first).
func writePkgs(b *strings.Builder, p *history.PkgDiff) {
	if p == nil || len(p.Changes) == 0 {
		return
	}
	const show = 40
	b.WriteString("Package versions changed:\n")
	for i, c := range p.Changes {
		if i == show {
			fmt.Fprintf(b, "- … and %d more\n", len(p.Changes)-show+p.More)
			return
		}
		where := "transitive"
		if c.Direct {
			where = "direct"
		}
		switch c.Kind {
		case "add":
			fmt.Fprintf(b, "- added %s@%s (%s)\n", c.Name, c.To, where)
		case "remove":
			fmt.Fprintf(b, "- removed %s@%s (%s)\n", c.Name, c.From, where)
		case "down":
			fmt.Fprintf(b, "- DOWNGRADED %s %s → %s (%s)\n", c.Name, c.From, c.To, where)
		default:
			fmt.Fprintf(b, "- %s %s → %s (%s)\n", c.Name, c.From, c.To, where)
		}
	}
	if p.More > 0 {
		fmt.Fprintf(b, "- … and %d more\n", p.More)
	}
}

func sevOf(it history.Item) string {
	var p []string
	if it.Sev != "" {
		p = append(p, it.Sev)
	}
	if it.Target != "" {
		p = append(p, "→ "+it.Target)
	}
	if it.Title != "" {
		p = append(p, untrusted(it.Title, 100))
	}
	if len(p) == 0 {
		return ""
	}
	return " (" + strings.Join(p, ", ") + ")"
}

func spec(it history.Item) string {
	if it.Ver == "" {
		return it.Pkg
	}
	return it.Pkg + "@" + it.Ver
}
