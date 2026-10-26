package history

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/report"
)

func proj(at time.Time, fs ...report.Finding) *report.Project {
	return &report.Project{Dir: "/p", ScannedAt: at, Findings: fs}
}

func TestCompare(t *testing.T) {
	at := time.Now().UTC()
	a := FromProject(proj(at,
		report.Finding{Kind: "vuln", Pkg: "next", Current: "14.2.3", Group: report.GroupNowEasy, Severity: "high", Target: "14.2.25"},
		report.Finding{Kind: "vuln", Pkg: "axios", Current: "1.0.0", Group: report.GroupNowEasy, Severity: "moderate"},
		report.Finding{Kind: "update", Pkg: "zod", Current: "3.0.0", Group: report.GroupOptional}, // churn: not kept
	), "ui", "", "aaa")
	if len(a.Items) != 2 {
		t.Fatalf("items %v", a.Items)
	}
	p := proj(at.Add(time.Hour),
		report.Finding{Kind: "vuln", Pkg: "next", Current: "14.2.3", Group: report.GroupNowEasy, Severity: "critical", Target: "14.2.25"},
		report.Finding{Kind: "malware", Pkg: "evil", Current: "1.0.0", Group: report.GroupNowEasy},
	)
	p.Docker = []report.DockerIssue{{File: "Dockerfile", Rule: "dockerfile-root-user", Severity: "high", Title: i18n.T{En: "root"}}}
	b := FromProject(p, "mcp", "claude-code 2.1", "aaa")
	d := Compare(&a, &b)
	if len(d.New) != 2 || len(d.Fixed) != 1 || d.Fixed[0].Pkg != "axios" || len(d.Changed) != 1 || d.Changed[0].Sev != "critical" || d.LockChanged {
		t.Fatalf("diff %+v", d)
	}
	b.Lock = "bbb"
	if !Compare(&a, &b).LockChanged || !Compare(nil, &b).First || !Compare(&b, &b).Same() {
		t.Fatal("lock / first / same")
	}
}

func TestLogTrimAndEvents(t *testing.T) {
	l := &Log{Dir: t.TempDir()}
	old := time.Now().Add(-100 * 24 * time.Hour)
	_ = l.AddScan("/p", Scan{At: old, By: "ui"})
	for i := 0; i < keepScans+25; i++ {
		_ = l.AddScan("/p", Scan{At: time.Now().Add(time.Duration(i) * time.Second), By: "cli"})
	}
	s := l.Scans("/p")
	if len(s) < keepScans || len(s) > keepScans+20 || s[0].At.Before(s[1].At) {
		t.Fatalf("kept %d, newest first? %v", len(s), s[0].At)
	}
	for _, x := range s {
		if x.At.Equal(old) || x.By == "ui" {
			t.Fatal("old scan kept")
		}
	}
	_ = l.AddEvent(Event{At: time.Now(), Agent: "a", Tool: "check_package", Project: "/w/p1"})
	_ = l.AddEvent(Event{At: time.Now(), Agent: "b", Tool: "get_fix_plan", Project: "/w/p2/apps/x"})
	_ = l.AddEvent(Event{At: time.Now(), Agent: "c", Tool: "connect", Project: "/other"})
	if e := l.Events("/w", 10); len(e) != 2 || e[0].Agent != "b" {
		t.Fatalf("events %v", e)
	}
	if e := l.Events("", 1); len(e) != 1 || e[0].Agent != "c" {
		t.Fatalf("all %v", e)
	}
	if err := l.Clear("/w", []string{"/p"}); err != nil {
		t.Fatal(err)
	}
	if len(l.Scans("/p")) != 0 || len(l.Events("", 10)) != 1 {
		t.Fatal("clear")
	}
}

func TestLockFingerprint(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "apps", "web")
	_ = os.MkdirAll(sub, 0o755)
	_ = os.WriteFile(filepath.Join(root, "pnpm-lock.yaml"), []byte("a"), 0o644)
	f := LockFingerprint(sub, "pnpm-lock.yaml")
	_ = os.WriteFile(filepath.Join(root, "pnpm-lock.yaml"), []byte("b"), 0o644)
	if f == "" || f == LockFingerprint(sub, "pnpm-lock.yaml") || LockFingerprint(sub, "") != "" {
		t.Fatal("fingerprint")
	}
}
