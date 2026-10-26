package app

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/history"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/store"
)

func TestHistoryOfFolder(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	_, _ = st.Add(store.Entry{Dir: a, Group: root}, store.Entry{Dir: b, Group: root})
	m := &Manager{Store: st}
	at := time.Now().UTC()
	st.RecordScan(&report.Project{Dir: a, ScannedAt: at}, "ui", "")
	st.RecordScan(&report.Project{Dir: a, ScannedAt: at.Add(time.Minute), Findings: []report.Finding{{Kind: "vuln", Pkg: "x", Current: "1.0.0", Group: report.GroupNowEasy}}}, "mcp", "codex 1")
	now := time.Now().UTC()
	_ = st.History.AddEvent(history.Event{At: now.Add(-time.Hour), Agent: "codex 1", Via: "http", Tool: "check_package", Verdict: "block", Project: b})
	_ = st.History.AddEvent(history.Event{At: now, Agent: "codex 1", Via: "http", Tool: "connect", Project: a})
	_ = st.History.AddEvent(history.Event{At: now, Agent: "else", Via: "http", Tool: "get_findings", Project: "/elsewhere"})
	h, err := m.History(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Projects) != 2 || len(h.Projects[0].Scans) != 2 || len(h.Projects[0].Scans[0].Diff.New) != 1 || h.Projects[0].Scans[0].Items != nil {
		t.Fatalf("projects %+v", h.Projects)
	}
	if len(h.Events) != 2 || len(h.Agents) != 1 || h.Agents[0].Calls != 1 || h.Agents[0].Blocked != 1 || !h.Agents[0].Last.Equal(now) {
		t.Fatalf("agents %+v", h.Agents)
	}
	if err := m.ClearHistory(root); err != nil {
		t.Fatal(err)
	}
	if h, _ := m.History(root, false); len(h.Events) != 0 || len(h.Projects[0].Scans) != 0 {
		t.Fatal("not cleared")
	}
	if err := st.Remove(a); err != nil || len(st.History.Scans(a)) != 0 {
		t.Fatal("remove")
	}
}

func TestKPI(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC) // a Wednesday
	it := func(k, sev, grp string) history.Item {
		return history.Item{Key: k, Pkg: k, Sev: sev, Group: grp, Kind: "vuln"}
	}
	day := func(d int) time.Time { return now.Add(-time.Duration(d) * 24 * time.Hour) }
	scans := []history.Scan{ // newest first
		{At: day(0), Items: []history.Item{it("a", "high", "now_easy"), it("c", "moderate", "plan")}, Summary: report.Summary{NowEasy: 1}},
		{At: day(2), Items: []history.Item{it("a", "high", "now_easy"), it("b", "critical", "now_easy")}, Summary: report.Summary{NowEasy: 2}},
		{At: day(10), Items: []history.Item{it("a", "high", "now_easy")}, Summary: report.Summary{NowEasy: 1}},
	}
	k := kpiOf(scans, now)
	// a: open since day 10; b: new on day 2, gone today after 2 days; c: plan (not important)
	if k.OpenUrgent != 1 || k.OldestPkg != "a" || k.OldestDays != 10 {
		t.Fatalf("open %+v", k)
	}
	if k.FixedN != 1 || k.MTTRHours != 48 || k.WeekNew != 1 || k.WeekFixed != 1 {
		t.Fatalf("mttr/week %+v", k)
	}
	if len(k.Weeks) != 8 || k.Weeks[7].Fixed != 1 || k.Weeks[7].New != 1 || len(k.Trend) != 3 || k.Trend[2].Urgent != 1 {
		t.Fatalf("series %+v", k)
	}
	s := sumKPI([]ProjectHistory{{Dir: "/x", KPI: k}, {Dir: "/y", KPI: kpiOf(nil, now)}})
	if s.OpenUrgent != 1 || s.OldestDir != "/x" || s.MTTRHours != 48 {
		t.Fatalf("sum %+v", s)
	}
	// Node.js "do now" counts as an open task since the first scan in a row that said so
	scans[0].Node, scans[0].NodeNeed = "22.20.0", "now"
	scans[1].Node, scans[1].NodeNeed = "22.20.0", "now"
	if k := kpiOf(scans, now); k.OpenUrgent != 2 || k.OldestPkg != "a" {
		t.Fatalf("node %+v", k)
	}
	scans[2].Node, scans[2].NodeNeed = "22.20.0", "now"
	scans[2].Items = nil
	if k := kpiOf(scans, now); k.OpenUrgent != 2 || k.OldestPkg != "Node.js 22.20.0" || k.OldestDays != 10 {
		t.Fatalf("node oldest %+v", k)
	}
}

func TestHistoryOnlyThisProject(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	root := t.TempDir()
	api := filepath.Join(root, "apps", "api")
	_, _ = st.Add(store.Entry{Dir: root, Group: root}, store.Entry{Dir: api, Group: root})
	st.RecordScan(&report.Project{Dir: root, ScannedAt: time.Now()}, "ui", "")
	st.RecordScan(&report.Project{Dir: api, ScannedAt: time.Now()}, "ui", "")
	_ = st.History.AddEvent(history.Event{At: time.Now(), Agent: "a", Tool: "connect", Project: api})
	_ = st.History.AddEvent(history.Event{At: time.Now(), Agent: "b", Tool: "connect", Project: root})
	m := &Manager{Store: st}
	all, _ := m.History(root, false)
	one, _ := m.History(root, true)
	if len(all.Projects) != 2 || len(one.Projects) != 1 || one.Projects[0].Dir != root || len(all.Events) != 2 || len(one.Events) != 1 || one.Events[0].Agent != "b" {
		t.Fatalf("all %d/%d one %d/%d", len(all.Projects), len(all.Events), len(one.Projects), len(one.Events))
	}
}
