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
	h, err := m.History(root)
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
	if h, _ := m.History(root); len(h.Events) != 0 || len(h.Projects[0].Scans) != 0 {
		t.Fatal("not cleared")
	}
	if err := st.Remove(a); err != nil || len(st.History.Scans(a)) != 0 {
		t.Fatal("remove")
	}
}
