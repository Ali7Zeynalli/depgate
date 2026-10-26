package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ali7Zeynalli/depgate/internal/store"
)

func TestTaskFlow(t *testing.T) {
	root := t.TempDir()
	web := filepath.Join(root, "web")
	project(t, web, "web")
	x, st := newSession(t, web)
	_, _ = st.Add(store.Entry{Dir: web})
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"claude-code","version":"2.1.4"}}}`

	// before start_tasks, get_task refuses
	got := x.call(initReq, callTool("get_overview", 2, nil), callTool("get_task", 3, map[string]any{"task": "now"}))
	ov, _ := text(t, got["2"])
	if !strings.Contains(ov, "STOP before changing anything") || !strings.Contains(ov, "**now**") || !strings.Contains(ov, "next 14.2.3 → 14.2.25") {
		t.Fatalf("overview: %s", ov)
	}
	if msg, isErr := text(t, got["3"]); !isErr || !strings.Contains(msg, "start_tasks") {
		t.Fatalf("get_task without session: %s", msg)
	}

	got = x.call(initReq, callTool("start_tasks", 2, map[string]any{"tasks": []string{"now", "docker"}}),
		callTool("get_task", 3, nil), callTool("get_task", 4, map[string]any{"task": "plan"}), callTool("complete_task", 5, map[string]any{"task": "now"}))
	if s, _ := text(t, got["2"]); !strings.Contains(s, "1. now") || !strings.Contains(s, "Not in the checklist (ignored): docker") {
		t.Fatalf("start: %s", s)
	}
	if s, _ := text(t, got["3"]); !strings.Contains(s, "# Task now") || !strings.Contains(s, "complete_task") {
		t.Fatalf("get_task: %s", s)
	}
	if s, isErr := text(t, got["4"]); !isErr || !strings.Contains(s, "did not choose") {
		t.Fatalf("other task: %s", s)
	}
	if s, _ := text(t, got["5"]); !strings.Contains(s, "NOT DONE") {
		t.Fatalf("complete before fixing: %s", s)
	}

	// the agent updates next; DepGate's new scan verifies it
	lock := `{"name":"web","lockfileVersion":3,"packages":{"":{"name":"web","dependencies":{"next":"^14.2.3"}},"node_modules/next":{"version":"14.2.25"}}}`
	if err := os.WriteFile(filepath.Join(web, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	got = x.call(initReq, callTool("complete_task", 2, map[string]any{"task": "now", "note": "npm i next@14.2.25"}))
	if s, _ := text(t, got["2"]); !strings.Contains(s, "VERIFIED") || !strings.Contains(s, "All chosen tasks are finished") {
		t.Fatalf("complete: %s", s)
	}
	ws := st.History.Sessions(root)
	if len(ws) != 1 || ws[0].Agent != "claude-code 2.1.4" || ws[0].Tasks[0].Status != "done" || !ws[0].Tasks[0].Items[0].Done || ws[0].Tasks[0].Note == "" {
		t.Fatalf("session %+v", ws)
	}
}
