package mcp

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ali7Zeynalli/depgate/internal/store"
)

func TestActivityAndHistoryStdio(t *testing.T) {
	root := t.TempDir()
	web := filepath.Join(root, "web")
	project(t, web, "web")
	x, st := newSession(t, web)
	_, _ = st.Add(store.Entry{Dir: web})
	got := x.call(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"claude-code","version":"2.1.4"}}}`,
		callTool("scan_project", 2, nil),
		callTool("check_package", 3, map[string]any{"name": "flatmap-stream"}),
		callTool("scan_project", 4, nil),
		callTool("get_history", 5, nil),
	)
	h, _ := text(t, got["5"])
	if !strings.Contains(h, "by mcp (claude-code 2.1.4)") || !strings.Contains(h, "No change since the scan before.") || !strings.Contains(h, "First scan.") {
		t.Fatalf("history: %s", h)
	}
	if n := len(st.History.Scans(web)); n != 2 {
		t.Fatalf("scans %d", n)
	}
	ev := st.History.Events(root, 20)
	if len(ev) != 5 || ev[4].Tool != "connect" || ev[4].Agent != "claude-code 2.1.4" || ev[4].Via != "stdio" {
		t.Fatalf("events %+v", ev)
	}
	var check bool
	for _, e := range ev {
		if e.Tool == "check_package" {
			check = e.Verdict == "block" && strings.HasPrefix(e.Target, "flatmap-stream@") && e.Project == web
		}
	}
	if !check {
		t.Fatalf("check_package event %+v", ev)
	}
}

func TestHTTPAgentName(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a")
	project(t, a, "proj-a")
	x, st := newSession(t, t.TempDir())
	_, _ = st.Add(store.Entry{Dir: a})
	h := x.s.HTTPHandler()
	post := func(sid, ua, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/mcp?project="+a, strings.NewReader(body))
		if sid != "" {
			req.Header.Set("Mcp-Session-Id", sid)
		}
		req.Header.Set("User-Agent", ua)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	rec := post("", "x", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"cursor","version":"1.2"}}}`)
	sid := rec.Header().Get("Mcp-Session-Id")
	if sid == "" || agentFromSession(sid) != "cursor 1.2" {
		t.Fatalf("session id %q", sid)
	}
	post(sid, "x", callTool("project_status", 2, nil))
	post("", "codex/0.9 (linux)", callTool("project_status", 3, nil))
	ev := st.History.Events("", 10)
	if len(ev) != 3 || ev[0].Agent != "codex 0.9" || ev[1].Agent != "cursor 1.2" || ev[1].Via != "http" || ev[1].Project != a {
		t.Fatalf("events %+v", ev)
	}
}
