package mcp

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ali7Zeynalli/depgate/internal/store"
)

func TestHTTPWithoutProjectAndHostPaths(t *testing.T) {
	home := t.TempDir()
	app := filepath.Join(home, "projects", "shop")
	project(t, app, "shop")
	x, st := newSession(t, t.TempDir())
	_, _ = st.Add(store.Entry{Dir: app})
	x.s.Roots = []string{home}
	h := x.s.HTTPHandler()
	post := func(body string) map[string]any {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/mcp", strings.NewReader(body)))
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return m
	}
	// one registration for all projects: "project" becomes required
	ts := post(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)["result"].(map[string]any)["tools"].([]any)
	for _, x := range ts {
		m := x.(map[string]any)
		req, _ := m["inputSchema"].(map[string]any)["required"].([]any)
		needs := len(req) > 0 && req[0] == "project"
		if m["name"] == "project_status" && !needs || m["name"] == "check_package" && needs || m["name"] == "list_projects" && needs {
			t.Fatalf("%s required %v", m["name"], req)
		}
	}
	// no project: a clear answer naming the known projects, not the server's own folder
	if s, isErr := text(t, post(callTool("project_status", 2, nil))); !isErr || !strings.Contains(s, "working directory") || !strings.Contains(s, app) {
		t.Fatalf("no project: %s", s)
	}
	if s, _ := text(t, post(callTool("project_status", 3, map[string]any{"project": app}))); !strings.Contains(s, "# shop") {
		t.Fatalf("with project: %s", s)
	}
	// Docker on Windows: the agent passes the path as Windows sees it
	t.Setenv("HOME", home)
	t.Setenv("DEPGATE_HOST_HOME", `C:\Users\Ali`)
	for _, p := range []string{`C:\Users\Ali\projects\shop`, `c:/users/ali/projects/shop/`, `/c/Users/Ali/projects/shop`, `/mnt/c/Users/Ali/projects/shop`} {
		if s, _ := text(t, post(callTool("project_status", 4, map[string]any{"project": p}))); !strings.Contains(s, "# shop") {
			t.Fatalf("%s: %s", p, s)
		}
	}
	if hostToLocal(`D:\work\x`) != `D:\work\x` || hostToLocal(`C:\Users\Alice\x`) != `C:\Users\Alice\x` {
		t.Fatal("only the mounted home is mapped")
	}
	// prompts: what DepGate can do, visible in the agent
	ps := post(`{"jsonrpc":"2.0","id":5,"method":"prompts/list"}`)["result"].(map[string]any)["prompts"].([]any)
	if len(ps) != 5 || ps[0].(map[string]any)["name"] != "fix" {
		t.Fatalf("prompts %v", ps)
	}
	g := post(`{"jsonrpc":"2.0","id":6,"method":"prompts/get","params":{"name":"check","arguments":{"package":"lodash","version":"4.17.20"}}}`)
	msg := g["result"].(map[string]any)["messages"].([]any)[0].(map[string]any)["content"].(map[string]any)["text"].(string)
	if !strings.Contains(msg, "check_package for lodash@4.17.20") {
		t.Fatalf("prompt %s", msg)
	}
	if e := post(`{"jsonrpc":"2.0","id":7,"method":"prompts/get","params":{"name":"check"}}`)["error"]; e == nil {
		t.Fatal("missing argument must be an error")
	}
	init := post(`{"jsonrpc":"2.0","id":8,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)["result"].(map[string]any)
	if init["capabilities"].(map[string]any)["prompts"] == nil {
		t.Fatal("prompts capability")
	}
}
