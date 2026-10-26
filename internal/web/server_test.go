package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Ali7Zeynalli/depgate/internal/app"
	"github.com/Ali7Zeynalli/depgate/internal/auth"
)

func init() { auth.Iterations = 1000 }

type fakeBackend struct {
	scanned []string
	added   string
}

func (f *fakeBackend) State() app.State {
	return app.State{Tool: "fake", Projects: []app.ProjectState{}}
}
func (f *fakeBackend) Scan(d []string) error {
	f.scanned = d
	return nil
}
func (f *fakeBackend) Add(p string) ([]string, []string, error) {
	if p == "/etc" {
		return nil, nil, app.ErrOutside
	}
	f.added = p
	return []string{p}, nil, nil
}
func (f *fakeBackend) Remove(string) error { return app.ErrReadOnly }
func (f *fakeBackend) History(d string, _ bool) (*app.History, error) {
	return &app.History{Dir: d, Projects: []app.ProjectHistory{}}, nil
}
func (f *fakeBackend) ClearHistory(string) error                  { return app.ErrReadOnly }
func (f *fakeBackend) SetRescanHours(int) error                   { return app.ErrReadOnly }
func (f *fakeBackend) Accept([]string, string, string, int) error { return app.ErrReadOnly }
func (f *fakeBackend) Unaccept([]string, string) error            { return app.ErrReadOnly }
func (f *fakeBackend) CheckUpdate(context.Context) (*app.Update, error) {
	return nil, app.ErrReadOnly
}
func (f *fakeBackend) Browse(p string) (*app.Listing, error) {
	if p == "/nope" {
		return nil, errors.New("x")
	}
	return &app.Listing{Path: p}, nil
}

type env struct {
	t   *testing.T
	b   *fakeBackend
	s   *Server
	h   http.Handler
	jar []*http.Cookie
}

func newEnv(t *testing.T) *env {
	a, err := auth.Open(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBackend{}
	s := &Server{Token: "secret123", B: b, Auth: a, AllowHosts: []string{"depgate.lan"}}
	return &env{t: t, b: b, s: s, h: s.Handler()}
}

// do sends a request; api=true adds the X-DepGate header; cookies from earlier responses are sent.
func (e *env) do(method, path, body string, api bool, host ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = "127.0.0.1:7777"
	if len(host) > 0 {
		r.Host = host[0]
	}
	if api {
		r.Header.Set("X-DepGate", "1")
	}
	for _, c := range e.jar {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		e.jar = []*http.Cookie{c}
		if c.MaxAge < 0 {
			e.jar = nil
		}
	}
	return w
}

func (e *env) expect(w *httptest.ResponseRecorder, code int, what string) {
	e.t.Helper()
	if w.Code != code {
		e.t.Fatalf("%s: got %d want %d (%s)", what, w.Code, code, w.Body.String())
	}
}

func TestHostCheckAndHealth(t *testing.T) {
	e := newEnv(t)
	e.expect(e.do("GET", "/healthz", "", false), 200, "healthz")
	e.expect(e.do("GET", "/healthz", "", false, "evil.example"), 403, "healthz foreign host")
	e.expect(e.do("GET", "/", "", false, "evil.example:7777"), 403, "foreign host")
	for _, h := range []string{"localhost:9999", "[::1]:7777", "depgate.lan:7777"} {
		e.expect(e.do("GET", "/", "", false, h), 200, h)
	}
}

func TestSetupLoginLogout(t *testing.T) {
	e := newEnv(t)
	// UI shell is public; data is not
	w := e.do("GET", "/", "", false)
	e.expect(w, 200, "index")
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("csp %q", csp)
	}
	e.expect(e.do("GET", "/api/state", "", false), 403, "api without header")
	e.expect(e.do("GET", "/api/state", "", true), 401, "api without session")
	if w := e.do("GET", "/api/auth", "", true); !strings.Contains(w.Body.String(), `"setup":true`) {
		t.Fatalf("auth state %s", w.Body.String())
	}
	e.expect(e.do("POST", "/api/auth/setup", `{"password":"short"}`, true), 400, "short password")
	e.expect(e.do("POST", "/api/auth/setup", `{"password":"correct horse"}`, true), 200, "setup")
	if len(e.jar) == 0 || !e.jar[0].HttpOnly || e.jar[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie %+v", e.jar)
	}
	e.expect(e.do("GET", "/api/state", "", true), 200, "state after setup")
	e.expect(e.do("POST", "/api/auth/setup", `{"password":"another password"}`, true), 409, "second setup")
	// logout → locked again
	e.expect(e.do("POST", "/api/auth/logout", "", true), 200, "logout")
	e.expect(e.do("GET", "/api/state", "", true), 401, "after logout")
	// login
	e.expect(e.do("POST", "/api/auth/login", `{"password":"wrong password"}`, true), 401, "wrong")
	e.expect(e.do("POST", "/api/auth/login", `{"password":"correct horse","remember":true}`, true), 200, "login")
	if e.jar[0].MaxAge <= 0 {
		t.Fatal("remember me did not set a persistent cookie")
	}
	e.expect(e.do("GET", "/api/state", "", true), 200, "state after login")
}

func TestPasswordChangeEndsOtherSessions(t *testing.T) {
	e := newEnv(t)
	e.expect(e.do("POST", "/api/auth/setup", `{"password":"correct horse"}`, true), 200, "setup")
	old := e.jar
	e.expect(e.do("POST", "/api/auth/password", `{"current":"nope nope","next":"battery staple"}`, true), 401, "wrong current")
	e.expect(e.do("POST", "/api/auth/password", `{"current":"correct horse","next":"battery staple"}`, true), 200, "change")
	e.expect(e.do("GET", "/api/state", "", true), 200, "this browser stays logged in")
	e.jar = old
	e.expect(e.do("GET", "/api/state", "", true), 401, "old session after change")
}

func TestTokenAndBearer(t *testing.T) {
	e := newEnv(t)
	_ = e.s.Auth.Setup("correct horse")
	e.expect(e.do("GET", "/?t=wrong", "", false), 403, "wrong token")
	w := e.do("GET", "/?t=secret123", "", false)
	e.expect(w, 302, "token link")
	e.expect(e.do("GET", "/api/state", "", true), 200, "session from token link")
	// bearer for scripts: no cookie, no custom header needed
	e.jar = nil
	r := httptest.NewRequest("GET", "/api/state", nil)
	r.Host = "127.0.0.1:7777"
	r.Header.Set("Authorization", "Bearer secret123")
	rw := httptest.NewRecorder()
	e.h.ServeHTTP(rw, r)
	e.expect(rw, 200, "bearer")
}

func TestAPIWithSession(t *testing.T) {
	e := newEnv(t)
	e.expect(e.do("POST", "/api/auth/setup", `{"password":"correct horse"}`, true), 200, "setup")
	e.expect(e.do("POST", "/api/scan", `{"dirs":["/a"]}`, true), 202, "scan")
	if len(e.b.scanned) != 1 {
		t.Fatal("scan not forwarded")
	}
	e.expect(e.do("POST", "/api/projects", `{"path":"/home/x/app"}`, true), 200, "add")
	e.expect(e.do("POST", "/api/projects", `{"path":"/etc"}`, true), 403, "outside root")
	e.expect(e.do("POST", "/api/projects/remove", `{"dir":"/a"}`, true), 409, "read-only remove")
	e.expect(e.do("POST", "/api/projects", `{bad`, true), 400, "bad json")
	if w := e.do("GET", "/api/browse?path=/x", "", true); w.Code != 200 || !strings.Contains(w.Body.String(), `"/x"`) {
		t.Fatalf("browse %d", w.Code)
	}
}

func TestNoAuth(t *testing.T) {
	e := newEnv(t)
	e.s.NoAuth = true
	e.expect(e.do("GET", "/api/state", "", true), 200, "no-auth state")
	e.expect(e.do("GET", "/api/state", "", false), 403, "custom header still required")
}

func TestMCPEndpointAuth(t *testing.T) {
	called := false
	s := &Server{Token: "tok-0123456789abcdef", NoAuth: false, MCP: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(200) })}
	h := s.Handler()
	do := func(hdr map[string]string) int {
		req := httptest.NewRequest("POST", "http://127.0.0.1:7777/mcp", strings.NewReader("{}"))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := do(nil); c != 401 || called {
		t.Fatalf("no token: %d", c)
	}
	if c := do(map[string]string{"Authorization": "Bearer wrong"}); c != 401 || called {
		t.Fatalf("wrong token: %d", c)
	}
	if c := do(map[string]string{"Authorization": "Bearer tok-0123456789abcdef", "Origin": "https://evil.example"}); c != 403 || called {
		t.Fatalf("foreign origin: %d", c)
	}
	if c := do(map[string]string{"Authorization": "Bearer tok-0123456789abcdef"}); c != 200 || !called {
		t.Fatalf("valid: %d", c)
	}
}
