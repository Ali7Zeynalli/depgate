package web

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Ali7Zeynalli/depgate/internal/app"
)

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
func (f *fakeBackend) Add(p string) ([]string, error) {
	if p == "/etc" {
		return nil, app.ErrOutside
	}
	f.added = p
	return []string{p}, nil
}
func (f *fakeBackend) Remove(string) error { return app.ErrReadOnly }
func (f *fakeBackend) Browse(p string) (*app.Listing, error) {
	if p == "/nope" {
		return nil, errors.New("x")
	}
	return &app.Listing{Path: p}, nil
}

func newSrv() (*fakeBackend, http.Handler) {
	b := &fakeBackend{}
	s := &Server{Token: "secret123", B: b, AllowHosts: []string{"depgate.lan"}}
	return b, s.Handler()
}

func do(h http.Handler, method, path, host, body string, mod func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = host
	if mod != nil {
		mod(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func authed(r *http.Request) {
	r.AddCookie(&http.Cookie{Name: cookieName, Value: "secret123"})
	r.Header.Set("X-DepGate", "1")
}

func TestHostCheck(t *testing.T) {
	_, h := newSrv()
	for host, want := range map[string]int{
		"evil.example:7777": http.StatusForbidden,
		"localhost:9999":    http.StatusOK, // published Docker port may differ
		"127.0.0.1:7777":    http.StatusOK,
		"[::1]:7777":        http.StatusOK,
		"depgate.lan:7777":  http.StatusOK,
	} {
		if w := do(h, "GET", "/api/state", host, "", authed); w.Code != want {
			t.Errorf("%s: got %d want %d", host, w.Code, want)
		}
	}
}

func TestTokenFlow(t *testing.T) {
	_, h := newSrv()
	if w := do(h, "GET", "/", "127.0.0.1:7777", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", w.Code)
	}
	if w := do(h, "GET", "/?t=wrong", "127.0.0.1:7777", "", nil); w.Code != http.StatusForbidden {
		t.Fatalf("wrong token: %d", w.Code)
	}
	w := do(h, "GET", "/?t=secret123", "127.0.0.1:7777", "", nil)
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Set-Cookie"), "HttpOnly") || !strings.Contains(w.Header().Get("Set-Cookie"), "SameSite=Strict") {
		t.Fatalf("token exchange: %d %q", w.Code, w.Header().Get("Set-Cookie"))
	}
	w = do(h, "GET", "/", "127.0.0.1:7777", "", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: cookieName, Value: "secret123"}) })
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "DepGate") {
		t.Fatalf("index: %d", w.Code)
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("csp %q", csp)
	}
}

func TestAPI(t *testing.T) {
	b, h := newSrv()
	if w := do(h, "POST", "/api/scan", "127.0.0.1:7777", `{}`, func(r *http.Request) { r.AddCookie(&http.Cookie{Name: cookieName, Value: "secret123"}) }); w.Code != http.StatusForbidden {
		t.Fatalf("missing header allowed: %d", w.Code)
	}
	if w := do(h, "POST", "/api/scan", "127.0.0.1:7777", `{"dirs":["/a"]}`, authed); w.Code != http.StatusAccepted || len(b.scanned) != 1 {
		t.Fatalf("scan: %d %v", w.Code, b.scanned)
	}
	if w := do(h, "POST", "/api/projects", "127.0.0.1:7777", `{"path":"/home/x/app"}`, authed); w.Code != http.StatusOK || b.added != "/home/x/app" {
		t.Fatalf("add: %d", w.Code)
	}
	if w := do(h, "POST", "/api/projects", "127.0.0.1:7777", `{"path":"/etc"}`, authed); w.Code != http.StatusForbidden {
		t.Fatalf("outside root: %d", w.Code)
	}
	if w := do(h, "POST", "/api/projects/remove", "127.0.0.1:7777", `{"dir":"/a"}`, authed); w.Code != http.StatusConflict {
		t.Fatalf("read-only remove: %d", w.Code)
	}
	if w := do(h, "POST", "/api/projects", "127.0.0.1:7777", `{bad`, authed); w.Code != http.StatusBadRequest {
		t.Fatalf("bad json: %d", w.Code)
	}
	if w := do(h, "GET", "/api/browse?path=/x", "127.0.0.1:7777", "", authed); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"/x"`) {
		t.Fatalf("browse: %d %s", w.Code, w.Body.String())
	}
}

func TestHealthz(t *testing.T) {
	_, h := newSrv()
	if w := do(h, "GET", "/healthz", "127.0.0.1:7777", "", nil); w.Code != http.StatusOK || w.Body.String() != "ok\n" {
		t.Fatalf("healthz %d %q", w.Code, w.Body.String())
	}
	if w := do(h, "GET", "/healthz", "evil.example", "", nil); w.Code != http.StatusForbidden {
		t.Fatalf("healthz foreign host %d", w.Code)
	}
}
