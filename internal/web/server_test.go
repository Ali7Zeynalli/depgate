package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Ali7Zeynalli/depgate/internal/report"
)

func newSrv() (*Server, http.Handler) {
	s := &Server{Token: "secret123", Rescan: func() *report.Report { return &report.Report{Schema: report.Schema, Tool: "rescanned"} }}
	s.Set(&report.Report{Schema: report.Schema, Tool: "first"})
	return s, s.Handler(7777)
}

func do(h http.Handler, method, path, host string, mod func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
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
	if w := do(h, "GET", "/api/report", "evil.example:7777", authed); w.Code != http.StatusForbidden {
		t.Fatalf("foreign host allowed: %d", w.Code)
	}
	if w := do(h, "GET", "/api/report", "localhost:7777", authed); w.Code != http.StatusOK {
		t.Fatalf("localhost rejected: %d", w.Code)
	}
}

func TestTokenFlow(t *testing.T) {
	_, h := newSrv()
	if w := do(h, "GET", "/", "127.0.0.1:7777", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", w.Code)
	}
	if w := do(h, "GET", "/?t=wrong", "127.0.0.1:7777", nil); w.Code != http.StatusForbidden {
		t.Fatalf("wrong token: %d", w.Code)
	}
	w := do(h, "GET", "/?t=secret123", "127.0.0.1:7777", nil)
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Set-Cookie"), "HttpOnly") || !strings.Contains(w.Header().Get("Set-Cookie"), "SameSite=Strict") {
		t.Fatalf("token exchange: %d %q", w.Code, w.Header().Get("Set-Cookie"))
	}
	w = do(h, "GET", "/", "127.0.0.1:7777", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: cookieName, Value: "secret123"}) })
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "DepGate") {
		t.Fatalf("index: %d", w.Code)
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("csp %q", csp)
	}
}

func TestAPIHeaderRequired(t *testing.T) {
	_, h := newSrv()
	w := do(h, "POST", "/api/rescan", "127.0.0.1:7777", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: cookieName, Value: "secret123"}) })
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing header allowed: %d", w.Code)
	}
	w = do(h, "POST", "/api/rescan", "127.0.0.1:7777", authed)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "rescanned") {
		t.Fatalf("rescan: %d %s", w.Code, w.Body.String())
	}
	w = do(h, "GET", "/api/report", "127.0.0.1:7777", authed)
	if !strings.Contains(w.Body.String(), "rescanned") {
		t.Fatalf("report not updated: %s", w.Body.String())
	}
}
