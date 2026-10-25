// Package web serves the local UI. It binds to 127.0.0.1 by default; in a
// container it may listen on 0.0.0.0 behind a host port published to
// 127.0.0.1. Every request needs the access token (cookie) and an allowed Host.
package web

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/Ali7Zeynalli/depgate/internal/app"
	"github.com/Ali7Zeynalli/depgate/internal/auth"
)

//go:embed ui
var uiFS embed.FS

// Backend is what the UI talks to (implemented by app.Manager).
type Backend interface {
	State() app.State
	Scan(dirs []string) error
	Add(path string) ([]string, error)
	Remove(dir string) error
	Browse(path string) (*app.Listing, error)
}

type Server struct {
	// Token is for automation (Authorization: Bearer, or a one-time ?t= login link).
	Token string
	B     Backend
	// Auth is the user's password; nil together with NoAuth=true disables login.
	Auth   *auth.Auth
	NoAuth bool
	// AllowHosts are extra Host header names (without port) accepted besides localhost.
	AllowHosts []string
	// Log receives one line per rejected Host (nil: no log).
	Log io.Writer

	rejMu    sync.Mutex
	rejected map[string]bool
	machine  string // this computer's name (allowed like an IP)
	// AllowPublic lets clients connect from public (internet) addresses.
	// Off by default: only this computer and the local network / VPN can connect.
	AllowPublic bool
	// MCP serves the Model Context Protocol at /mcp for AI agents (Bearer token only).
	MCP http.Handler
}

// Listen binds addr:port, trying the next ports when busy.
func Listen(addr string, port int) (net.Listener, int, error) {
	if addr == "" {
		addr = "127.0.0.1"
	}
	var lastErr error
	for p := port; p < port+20; p++ {
		ln, err := net.Listen("tcp", net.JoinHostPort(addr, strconv.Itoa(p)))
		if err == nil {
			return ln, p, nil
		}
		lastErr = err
	}
	return nil, 0, lastErr
}

const cookieName = "depgate_session"

// localIP reports addresses that are not reachable from the internet:
// loopback, private (10/8, 172.16/12, 192.168/16, fc00::/7), link-local and
// carrier-grade NAT 100.64/10 (Tailscale and other VPNs).
func localIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true
	}
	_, cgnat, _ := net.ParseCIDR("100.64.0.0/10")
	return cgnat.Contains(ip)
}

// clientOK refuses connections from public addresses unless AllowPublic is set
// or the name the browser used was allowed explicitly (a reverse proxy, a domain).
func (s *Server) clientOK(r *http.Request) bool {
	if s.AllowPublic {
		return true
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		h = r.RemoteAddr
	}
	ip := net.ParseIP(h)
	if ip == nil || localIP(ip) {
		return true
	}
	return s.explicit(r.Host)
}

// explicit reports whether the Host was listed in AllowHosts.
func (s *Server) explicit(h string) bool {
	host := h
	if hh, _, err := net.SplitHostPort(h); err == nil {
		host = hh
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	for _, a := range s.AllowHosts {
		if strings.EqualFold(strings.TrimSpace(a), host) {
			return true
		}
	}
	return false
}

func (s *Server) forbiddenClient(w http.ResponseWriter, r *http.Request) {
	if s.Log != nil {
		s.rejMu.Lock()
		k := "client:" + clientKey(r)
		if s.rejected == nil {
			s.rejected = map[string]bool{}
		}
		if !s.rejected[k] && len(s.rejected) < 50 {
			s.rejected[k] = true
			fmt.Fprintf(s.Log, "depgate: refused a connection from the internet (%s) — DepGate answers this computer, the local network and VPNs; behind an HTTPS proxy set DEPGATE_ALLOW_HOSTS=<your domain>, or DEPGATE_ALLOW_PUBLIC=1\n", clientKey(r))
		}
		s.rejMu.Unlock()
	}
	http.Error(w, "DepGate is not open to the internet", http.StatusForbidden)
}

// SetMachineName allows the computer's own name (and name.local / name.lan) as Host.
func (s *Server) SetMachineName(n string) { s.machine = strings.ToLower(strings.TrimSpace(n)) }

func (s *Server) hostOK(h string) bool {
	host := h
	if hh, _, err := net.SplitHostPort(h); err == nil {
		host = hh
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	// An IP address is always fine: DNS rebinding needs a domain name (the
	// browser then sends that name as Host), so a bare IP only comes from you
	// typing it. Cross-site requests to the IP are still stopped by the
	// X-DepGate header and the SameSite session cookie.
	if ip := net.ParseIP(host); ip != nil && localIP(ip) {
		return true
	}
	if s.machine != "" && (host == s.machine || host == s.machine+".local" || host == s.machine+".lan") {
		return true
	}
	for _, a := range s.AllowHosts {
		if strings.EqualFold(strings.TrimSpace(a), host) {
			return true
		}
	}
	return false
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	sub, _ := fs.Sub(uiFS, "ui")
	static := http.FileServer(http.FS(sub))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, s.B.State()) })
	mux.HandleFunc("POST /api/scan", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Dirs []string `json:"dirs"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		if err := s.B.Scan(req.Dirs); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, s.B.State())
	})
	mux.HandleFunc("POST /api/projects", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Path string `json:"path"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		dirs, err := s.B.Add(req.Path)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"added": dirs, "state": s.B.State()})
	})
	mux.HandleFunc("POST /api/projects/remove", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Dir  string   `json:"dir"`
			Dirs []string `json:"dirs"` // a whole folder group at once
		}
		if !readJSON(w, r, &req) {
			return
		}
		if req.Dir != "" {
			req.Dirs = append(req.Dirs, req.Dir)
		}
		for _, d := range req.Dirs {
			if err := s.B.Remove(d); err != nil {
				writeErr(w, err)
				return
			}
		}
		writeJSON(w, http.StatusOK, s.B.State())
	})
	mux.HandleFunc("GET /api/browse", func(w http.ResponseWriter, r *http.Request) {
		l, err := s.B.Browse(r.URL.Query().Get("path"))
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, l)
	})
	mux.HandleFunc("GET /api/mcp", func(w http.ResponseWriter, r *http.Request) {
		// what the "AI agent (MCP)" dialog needs to build a connection for this server
		writeJSON(w, http.StatusOK, map[string]any{"enabled": s.MCP != nil, "token": s.Token})
	})
	mux.Handle("GET /", static)

	// ---- authentication (reachable without a session) ----
	authMux := http.NewServeMux()
	authMux.HandleFunc("GET /api/auth", func(w http.ResponseWriter, r *http.Request) {
		st := map[string]bool{"authed": s.authed(r), "noAuth": s.NoAuth}
		if s.Auth != nil {
			st["setup"] = !s.Auth.Configured()
			st["fromEnv"] = s.Auth.FromEnv()
		}
		writeJSON(w, http.StatusOK, st)
	})
	authMux.HandleFunc("POST /api/auth/setup", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		if !readJSON(w, r, &req) || s.Auth == nil {
			return
		}
		if err := s.Auth.Setup(req.Password); err != nil {
			writeAuthErr(w, err)
			return
		}
		s.login(w, r, true)
	})
	authMux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
			Remember bool   `json:"remember"`
		}
		if !readJSON(w, r, &req) || s.Auth == nil {
			return
		}
		if err := s.Auth.Check(clientKey(r), req.Password); err != nil {
			writeAuthErr(w, err)
			return
		}
		s.login(w, r, req.Remember)
	})
	authMux.HandleFunc("POST /api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	authMux.HandleFunc("POST /api/auth/password", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Current string `json:"current"`
			Next    string `json:"next"`
		}
		if !readJSON(w, r, &req) || s.Auth == nil {
			return
		}
		if !s.authed(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required", "error_az": "giriş lazımdır"})
			return
		}
		if err := s.Auth.Change(clientKey(r), req.Current, req.Next); err != nil {
			writeAuthErr(w, err)
			return
		}
		s.login(w, r, true) // the key rotated: issue a fresh session for this browser
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.clientOK(r) { // reachable from the internet by mistake: refuse
			s.forbiddenClient(w, r)
			return
		}
		if !s.hostOK(r.Host) { // DNS-rebinding guard
			s.forbiddenHost(w, r)
			return
		}
		if r.URL.Path == "/healthz" { // container health check: no data
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "ok\n")
			return
		}
		if r.URL.Path == "/mcp" && s.MCP != nil {
			// agents, not browsers: token only, and a browser origin must be this server
			if o := r.Header.Get("Origin"); o != "" {
				u, err := url.Parse(o)
				if err != nil || !s.hostOK(u.Host) {
					http.Error(w, "forbidden origin", http.StatusForbidden)
					return
				}
			}
			if !s.bearer(r) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="depgate"`)
				http.Error(w, "Authorization: Bearer <DepGate token> required", http.StatusUnauthorized)
				return
			}
			s.MCP.ServeHTTP(w, r)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")

		// one-time login link for automation and as a fallback
		if t := r.URL.Query().Get("t"); t != "" {
			if s.Token == "" || subtle.ConstantTimeCompare([]byte(t), []byte(s.Token)) != 1 {
				http.Error(w, "bad token", http.StatusForbidden)
				return
			}
			if s.Auth != nil && s.Auth.Configured() {
				s.setSession(w, r, true)
			}
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			static.ServeHTTP(w, r) // the UI shell holds no data; it shows the login screen itself
			return
		}
		// every API call must carry the custom header (blocks cross-site form posts)
		if r.Header.Get("X-DepGate") != "1" && !s.bearer(r) {
			http.Error(w, "missing header", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/api/auth" || strings.HasPrefix(r.URL.Path, "/api/auth/") {
			authMux.ServeHTTP(w, r)
			return
		}
		if !s.authed(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required", "error_az": "giriş lazımdır"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) bearer(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	return s.Token != "" && strings.HasPrefix(h, "Bearer ") && subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(h, "Bearer ")), []byte(s.Token)) == 1
}

func (s *Server) authed(r *http.Request) bool {
	if s.NoAuth || s.bearer(r) {
		return true
	}
	if s.Auth == nil {
		return false
	}
	c, err := r.Cookie(cookieName)
	return err == nil && s.Auth.Valid(c.Value)
}

func (s *Server) setSession(w http.ResponseWriter, r *http.Request, remember bool) {
	ttl := auth.ShortSession
	if remember {
		ttl = auth.LongSession
	}
	v, err := s.Auth.Issue(ttl)
	if err != nil {
		return
	}
	c := &http.Cookie{Name: cookieName, Value: v, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")}
	if remember {
		c.MaxAge = int(ttl.Seconds())
	}
	http.SetCookie(w, c)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request, remember bool) {
	s.setSession(w, r, remember)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func clientKey(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func writeAuthErr(w http.ResponseWriter, err error) {
	code, az := http.StatusBadRequest, err.Error()
	switch {
	case errors.Is(err, auth.ErrWrong):
		code, az = http.StatusUnauthorized, "parol yanlışdır"
	case errors.Is(err, auth.ErrLocked):
		code, az = http.StatusTooManyRequests, "çox cəhd edildi, bir az gözlə"
	case errors.Is(err, auth.ErrTooShort):
		az = "parol ən azı 8 simvol olmalıdır"
	case errors.Is(err, auth.ErrHasPassword):
		code, az = http.StatusConflict, "parol artıq təyin olunub"
	case errors.Is(err, auth.ErrNoPassword):
		code, az = http.StatusConflict, "hələ parol təyin olunmayıb"
	}
	en := err.Error()
	if errors.Is(err, auth.ErrTooShort) {
		en = "password must be at least 8 characters"
	}
	writeJSON(w, code, map[string]string{"error": en, "error_az": az})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request", "error_az": "yanlış sorğu"})
		return false
	}
	return true
}

func writeErr(w http.ResponseWriter, err error) {
	code := http.StatusBadRequest
	switch {
	case errors.Is(err, app.ErrReadOnly):
		code = http.StatusConflict
	case errors.Is(err, app.ErrOutside):
		code = http.StatusForbidden
	}
	out := map[string]string{"error": err.Error()}
	var le *app.Error
	if errors.As(err, &le) {
		out["error"], out["error_az"] = le.T.En, le.T.Az
	}
	writeJSON(w, code, out)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// NewToken returns a random 128-bit hex token.
func NewToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// forbiddenHost explains how to allow the name the browser used: a name other
// than localhost, an IP or this computer's name needs DEPGATE_ALLOW_HOSTS (--allow-host).
func (s *Server) forbiddenHost(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if s.Log != nil {
		s.rejMu.Lock()
		if s.rejected == nil {
			s.rejected = map[string]bool{}
		}
		if !s.rejected[host] && len(s.rejected) < 50 {
			s.rejected[host] = true
			fmt.Fprintf(s.Log, "depgate: rejected Host %q from %s — to allow it, set DEPGATE_ALLOW_HOSTS=%s (or --allow-host %s)\n", r.Host, r.RemoteAddr, host, host)
		}
		s.rejMu.Unlock()
	}
	safe := html.EscapeString(host)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DepGate — address not allowed</title>
<body style="font:15px/1.5 system-ui,sans-serif;max-width:640px;margin:8vh auto;padding:0 16px">
<h1 style="font-size:20px">DepGate: this address is not allowed</h1>
<p>DepGate only answers to the addresses you allow, so other websites cannot reach it through your browser (DNS rebinding). You opened it as <b>%[1]s</b>.</p>
<p>Allow it on the server and restart DepGate:</p>
<pre style="background:#f2f3f5;padding:10px;border-radius:8px;overflow:auto">DEPGATE_ALLOW_HOSTS=%[1]s   # docker-compose: under environment, or in .env
depgate --addr 0.0.0.0 --allow-host %[1]s   # without Docker</pre>
<hr style="border:0;border-top:1px solid #ddd;margin:24px 0">
<h1 style="font-size:20px">DepGate: bu ünvana icazə yoxdur</h1>
<p>DepGate yalnız icazə verdiyin ünvanlara cavab verir ki, başqa saytlar brauzerin vasitəsilə ona çata bilməsin (DNS rebinding). Sən onu <b>%[1]s</b> ünvanı ilə açmısan.</p>
<p>Serverdə bu ünvana icazə ver və DepGate-i yenidən başlat: <code>DEPGATE_ALLOW_HOSTS=%[1]s</code></p>
</body>`, safe)
}
