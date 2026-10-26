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
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
	History(dir string) (*app.History, error)
	ClearHistory(dir string) error
	SetRescanHours(h int) error
	Accept(dirs []string, key, reason string, days int) error
	Unaccept(dirs []string, key string) error
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
	mux.HandleFunc("GET /api/history", func(w http.ResponseWriter, r *http.Request) {
		h, err := s.B.History(r.URL.Query().Get("dir"))
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, h)
	})
	mux.HandleFunc("POST /api/history/clear", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Dir string `json:"dir"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		if req.Dir == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "dir is required"})
			return
		}
		if err := s.B.ClearHistory(req.Dir); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /api/settings", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RescanHours *int `json:"rescanHours"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		if req.RescanHours != nil {
			if err := s.B.SetRescanHours(*req.RescanHours); err != nil {
				writeErr(w, err)
				return
			}
		}
		writeJSON(w, http.StatusOK, s.B.State())
	})
	mux.HandleFunc("POST /api/accept", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Dirs   []string `json:"dirs"`
			Key    string   `json:"key"`
			Reason string   `json:"reason"`
			Days   int      `json:"days"`
			Remove bool     `json:"remove"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		if len(req.Dirs) == 0 || req.Key == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "dirs and key are required"})
			return
		}
		var err error
		if req.Remove {
			err = s.B.Unaccept(req.Dirs, req.Key)
		} else {
			err = s.B.Accept(req.Dirs, req.Key, req.Reason, req.Days)
		}
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, s.B.State())
	})
	mux.HandleFunc("GET /api/mcp", func(w http.ResponseWriter, r *http.Request) {
		// what the "AI agent (MCP)" dialog needs to build a connection for this server
		// home / hostHome: in Docker, the home folder as the page sees it and as the computer sees it
		// (the agent runs on the computer, so the dialog shows the real path)
		writeJSON(w, http.StatusOK, map[string]any{"enabled": s.MCP != nil, "token": s.Token,
			"home": filepath.Clean(os.Getenv("HOME")), "hostHome": os.Getenv("DEPGATE_HOST_HOME")})
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
		s.login(w, true)
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
		s.login(w, req.Remember)
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
		s.login(w, true) // the key rotated: issue a fresh session for this browser
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostOK(r.Host) { // DNS-rebinding guard
			http.Error(w, "forbidden host", http.StatusForbidden)
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
				s.setSession(w, true)
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

func (s *Server) setSession(w http.ResponseWriter, remember bool) {
	ttl := auth.ShortSession
	if remember {
		ttl = auth.LongSession
	}
	v, err := s.Auth.Issue(ttl)
	if err != nil {
		return
	}
	c := &http.Cookie{Name: cookieName, Value: v, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode}
	if remember {
		c.MaxAge = int(ttl.Seconds())
	}
	http.SetCookie(w, c)
}

func (s *Server) login(w http.ResponseWriter, remember bool) {
	s.setSession(w, remember)
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
