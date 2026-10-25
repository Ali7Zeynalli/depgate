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
	"strconv"
	"strings"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/app"
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
	Token string
	B     Backend
	// AllowHosts are extra Host header names (without port) accepted besides localhost.
	AllowHosts []string
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
			Dir string `json:"dir"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		if err := s.B.Remove(req.Dir); err != nil {
			writeErr(w, err)
			return
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
	mux.Handle("GET /", static)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostOK(r.Host) { // DNS-rebinding guard
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/healthz" { // container health check: no token, no data
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "ok\n")
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")

		if t := r.URL.Query().Get("t"); t != "" {
			if subtle.ConstantTimeCompare([]byte(t), []byte(s.Token)) != 1 {
				http.Error(w, "bad token", http.StatusForbidden)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.Token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: time.Now().Add(30 * 24 * time.Hour)})
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		c, err := r.Cookie(cookieName)
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.Token)) != 1 {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "DepGate: open the link printed in the terminal (or docker logs) — a token is required.\nDepGate: terminalda (və ya docker logs-da) göstərilən linki aç — token lazımdır.\n")
			return
		}
		// API calls must carry the custom header too (blocks cross-site form posts)
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Header.Get("X-DepGate") != "1" {
			http.Error(w, "missing header", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
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
