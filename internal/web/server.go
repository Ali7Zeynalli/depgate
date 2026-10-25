// Package web serves the local report UI on 127.0.0.1 only.
package web

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/report"
)

//go:embed ui
var uiFS embed.FS

// Server holds the current report and knows how to produce a new one.
type Server struct {
	Token  string
	Rescan func() *report.Report

	mu   sync.Mutex
	rep  *report.Report
	port int
	busy sync.Mutex
}

func NewToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Listen binds 127.0.0.1:port, trying the next ports when busy.
func Listen(port int) (net.Listener, int, error) {
	var lastErr error
	for p := port; p < port+20; p++ {
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err == nil {
			return ln, p, nil
		}
		lastErr = err
	}
	return nil, 0, lastErr
}

func (s *Server) Set(r *report.Report) {
	s.mu.Lock()
	s.rep = r
	s.mu.Unlock()
}

const cookieName = "depgate_session"

// Handler returns the HTTP handler. port is used for the Host check.
func (s *Server) Handler(port int) http.Handler {
	s.port = port
	sub, _ := fs.Sub(uiFS, "ui")
	static := http.FileServer(http.FS(sub))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/report", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		rep := s.rep
		s.mu.Unlock()
		writeJSON(w, rep)
	})
	mux.HandleFunc("POST /api/rescan", func(w http.ResponseWriter, r *http.Request) {
		if s.Rescan == nil {
			http.Error(w, "rescan unavailable", http.StatusNotImplemented)
			return
		}
		s.busy.Lock() // one scan at a time
		rep := s.Rescan()
		s.busy.Unlock()
		s.Set(rep)
		writeJSON(w, rep)
	})
	mux.Handle("GET /", static)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// DNS-rebinding guard: only our own host names
		host := r.Host
		okHost := host == "127.0.0.1:"+strconv.Itoa(port) || host == "localhost:"+strconv.Itoa(port)
		if !okHost {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")

		// first visit: ?t=<token> → cookie → clean URL
		if t := r.URL.Query().Get("t"); t != "" {
			if subtle.ConstantTimeCompare([]byte(t), []byte(s.Token)) != 1 {
				http.Error(w, "bad token", http.StatusForbidden)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.Token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: time.Now().Add(24 * time.Hour)})
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		c, err := r.Cookie(cookieName)
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.Token)) != 1 {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("DepGate: terminalda göstərilən linki aç (token lazımdır).\n"))
			return
		}
		// API calls must also carry the custom header (blocks cross-site form posts)
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Header.Get("X-DepGate") != "1" {
			http.Error(w, "missing header", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}
