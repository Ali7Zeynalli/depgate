// Package sources fetches public data (OSV, Node.js releases, CISA KEV, EPSS,
// deps.dev, npm registry) with an on-disk cache. Only package names and
// versions ever leave the machine.
package sources

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Fetcher is the transport used by all sources. Tests replace it.
type Fetcher interface {
	// Do performs a GET (body == nil) or POST and returns the response body.
	// ttl is how long a cached response stays fresh; 0 disables caching.
	Do(ctx context.Context, method, url string, body []byte, headers map[string]string, ttl time.Duration) ([]byte, error)
}

// ErrNotFound is returned for HTTP 404.
var ErrNotFound = errors.New("not found")

// ErrOffline is returned in offline mode when nothing is cached.
var ErrOffline = errors.New("offline and not cached")

// HTTP is the real Fetcher: net/http + a file cache + a small rate limit per host.
type HTTP struct {
	Client    *http.Client
	CacheDir  string // "" disables the disk cache
	Offline   bool
	UserAgent string

	mu   sync.Mutex
	last map[string]time.Time
}

func NewHTTP(cacheDir string, offline bool, version string) *HTTP {
	return &HTTP{
		Client:    &http.Client{Timeout: 30 * time.Second},
		CacheDir:  cacheDir,
		Offline:   offline,
		UserAgent: "depgate/" + version + " (+https://github.com/Ali7Zeynalli/depgate)",
		last:      map[string]time.Time{},
	}
}

func (h *HTTP) cachePath(method, url string, body []byte) string {
	if h.CacheDir == "" {
		return ""
	}
	sum := sha256.New()
	sum.Write([]byte(method + " " + url + "\n"))
	sum.Write(body)
	k := hex.EncodeToString(sum.Sum(nil))
	return filepath.Join(h.CacheDir, "http", k[:2], k)
}

func (h *HTTP) Do(ctx context.Context, method, url string, body []byte, headers map[string]string, ttl time.Duration) ([]byte, error) {
	cp := h.cachePath(method, url, body)
	if cp != "" && ttl > 0 {
		if st, err := os.Stat(cp); err == nil {
			if h.Offline || time.Since(st.ModTime()) < ttl {
				if b, err := os.ReadFile(cp); err == nil {
					if bytes.Equal(b, notFoundMarker) {
						return nil, ErrNotFound
					}
					return b, nil
				}
			}
		}
	}
	if h.Offline {
		return nil, fmt.Errorf("%w: %s", ErrOffline, url)
	}
	b, err := h.fetch(ctx, method, url, body, headers)
	if cp != "" && ttl > 0 {
		switch {
		case err == nil:
			writeCache(cp, b)
		case errors.Is(err, ErrNotFound):
			writeCache(cp, notFoundMarker)
		}
	}
	return b, err
}

var notFoundMarker = []byte("\x00depgate:404\x00")

func writeCache(p string, b []byte) {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, p)
	}
}

func (h *HTTP) pace(host string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if t, ok := h.last[host]; ok {
		if d := 50*time.Millisecond - time.Since(t); d > 0 {
			time.Sleep(d)
		}
	}
	h.last[host] = time.Now()
}

func (h *HTTP) fetch(ctx context.Context, method, url string, body []byte, headers map[string]string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, rd)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", h.UserAgent)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		h.pace(req.URL.Host)
		resp, err := h.Client.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
			continue
		}
		b, rerr := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusNotFound:
			return nil, ErrNotFound
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
			wait := time.Duration(attempt+1) * time.Second
			if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 && s <= 30 {
				wait = time.Duration(s) * time.Second
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		case resp.StatusCode >= 400:
			return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
		}
		if rerr != nil {
			return nil, rerr
		}
		return b, nil
	}
	return nil, lastErr
}
