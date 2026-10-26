package sources

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPCacheOfflineAndRetry(t *testing.T) {
	var hits, flaky atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/ok":
			if r.Header.Get("User-Agent") == "" {
				w.WriteHeader(400)
				return
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/missing":
			w.WriteHeader(404)
		case "/flaky": // fails once, then answers
			if flaky.Add(1) == 1 {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(429)
				return
			}
			_, _ = w.Write([]byte("later"))
		case "/bad":
			w.WriteHeader(403)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	h := NewHTTP(dir, false, "test")

	for i := 0; i < 2; i++ { // the second answer comes from the cache
		if b, err := h.Do(ctx, "GET", srv.URL+"/ok", nil, nil, time.Hour); err != nil || string(b) != `{"ok":true}` {
			t.Fatalf("ok: %q %v", b, err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("cache not used: %d requests", hits.Load())
	}
	// a POST with another body is another cache entry
	_, _ = h.Do(ctx, "POST", srv.URL+"/ok", []byte("a"), nil, time.Hour)
	_, _ = h.Do(ctx, "POST", srv.URL+"/ok", []byte("b"), nil, time.Hour)
	if hits.Load() != 3 {
		t.Fatalf("POST bodies share a cache entry: %d", hits.Load())
	}
	// 404 is remembered too
	for i := 0; i < 2; i++ {
		if _, err := h.Do(ctx, "GET", srv.URL+"/missing", nil, nil, time.Hour); !errors.Is(err, ErrNotFound) {
			t.Fatalf("404: %v", err)
		}
	}
	if hits.Load() != 4 {
		t.Fatalf("404 not cached: %d", hits.Load())
	}
	// 429 with Retry-After: waits and tries again
	if b, err := h.Do(ctx, "GET", srv.URL+"/flaky", nil, nil, 0); err != nil || string(b) != "later" {
		t.Fatalf("retry: %q %v", b, err)
	}
	// other 4xx: an error, no retries
	before := hits.Load()
	if _, err := h.Do(ctx, "GET", srv.URL+"/bad", nil, nil, 0); err == nil || hits.Load()-before != 1 {
		t.Fatalf("403: %v, %d requests", err, hits.Load()-before)
	}
	// offline: only the cache answers
	off := NewHTTP(dir, true, "test")
	if b, err := off.Do(ctx, "GET", srv.URL+"/ok", nil, nil, time.Nanosecond); err != nil || string(b) != `{"ok":true}` {
		t.Fatalf("offline cached: %q %v", b, err)
	}
	if _, err := off.Do(ctx, "GET", srv.URL+"/never", nil, nil, time.Hour); !errors.Is(err, ErrOffline) {
		t.Fatalf("offline uncached: %v", err)
	}
}
