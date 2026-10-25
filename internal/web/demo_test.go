package web

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/app"
	"github.com/Ali7Zeynalli/depgate/internal/auth"
	"github.com/Ali7Zeynalli/depgate/internal/decide"
	"github.com/Ali7Zeynalli/depgate/internal/scan"
	"github.com/Ali7Zeynalli/depgate/internal/semver"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
	"github.com/Ali7Zeynalli/depgate/internal/sources/sourcestest"
	"github.com/Ali7Zeynalli/depgate/internal/store"
)

// TestServeDemo starts the full UI on fake data for manual/visual checks:
//
//	DEPGATE_DEMO_ROOT=/path/with/projects DEPGATE_DEMO_PORT=7795 go test -run TestServeDemo ./internal/web -timeout 0
func TestServeDemo(t *testing.T) {
	root := os.Getenv("DEPGATE_DEMO_ROOT")
	if root == "" {
		t.Skip("set DEPGATE_DEMO_ROOT to run the demo server")
	}
	now := time.Now()
	f := sourcestest.New(now)
	f.Match = func(v *sources.Vuln, name, ver string) bool {
		sv, err := semver.Parse(ver)
		return err == nil && decide.Affects(v, name, sv)
	}
	f.Vuln("GHSA-demo-next", "next", "HIGH", "14.0.0", "14.2.25", "Authorization bypass in Next.js middleware", "CVE-2025-29927")
	f.Vuln("GHSA-demo-follow", "follow-redirects", "MODERATE", "0", "1.15.9", "follow-redirects leaks Proxy-Authorization header")
	f.Vuln("GHSA-demo-express", "express", "MODERATE", "0", "5.0.0", "express open redirect (fixed only in 5.x)")
	f.Malware("MAL-2026-demo", "debug", "4.3.4")
	f.EPSS["CVE-2025-29927"] = 0.92
	f.KEV = []string{"CVE-2025-29927"}
	for k, v := range map[string][]string{
		"next": {"14.2.3", "14.2.25", "15.5.6"}, "follow-redirects": {"1.15.6", "1.15.9"}, "express": {"4.19.2", "5.0.0"},
		"debug": {"4.3.3", "4.3.4", "4.4.1"}, "react": {"18.2.0", "18.3.1", "19.2.0"}, "react-dom": {"18.2.0", "18.3.1", "19.2.0"},
		"axios": {"1.6.8", "1.12.2"}, "typescript": {"5.4.5", "5.9.3"}, "lodash": {"4.17.21"}, "make-dir": {"3.1.0", "5.1.0"},
		"nodemon": {"3.1.0", "3.1.10"}, "@types/node": {"20.12.7", "20.19.0"},
	} {
		f.Versions[k] = sourcestest.Old(v...)
	}
	f.Manifest["next@15.5.6"] = map[string]any{"name": "next", "version": "15.5.6", "repository": map[string]string{"url": "git+https://github.com/vercel/next.js.git"}}
	f.Releases["vercel/next.js"] = []sources.Release{{Tag: "v15.0.0", URL: "https://github.com/vercel/next.js/releases/tag/v15.0.0", Body: "## Breaking changes\n- Async Request APIs: cookies, headers, draftMode, params and searchParams are now async\n- fetch, GET route handlers and the client router cache are no longer cached by default\n- React 19 is the minimum for the App Router"}}
	f.Manifest["axios@1.6.8"] = map[string]any{"name": "axios", "version": "1.6.8", "dependencies": map[string]string{"follow-redirects": "^1.15.6"}}
	f.Node = []sources.NodeRelease{{Version: "v22.23.4", LTS: "Jod", Security: true}, {Version: "v22.20.0", LTS: "Jod"}}
	f.Schedule = map[string]sources.NodeLine{"v22": {LTS: "2024-10-29", End: "2027-04-30"}}

	st, err := store.Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	m := &app.Manager{Store: st, Fetcher: func() sources.Fetcher { return f }, Opt: scan.Options{Version: "demo"}, Roots: []string{root}, Depth: 3}
	m.Start(context.Background())
	port := 7795
	if p := os.Getenv("DEPGATE_DEMO_PORT"); p != "" {
		fmt.Sscan(p, &port)
	}
	ln, port, err := Listen("127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("DEMO http://127.0.0.1:%d/?t=demo-token-0123456789\n", port)
	au, err := auth.Open(filepath.Join(t.TempDir(), "auth"), os.Getenv("DEPGATE_DEMO_PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	_ = http.Serve(ln, (&Server{Token: "demo-token-0123456789", B: m, Auth: au}).Handler())
}
