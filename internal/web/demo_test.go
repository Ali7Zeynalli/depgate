package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/app"
	"github.com/Ali7Zeynalli/depgate/internal/auth"
	"github.com/Ali7Zeynalli/depgate/internal/decide"
	"github.com/Ali7Zeynalli/depgate/internal/mcp"
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
	f.Vuln("GHSA-demo-next-cache", "next", "MODERATE", "14.0.0", "14.2.10", "Cache poisoning in Next.js")
	f.Vuln("GHSA-demo-next-ssrf", "next", "HIGH", "14.0.0", "14.2.10", "Server-side request forgery in Server Actions")
	f.Vuln("GHSA-demo-follow", "follow-redirects", "MODERATE", "0", "1.15.9", "follow-redirects leaks Proxy-Authorization header")
	f.Vuln("GHSA-demo-express", "express", "MODERATE", "0", "5.0.0", "express open redirect (fixed only in 5.x)")
	f.Malware("MAL-2026-demo", "debug", "4.3.4")
	f.Vulns["GHSA-demo-next"].DatabaseSpecific.CWEIDs = []string{"CWE-285", "CWE-863"}
	f.Vulns["GHSA-demo-next"].Details = "### Impact\nIt is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware.\n\n### Patches\nFixed in 14.2.25 and 15.2.3."
	f.Vulns["GHSA-demo-follow"].DatabaseSpecific.CWEIDs = []string{"CWE-200"}
	f.Vulns["GHSA-demo-express"].DatabaseSpecific.CWEIDs = []string{"CWE-601"}
	for k, d := range map[string]string{"next@14.2.3": "The React Framework", "debug@4.3.4": "Lightweight debugging utility for Node.js and the browser",
		"follow-redirects@1.15.6": "HTTP and HTTPS modules that follow redirects.", "express@4.19.2": "Fast, unopinionated, minimalist web framework",
		"react@18.2.0": "React is a JavaScript library for building user interfaces.", "typescript@5.4.5": "TypeScript is a language for application scale JavaScript development"} {
		n, v, _ := strings.Cut(k, "@")
		f.Manifest[k] = map[string]any{"name": n, "version": v, "description": d}
	}
	f.EPSS["CVE-2025-29927"] = 0.92
	f.KEV = []string{"CVE-2025-29927"}
	for k, v := range map[string][]string{
		"next": {"14.2.3", "14.2.25", "15.5.6"}, "follow-redirects": {"1.15.6", "1.15.9"}, "express": {"4.19.2", "5.0.0"},
		"debug": {"4.3.3", "4.3.4", "4.4.1"}, "react": {"18.2.0", "18.3.1", "19.2.0"}, "react-dom": {"18.2.0", "18.3.1", "19.2.0"},
		"axios": {"1.6.8", "1.12.2"}, "typescript": {"5.4.5", "5.9.3"}, "lodash": {"4.17.21"}, "make-dir": {"3.1.0", "5.1.0"},
		"nodemon": {"3.1.0", "3.1.10"}, "moment": {"2.29.4", "2.30.1"}, "@types/node": {"20.12.7", "20.19.0"},
	} {
		f.Versions[k] = sourcestest.Old(v...)
	}
	f.Manifest["next@15.5.6"] = map[string]any{"name": "next", "version": "15.5.6", "repository": map[string]string{"url": "git+https://github.com/vercel/next.js.git"}}
	f.Releases["vercel/next.js"] = []sources.Release{{Tag: "v15.0.0", URL: "https://github.com/vercel/next.js/releases/tag/v15.0.0", Body: "## Breaking changes\n- Async Request APIs: cookies, headers, draftMode, params and searchParams are now async\n- fetch, GET route handlers and the client router cache are no longer cached by default\n- React 19 is the minimum for the App Router"}}
	f.EOL["postgresql"] = []map[string]any{{"cycle": "17", "eol": "2029-11-08", "latest": "17.6"}, {"cycle": "15", "eol": "2027-11-11", "latest": "15.14"}}
	f.EOL["redis"] = []map[string]any{{"cycle": "8.2", "eol": false, "latest": "8.2.2"}, {"cycle": "7.4", "eol": "2026-11-18", "latest": "7.4.6"}, {"cycle": "6.2", "eol": "2025-02-28", "latest": "6.2.20"}}
	f.EOL["nginx"] = []map[string]any{{"cycle": "1.31", "eol": false, "latest": "1.31.7"}, {"cycle": "1.30", "eol": false, "latest": "1.30.6"}, {"cycle": "1.25", "eol": "2024-04-23", "latest": "1.25.5"}}
	f.NginxHTML = `<ul>
<li><p>Buffer overflow when using map and regex<br>Severity: <b>major</b><br><a href="https://nginx.org/en/security_advisories.html">Advisory</a><br><a href="#">CVE-2026-42533</a><br>Not vulnerable: 1.31.3+, 1.30.4+<br>Vulnerable: 0.9.6-1.31.2</p></li>
<li><p>Memory disclosure when using ngx_http_slice_module<br>Severity: medium<br><a href="https://nginx.org/en/security_advisories.html">Advisory</a><br><a href="#">CVE-2026-60005</a><br>Not vulnerable: 1.31.3+, 1.30.4+<br>Vulnerable: 1.15.8-1.31.2</p></li>
</ul>`
	f.Manifest["axios@1.6.8"] = map[string]any{"name": "axios", "version": "1.6.8", "description": "Promise based HTTP client for the browser and node.js", "dependencies": map[string]string{"follow-redirects": "^1.15.6"}}
	f.Node = []sources.NodeRelease{{Version: "v22.23.4", LTS: "Jod", Security: true}, {Version: "v22.20.0", LTS: "Jod"}}
	f.Schedule = map[string]sources.NodeLine{"v22": {LTS: "2024-10-29", End: "2027-04-30"}}
	// news (sample data: the CVE ids use the year 2099 so nobody takes them for real ones)
	day := func(d int) string { return now.AddDate(0, 0, -d).Format("2006-01-02") }
	ts := func(d int) string { return now.AddDate(0, 0, -d).Format(time.RFC3339) }
	f.KEVFull = []sources.KEVEntry{
		{CVE: "CVE-2099-1001", Vendor: "Linux", Product: "Kernel", Name: "Linux Kernel Use-After-Free Privilege Escalation", Added: day(0), Description: "A local user can gain root privileges.", Action: "Apply the vendor updates and reboot."},
		{CVE: "CVE-2099-1002", Vendor: "Linux Foundation", Product: "runc", Name: "runc Container Breakout", Added: day(1), Description: "A malicious image can write to the host file system.", Action: "Update Docker Engine / containerd."},
		{CVE: "CVE-2099-1003", Vendor: "OpenSSL", Product: "OpenSSL", Name: "OpenSSL TLS Handshake Memory Corruption", Added: day(2), Description: "A crafted TLS message can crash the process or run code.", Action: "Apply updates."},
		{CVE: "CVE-2099-1004", Vendor: "Sudo", Product: "Sudo", Name: "Sudo Privilege Escalation", Added: day(6), Description: "An unprivileged user can become root.", Action: "Apply updates."},
	}
	osvRec := func(id, cve, pkg, eco, sum, fix string, d int) sources.Vuln {
		var v sources.Vuln
		_ = json.Unmarshal([]byte(`{"id":"`+id+`","aliases":["`+cve+`"],"summary":"`+sum+`","published":"`+ts(d)+`","affected":[{"package":{"ecosystem":"`+eco+`","name":"`+pkg+`"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"`+fix+`"}]}]}]}`), &v)
		return v
	}
	f.OSVRecent["Debian:12|openssl"] = []sources.Vuln{osvRec("DEBIAN-CVE-2099-1003", "CVE-2099-1003", "openssl", "Debian:12", "TLS handshake memory corruption", "3.0.15-1~deb12u3", 2)}
	f.OSVRecent["Debian:12|glibc"] = []sources.Vuln{osvRec("DEBIAN-CVE-2099-1010", "CVE-2099-1010", "glibc", "Debian:12", "Buffer overflow in iconv", "2.36-9+deb12u10", 5)}
	f.Feeds[sources.UbuntuUSN] = `<rss version="2.0"><channel>
<item><title>USN-9901-1: OpenSSH vulnerability</title><link>https://ubuntu.com/security/notices</link><description>CVE-2099-1020: a remote attacker could cause sshd to stop responding.</description><pubDate>` + now.AddDate(0, 0, -1).Format(time.RFC1123Z) + `</pubDate></item>
<item><title>USN-9902-1: Linux kernel vulnerabilities</title><link>https://ubuntu.com/security/notices</link><description>Several security issues were fixed in the Linux kernel.</description><pubDate>` + now.AddDate(0, 0, -3).Format(time.RFC1123Z) + `</pubDate></item>
</channel></rss>`
	f.Feeds[sources.DebianDSA] = `<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">
<item><title>DSA-9903-1 postgresql-15 - security update</title><link>https://www.debian.org/security/</link><description>Several vulnerabilities were found in PostgreSQL.</description><dc:date>` + day(4) + `</dc:date></item>
</rdf:RDF>`

	st, err := store.Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	// the screenshots show the version being released, as the real binary does
	ver := "dev"
	if b, err := os.ReadFile(filepath.Join("..", "..", "VERSION")); err == nil {
		ver = strings.TrimSpace(string(b))
	}
	m := &app.Manager{Store: st, Fetcher: func() sources.Fetcher { return f }, Opt: scan.Options{Version: ver}, Roots: []string{root}, Depth: 3}
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
	ms := &mcp.Server{Store: st, Fetcher: func() sources.Fetcher { return f }, Opt: scan.Options{Version: ver}, Version: ver, Roots: []string{root}}
	_ = http.Serve(ln, (&Server{Token: "demo-token-0123456789", B: m, Auth: au, MCP: ms.HTTPHandler()}).Handler())
}
