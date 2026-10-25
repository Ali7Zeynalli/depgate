package webserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/docker"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
	"github.com/Ali7Zeynalli/depgate/internal/sources/sourcestest"
)

func write(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func rules(is []report.DockerIssue) map[string]report.DockerIssue {
	m := map[string]report.DockerIssue{}
	for _, i := range is {
		if _, ok := m[i.Rule]; !ok {
			m[i.Rule] = i
		}
	}
	return m
}

const badNginx = `# a vulnerable site
server {
    listen 443 ssl http2;
    server_name shop.example.com;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers "HIGH:!aNULL:RC4-SHA:DES-CBC3-SHA";
    add_header X-Frame-Options DENY;

    location /static {
        alias /var/www/static/;
        autoindex on;
    }
    location /api/ {
        add_header Cache-Control no-store;
        proxy_set_header Host $http_host;
        proxy_pass http://api:3000;
    }
    location /fetch {
        proxy_pass http://$arg_target;
    }
    location /old {
        return 301 https://$host$uri;
    }
}
`

func TestNginxRules(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{"package.json": "{}", "nginx/conf.d/site.conf": badNginx})
	is, files := Scan(dir, "")
	if len(files) != 1 || files[0] != "nginx/conf.d/site.conf" {
		t.Fatalf("files = %v", files)
	}
	m := rules(is)
	want := map[string]int{
		"nginx-old-tls": 5, "nginx-weak-ciphers": 6, "nginx-alias-traversal": 10, "nginx-autoindex": 11,
		"nginx-add-header-dropped": 14, "nginx-host-spoofing": 15, "nginx-ssrf": 19, "nginx-crlf": 22,
		"nginx-no-hsts": 2, "nginx-missing-headers": 2, "nginx-server-tokens": 2,
	}
	for r, line := range want {
		i, ok := m[r]
		if !ok {
			t.Errorf("missing %s; got %v", r, keys(m))
			continue
		}
		if i.Line != line {
			t.Errorf("%s at line %d, want %d", r, i.Line, line)
		}
	}
	if w := m["nginx-weak-ciphers"].Title.En; !strings.Contains(w, "RC4-SHA") || !strings.Contains(w, "DES-CBC3-SHA") || strings.Contains(w, "aNULL") {
		t.Errorf("weak ciphers title: %s", w)
	}
	if d := m["nginx-add-header-dropped"].Detail.En; !strings.Contains(d, "x-frame-options") {
		t.Errorf("dropped detail: %s", d)
	}
	if f := m["nginx-alias-traversal"].Fix; f != "location /static/ { alias /var/www/static/; }" {
		t.Errorf("alias fix: %s", f)
	}
}

func TestNginxGoodConfig(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"package.json": "{}",
		"deploy/nginx.conf": `user nginx;
events { worker_connections 1024; }
http {
    include mime.types;
    server_tokens off;
    include /etc/nginx/conf.d/*.conf;
}`,
		"deploy/conf.d/app.conf.template": `server {
    listen 443 ssl;
    server_name ${NGINX_HOST};
    ssl_protocols TLSv1.2 TLSv1.3;
    include snippets/headers.conf;
    location / { root /usr/share/nginx/html; try_files $uri $uri/ /index.html; }
}
server {
    listen 80;
    server_name ${NGINX_HOST};
    return 301 https://$host$request_uri;
}`,
		"deploy/snippets/headers.conf": `add_header Strict-Transport-Security "max-age=63072000" always;
add_header X-Content-Type-Options nosniff always;
add_header Content-Security-Policy "frame-ancestors 'self'" always;
add_header Referrer-Policy strict-origin-when-cross-origin always;`,
	})
	is, files := Scan(dir, "")
	if len(files) != 3 {
		t.Fatalf("files = %v", files)
	}
	if len(is) != 0 {
		for _, i := range is {
			t.Errorf("unexpected %s at %s:%d: %s", i.Rule, i.File, i.Line, i.Title.En)
		}
	}
}

func TestNginxSkipsOtherPackages(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{
		"package.json":                "{}",
		"nginx/default.conf":          "server { listen 80; location / { autoindex on; } }",
		"apps/api/package.json":       "{}",
		"apps/web/package.json":       "{}",
		"apps/web/nginx/site.conf":    "server { listen 80; location / { autoindex on; } }",
		"node_modules/x/nginx/a.conf": "server { autoindex on; }",
	})
	_, files := Scan(filepath.Join(root, "apps/api"), root)
	if len(files) != 1 || files[0] != "../../nginx/default.conf" {
		t.Fatalf("files = %v", files)
	}
}

const badCaddy = `{
	admin 0.0.0.0:2019
	debug
}

(common) {
	encode gzip
}

shop.example.com, www.shop.example.com {
	import common
	tls internal
	file_server browse
	reverse_proxy api:3000 {
		transport http {
			tls
			tls_insecure_skip_verify
		}
	}
}

localhost:8080 {
	respond "dev"
}

legacy.example.com {
	tls {
		protocols tls1.0 tls1.3
	}
	header Strict-Transport-Security "max-age=31536000"
	header {
		X-Content-Type-Options nosniff
		Referrer-Policy no-referrer
		-Server
	}
	reverse_proxy legacy:80
}
`

func TestCaddyRules(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{"package.json": "{}", "Caddyfile": badCaddy})
	is, files := Scan(dir, "")
	if len(files) != 1 || files[0] != "Caddyfile" {
		t.Fatalf("files = %v", files)
	}
	m := rules(is)
	want := map[string]int{"caddy-admin-exposed": 2, "caddy-debug": 3, "caddy-tls-internal": 12, "caddy-browse": 13,
		"caddy-insecure-upstream": 17, "caddy-no-hsts": 10, "caddy-missing-headers": 10, "caddy-old-tls": 28}
	for r, line := range want {
		i, ok := m[r]
		if !ok {
			t.Errorf("missing %s; got %v", r, keys(m))
			continue
		}
		if i.Line != line {
			t.Errorf("%s at line %d, want %d", r, i.Line, line)
		}
	}
	for _, i := range is {
		if (i.Rule == "caddy-no-hsts" || i.Rule == "caddy-missing-headers") && i.Line != 10 {
			t.Errorf("%s reported for line %d (localhost and the site with headers must be clean)", i.Rule, i.Line)
		}
	}
}

func TestCaddySingleSiteAndImports(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{"package.json": "{}", "docker/Caddyfile": "example.org\nreverse_proxy app:3000\nimport /etc/caddy/headers.caddy\n"})
	is, _ := Scan(dir, "")
	for _, i := range is {
		if i.Rule == "caddy-no-hsts" || i.Rule == "caddy-missing-headers" {
			t.Errorf("an unknown import must silence header rules, got %s", i.Rule)
		}
	}
	write(t, dir, map[string]string{"docker/Caddyfile": "example.org\nreverse_proxy app:3000\n"})
	is, _ = Scan(dir, "")
	if _, ok := rules(is)["caddy-no-hsts"]; !ok {
		t.Errorf("single-site Caddyfile without braces: no HSTS finding, got %v", keys(rules(is)))
	}
}

func TestVersions(t *testing.T) {
	f := sourcestest.New(time.Now())
	f.NginxHTML = sources_nginxPage
	f.EOL["nginx"] = []map[string]any{{"cycle": "1.31", "latest": "1.31.4"}, {"cycle": "1.30", "latest": "1.30.6"}, {"cycle": "1.25", "latest": "1.25.5", "eol": "2024-04-23"}}
	f.Releases["caddyserver/caddy"] = []sources.Release{{Tag: "v2.10.2"}, {Tag: "v2.9.1"}, {Tag: "v2.7.6"}, {Tag: "v2.11.0-beta.1", Prerelease: true}}
	f.OSVQuery["Go|github.com/caddyserver/caddy/v2|2.7.6"] = []string{"GO-2026-0001"}
	f.Vulns["GO-2026-0001"] = mustVuln(t, `{"id":"GO-2026-0001","aliases":["CVE-2026-1111"],"summary":"Header injection in reverse_proxy","database_specific":{"severity":"HIGH"},
		"affected":[{"package":{"ecosystem":"Go","name":"github.com/caddyserver/caddy/v2"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.9.0"}]}]}]}`)
	refs := []docker.ImageRef{
		{File: "Dockerfile", Line: 1, Ref: "nginx:1.25.3-alpine"},
		{File: "docker-compose.yml", Line: 4, Service: "web", Ref: "nginx:1.30"},
		{File: "docker-compose.yml", Line: 9, Service: "proxy", Ref: "caddy:2.7.6-alpine"},
		{File: "docker-compose.yml", Line: 14, Service: "edge", Ref: "caddy:2.9"},
		{File: "docker-compose.yml", Line: 18, Service: "x", Ref: "nginx:stable-alpine"},
	}
	is := Versions(context.Background(), f, refs, time.Now())
	byLine := map[int]report.DockerIssue{}
	for _, i := range is {
		byLine[i.Line] = i
	}
	if i := byLine[1]; i.Rule != "nginx-vulnerable" || i.Severity != "high" || i.Fix != "nginx:1.30.4-alpine" || !strings.Contains(i.Title.En, "3 known") {
		t.Errorf("nginx 1.25.3: %+v", i)
	}
	if _, ok := byLine[4]; ok {
		t.Errorf("nginx:1.30 resolves to 1.30.6, which is fixed: %+v", byLine[4])
	}
	if i := byLine[9]; i.Rule != "caddy-vulnerable" || i.Severity != "high" || i.Fix != "caddy:2.9.0-alpine" || !strings.Contains(i.Detail.En, "CVE-2026-1111") {
		t.Errorf("caddy 2.7.6: %+v", i)
	}
	if i := byLine[14]; i.Rule != "caddy-outdated" || i.Fix != "caddy:2.10" {
		t.Errorf("caddy 2.9: %+v", i)
	}
	if _, ok := byLine[18]; ok {
		t.Errorf("floating tags are not checked: %+v", byLine[18])
	}
}

const sources_nginxPage = `<ul>
<li><p>Buffer overflow when using map and regex<br>Severity: <b>major</b><br><a href="https://my.f5.com/a">Advisory</a><br><a href="#">CVE-2026-42533</a><br>Not vulnerable: 1.31.3+, 1.30.4+<br>Vulnerable: 0.9.6-1.31.2</p></li>
<li><p>Memory disclosure in slice<br>Severity: medium<br><a href="https://my.f5.com/b">Advisory</a><br><a href="#">CVE-2026-60005</a><br>Not vulnerable: 1.31.3+, 1.30.4+<br>Vulnerable: 1.15.8-1.31.2</p></li>
<li><p>HTTP/3 issue<br>Severity: low<br><a href="https://my.f5.com/c">Advisory</a><br><a href="#">CVE-2024-0001</a><br>Not vulnerable: 1.25.4+<br>Vulnerable: 1.25.0-1.25.3</p></li>
</ul>`

func mustVuln(t *testing.T, js string) *sources.Vuln {
	t.Helper()
	var v sources.Vuln
	if err := json.Unmarshal([]byte(js), &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func keys(m map[string]report.DockerIssue) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
