package webserver

import (
	"path"
	"strings"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/report"
)

// directive is one nginx directive; Block is set for "name args { … }".
type directive struct {
	Name  string
	Args  []string
	Line  int
	Block []*directive
	Open  bool // has a block
}

// parseNginx turns an nginx config into a directive tree. It follows nginx's
// own tokenizer: words, quoted strings, ";" "{" "}", "#" comments; "${VAR}"
// (envsubst templates) stays part of a word.
func parseNginx(src string) []*directive {
	type tok struct {
		s    string
		line int
		sym  bool
	}
	var toks []tok
	line := 1
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == ';' || c == '{' || c == '}':
			toks = append(toks, tok{string(c), line, true})
			i++
		case c == '"' || c == '\'':
			q, start := c, line
			i++
			var b strings.Builder
			for i < len(src) && src[i] != q {
				if src[i] == '\\' && i+1 < len(src) {
					i++
				}
				if src[i] == '\n' {
					line++
				}
				b.WriteByte(src[i])
				i++
			}
			i++
			toks = append(toks, tok{b.String(), start, false})
		default:
			var b strings.Builder
			for i < len(src) {
				c := src[i]
				if c == '$' && i+1 < len(src) && src[i+1] == '{' {
					for i < len(src) && src[i] != '}' {
						b.WriteByte(src[i])
						i++
					}
					if i < len(src) {
						b.WriteByte('}')
						i++
					}
					continue
				}
				if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ';' || c == '{' || c == '}' || c == '"' || c == '\'' {
					break
				}
				b.WriteByte(c)
				i++
			}
			toks = append(toks, tok{b.String(), line, false})
		}
	}
	root := &directive{Open: true}
	stack := []*directive{root}
	var cur *directive
	for _, t := range toks {
		top := stack[len(stack)-1]
		switch {
		case t.sym && t.s == ";":
			if cur != nil {
				top.Block = append(top.Block, cur)
				cur = nil
			}
		case t.sym && t.s == "{":
			if cur == nil {
				cur = &directive{Line: t.line}
			}
			cur.Open = true
			top.Block = append(top.Block, cur)
			stack = append(stack, cur)
			cur = nil
		case t.sym && t.s == "}":
			if cur != nil {
				top.Block = append(top.Block, cur)
				cur = nil
			}
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		default:
			if cur == nil {
				cur = &directive{Name: strings.ToLower(t.s), Line: t.line}
			} else {
				cur.Args = append(cur.Args, t.s)
			}
		}
	}
	return root.Block
}

type ngxFile struct {
	rel  string
	tree []*directive
}

// standard includes that never carry security headers
var stdInclude = map[string]bool{"mime.types": true, "fastcgi_params": true, "fastcgi.conf": true, "proxy_params": true, "uwsgi_params": true, "scgi_params": true, "koi-utf": true, "koi-win": true, "win-utf": true}

func walk(ds []*directive, fn func(d *directive, parents []*directive)) {
	var rec func(ds []*directive, ps []*directive)
	rec = func(ds []*directive, ps []*directive) {
		for _, d := range ds {
			fn(d, ps)
			if d.Open {
				rec(d.Block, append(append([]*directive(nil), ps...), d))
			}
		}
	}
	rec(ds, nil)
}

func headerNames(ds []*directive, snippets map[string]map[string]bool) (map[string]bool, bool) {
	hs := map[string]bool{}
	known := true
	for _, d := range ds {
		switch d.Name {
		case "add_header":
			if len(d.Args) > 0 {
				hs[strings.ToLower(d.Args[0])] = true
			}
		case "include":
			if len(d.Args) == 0 {
				continue
			}
			base := path.Base(d.Args[0])
			if stdInclude[base] {
				continue
			}
			if sh, ok := snippets[base]; ok {
				for h := range sh {
					hs[h] = true
				}
			} else {
				known = false
			}
		}
	}
	return hs, known
}

// checkNginx runs the nginx rules over all config files of a project.
// Rule basis: gixy (alias traversal, add_header redefinition, HTTP splitting,
// host spoofing, SSRF), Mozilla SSL Configuration, OWASP Secure Headers,
// and the nginx documentation (server_tokens, autoindex).
func checkNginx(files []ngxFile) []report.DockerIssue {
	var out []report.DockerIssue
	add := func(f ngxFile, line int, rule, sev string, title, detail i18n.T, fix string) {
		out = append(out, report.DockerIssue{File: f.rel, Line: line, Rule: rule, Severity: sev, Title: title, Detail: detail, Fix: fix})
	}

	// snippet files (no server/http block) and http-level headers, shared by all files
	snippets := map[string]map[string]bool{}
	httpHeaders := map[string]bool{}
	tokensOff := false
	for _, f := range files {
		hasCtx := false
		walk(f.tree, func(d *directive, ps []*directive) {
			if d.Name == "server" || d.Name == "http" {
				hasCtx = true
			}
			if d.Name == "server_tokens" && len(d.Args) > 0 && strings.EqualFold(d.Args[0], "off") {
				tokensOff = true
			}
			if d.Name == "http" {
				hs, _ := headerNames(d.Block, nil)
				for h := range hs {
					httpHeaders[h] = true
				}
			}
		})
		if !hasCtx {
			hs, _ := headerNames(f.tree, nil)
			snippets[path.Base(f.rel)] = hs
		}
	}

	tokensReported := false
	for _, f := range files {
		walk(f.tree, func(d *directive, ps []*directive) {
			arg := func(i int) string {
				if i < len(d.Args) {
					return d.Args[i]
				}
				return ""
			}
			switch d.Name {
			case "ssl_protocols":
				var old []string
				for _, a := range d.Args {
					switch strings.ToLower(a) {
					case "sslv2", "sslv3", "tlsv1", "tlsv1.1":
						old = append(old, a)
					}
				}
				if len(old) > 0 {
					add(f, d.Line, "nginx-old-tls", "high",
						i18n.F("Köhnə TLS protokolları açıqdır: %s", "Old TLS protocols are enabled: %s", strings.Join(old, " ")),
						i18n.F("SSLv3, TLS 1.0 və 1.1 sındırılmış və ya köhnəlmiş sayılır (RFC 8996); müasir brauzerlər onları dəstəkləmir.", "SSLv3, TLS 1.0 and 1.1 are broken or deprecated (RFC 8996); modern browsers no longer support them."),
						"ssl_protocols TLSv1.2 TLSv1.3;")
				}
			case "ssl_ciphers":
				if weak := weakCiphers(arg(0)); len(weak) > 0 {
					add(f, d.Line, "nginx-weak-ciphers", "high",
						i18n.F("Zəif şifrləmə alqoritmləri icazəlidir: %s", "Weak ciphers are allowed: %s", strings.Join(weak, ", ")),
						i18n.F("RC4, DES/3DES, MD5, NULL və EXPORT şifrləri sındırıla bilər; Mozilla «intermediate» siyahısını istifadə et.", "RC4, DES/3DES, MD5, NULL and EXPORT ciphers can be broken; use Mozilla's “intermediate” list."),
						"ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;")
				}
			case "autoindex":
				if strings.EqualFold(arg(0), "on") {
					add(f, d.Line, "nginx-autoindex", "medium",
						i18n.F("Qovluq siyahısı açıqdır (autoindex on)", "Directory listing is on (autoindex on)"),
						i18n.F("Hər kəs qovluqdakı faylların siyahısını görür: yedəklər, .env, köhnə build-lər təsadüfən açıq qala bilər.", "Anyone can list the files in the folder: backups, .env files and old builds can end up exposed."),
						"autoindex off;")
				}
			case "alias":
				loc := parentNamed(ps, "location")
				if loc == nil || !strings.HasSuffix(arg(0), "/") {
					break
				}
				if p, prefix := locationPath(loc); prefix && p != "" && !strings.HasSuffix(p, "/") {
					add(f, d.Line, "nginx-alias-traversal", "high",
						i18n.F("alias ilə yol keçidi: location %s sonunda / yoxdur", "Path traversal through alias: location %s has no trailing /", p),
						i18n.F("«%s../» sorğusu alias qovluğundan bir səviyyə yuxarı çıxır və oradakı faylları verir (off-by-slash).", "A request for “%s../” climbs one level above the alias folder and serves the files there (off-by-slash).", p),
						"location "+p+"/ { alias "+arg(0)+"; }")
				}
			case "proxy_set_header":
				if strings.EqualFold(arg(0), "host") && strings.Contains(arg(1), "$http_host") {
					add(f, d.Line, "nginx-host-spoofing", "medium",
						i18n.F("Host başlığı müştəridən olduğu kimi ötürülür ($http_host)", "The Host header is passed through from the client ($http_host)"),
						i18n.F("Hücumçu istənilən Host göndərə bilər: parol bərpası linkləri və keş saxtalaşdırıla bilər. $host server_name-ə görə yoxlanmış dəyərdir.", "An attacker can send any Host: password-reset links and caches can be poisoned. $host is checked against server_name."),
						"proxy_set_header Host $host;")
				}
				if len(d.Args) > 1 && usesURI(d.Args[1:]) {
					add(f, d.Line, "nginx-crlf", "medium", crlfTitle(), crlfDetail(), strings.ReplaceAll(strings.Join(append([]string{d.Name}, d.Args...), " "), "$uri", "$request_uri")+";")
				}
			case "add_header", "return", "rewrite":
				if usesURI(d.Args) && (d.Name != "return" || len(d.Args) > 1) {
					add(f, d.Line, "nginx-crlf", "medium", crlfTitle(), crlfDetail(), strings.ReplaceAll(strings.Join(append([]string{d.Name}, d.Args...), " "), "$uri", "$request_uri")+";")
				}
			case "proxy_pass":
				for _, v := range []string{"$arg_", "$http_", "$cookie_"} {
					if strings.Contains(arg(0), v) {
						add(f, d.Line, "nginx-ssrf", "high",
							i18n.F("proxy_pass hədəfi istifadəçi girişindən gəlir (%s…)", "proxy_pass target comes from user input (%s…)", v),
							i18n.F("Sorğu göndərən istənilən daxili ünvana (verilənlər bazası, metadata servisi) sorğu atdıra bilər (SSRF).", "Whoever sends the request can make nginx call any internal address (databases, cloud metadata) — SSRF."),
							"proxy_pass http://upstream_name;")
						break
					}
				}
			case "http", "server":
				if !tokensOff && !tokensReported && (d.Name == "http" || parentNamed(ps, "http") == nil) {
					tokensReported = true
					add(f, d.Line, "nginx-server-tokens", "low",
						i18n.F("nginx versiyası cavablarda görünür (server_tokens)", "nginx shows its version in responses (server_tokens)"),
						i18n.F("Default olaraq nginx «Server: nginx/1.x.y» və xəta səhifələrində versiyanı göstərir; hücumçu uyğun zəifliyi asan tapır.", "By default nginx sends “Server: nginx/1.x.y” and prints the version on error pages; attackers can match it to known vulnerabilities."),
						"server_tokens off;")
				}
				if d.Name == "server" {
					out = append(out, checkServer(f, d, httpHeaders, snippets)...)
				}
			}
		})
	}
	return out
}

// checkServer looks at one server block: HSTS, basic security headers and
// add_header in locations that silently drop the server's headers.
func checkServer(f ngxFile, srv *directive, httpHeaders map[string]bool, snippets map[string]map[string]bool) []report.DockerIssue {
	var out []report.DockerIssue
	own, known := headerNames(srv.Block, snippets)
	eff := own
	if len(own) == 0 {
		eff = httpHeaders
	}
	tls, serves := false, false
	for _, d := range srv.Block {
		if d.Name == "listen" {
			for _, a := range d.Args {
				if a == "ssl" || a == "quic" || strings.HasSuffix(a, ":443") || a == "443" {
					tls = true
				}
			}
		}
		if d.Name == "location" || d.Name == "root" || d.Name == "proxy_pass" {
			serves = true
		}
	}
	redirectOnly := true
	for _, d := range srv.Block {
		if d.Name != "listen" && d.Name != "server_name" && d.Name != "return" && d.Name != "access_log" && d.Name != "error_log" {
			redirectOnly = false
		}
	}
	if known && tls && !eff["strict-transport-security"] {
		out = append(out, report.DockerIssue{File: f.rel, Line: srv.Line, Rule: "nginx-no-hsts", Severity: "medium",
			Title:  i18n.F("HTTPS server-də HSTS yoxdur", "HTTPS server without HSTS"),
			Detail: i18n.F("Strict-Transport-Security olmadan ilk sorğu HTTP ilə gedə bilər və ələ keçirilə bilər (SSL stripping).", "Without Strict-Transport-Security the first request can go over plain HTTP and be intercepted (SSL stripping)."),
			Fix:    `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;`})
	}
	if known && serves && !redirectOnly {
		var miss []string
		if !eff["x-content-type-options"] {
			miss = append(miss, "X-Content-Type-Options")
		}
		if !eff["x-frame-options"] && !eff["content-security-policy"] {
			miss = append(miss, "X-Frame-Options / CSP frame-ancestors")
		}
		if !eff["referrer-policy"] {
			miss = append(miss, "Referrer-Policy")
		}
		if len(miss) > 0 {
			out = append(out, report.DockerIssue{File: f.rel, Line: srv.Line, Rule: "nginx-missing-headers", Severity: "low",
				Title:  i18n.F("Təhlükəsizlik başlıqları yoxdur: %s", "Security headers missing: %s", strings.Join(miss, ", ")),
				Detail: i18n.F("Bu başlıqlar MIME sniffing, clickjacking və referrer sızmasının qarşısını alır (OWASP Secure Headers). Tətbiq özü göndərirsə, bunu nəzərə alma.", "These headers stop MIME sniffing, clickjacking and referrer leaks (OWASP Secure Headers). Ignore this if your app already sends them."),
				Fix: map[string]string{"X-Content-Type-Options": `add_header X-Content-Type-Options "nosniff" always;`,
					"X-Frame-Options / CSP frame-ancestors": `add_header Content-Security-Policy "frame-ancestors 'self'" always;`,
					"Referrer-Policy":                       `add_header Referrer-Policy "strict-origin-when-cross-origin" always;`}[miss[0]]})
		}
	}
	// add_header inside a location replaces every inherited add_header
	if len(eff) > 0 {
		walk(srv.Block, func(d *directive, ps []*directive) {
			if d.Name != "location" {
				return
			}
			hs, k := headerNames(d.Block, snippets)
			if len(hs) == 0 || !k {
				return
			}
			var lost []string
			for h := range eff {
				if !hs[h] {
					lost = append(lost, h)
				}
			}
			if len(lost) == 0 {
				return
			}
			sortStrings(lost)
			line := d.Line
			for _, x := range d.Block {
				if x.Name == "add_header" {
					line = x.Line
					break
				}
			}
			p, _ := locationPath(d)
			out = append(out, report.DockerIssue{File: f.rel, Line: line, Rule: "nginx-add-header-dropped", Severity: "medium",
				Title:  i18n.F("location %s-də add_header yuxarıdakı başlıqları silir", "add_header in location %s drops the inherited headers", p),
				Detail: i18n.F("nginx-də add_header miras alınmır: location öz add_header-ı olanda bu başlıqlar orada göndərilmir: %s.", "nginx does not merge add_header: once a location has its own, these headers are not sent there: %s.", strings.Join(lost, ", ")),
				Fix:    "include snippets/security-headers.conf;   # repeat the headers in the location"})
		})
	}
	return out
}

func parentNamed(ps []*directive, name string) *directive {
	for i := len(ps) - 1; i >= 0; i-- {
		if ps[i].Name == name {
			return ps[i]
		}
	}
	return nil
}

// locationPath returns the location's path and whether it is a plain prefix location.
func locationPath(d *directive) (string, bool) {
	if len(d.Args) == 0 {
		return "", false
	}
	if len(d.Args) == 1 {
		return d.Args[0], !strings.HasPrefix(d.Args[0], "@")
	}
	return d.Args[1], d.Args[0] == "^~"
}

func usesURI(args []string) bool {
	for _, a := range args {
		if strings.Contains(a, "$uri") || strings.Contains(a, "$document_uri") {
			return true
		}
	}
	return false
}

func crlfTitle() i18n.T {
	return i18n.F("$uri başlığa və ya yönləndirməyə yazılır (CRLF injection)", "$uri is written into a header or redirect (CRLF injection)")
}
func crlfDetail() i18n.T {
	return i18n.F("$uri dekod olunmuş yoldur: «%%0d%%0a» ilə cavaba yeni başlıq əlavə etmək olar (HTTP response splitting). $request_uri kodlu qalır.", "$uri is the decoded path: “%%0d%%0a” in a request adds new headers to the response (HTTP response splitting). $request_uri stays encoded.")
}

func weakCiphers(spec string) []string {
	var out []string
	for _, c := range strings.FieldsFunc(spec, func(r rune) bool { return r == ':' || r == ' ' || r == ',' }) {
		if strings.HasPrefix(c, "!") || strings.HasPrefix(c, "-") {
			continue
		}
		c = strings.TrimPrefix(c, "+")
		up := strings.ToUpper(c)
		bad := up == "ANULL" || up == "ENULL" || up == "ALL" || up == "LOW" || up == "EXP" || up == "EXPORT"
		for _, part := range strings.Split(up, "-") {
			switch part {
			case "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "EXP", "ADH", "AECDH", "CBC3":
				bad = true
			}
		}
		if bad {
			out = append(out, c)
		}
	}
	return out
}
