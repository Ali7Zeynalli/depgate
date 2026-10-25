package webserver

import (
	"net"
	"strings"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/report"
)

// cnode is one Caddyfile line (directive or block head) and its block.
type cnode struct {
	Tok   []string
	Line  int
	Block []*cnode
	Open  bool
}

// parseCaddy reads a Caddyfile: one directive per line, "{" at the end of a
// line opens a block, "}" closes it, "#" starts a comment, quotes and
// backticks group words. Placeholders such as {host} are ordinary words.
func parseCaddy(src string) []*cnode {
	root := &cnode{Open: true}
	stack := []*cnode{root}
	for i, raw := range strings.Split(src, "\n") {
		toks := caddyTokens(raw)
		if len(toks) == 0 {
			continue
		}
		top := stack[len(stack)-1]
		for len(toks) > 0 && toks[0] == "}" {
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			top = stack[len(stack)-1]
			toks = toks[1:]
		}
		if len(toks) == 0 {
			continue
		}
		n := &cnode{Tok: toks, Line: i + 1}
		closeAfter := false
		if toks[len(toks)-1] == "}" && len(toks) > 1 && toks[len(toks)-2] == "{" { // "name { }" on one line
			n.Tok, n.Open = toks[:len(toks)-2], true
			closeAfter = true
		} else if toks[len(toks)-1] == "{" {
			n.Tok, n.Open = toks[:len(toks)-1], true
		}
		top.Block = append(top.Block, n)
		if n.Open && !closeAfter {
			stack = append(stack, n)
		}
	}
	return root.Block
}

func caddyTokens(line string) []string {
	var out []string
	for i := 0; i < len(line); {
		c := line[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#':
			return out
		case c == '"' || c == '`':
			q := c
			i++
			var b strings.Builder
			for i < len(line) && line[i] != q {
				if line[i] == '\\' && q == '"' && i+1 < len(line) {
					i++
				}
				b.WriteByte(line[i])
				i++
			}
			i++
			out = append(out, b.String())
		default:
			j := i
			for j < len(line) && line[j] != ' ' && line[j] != '\t' && line[j] != '\r' {
				j++
			}
			out = append(out, line[i:j])
			i = j
		}
	}
	return out
}

type caddySite struct {
	addrs []string
	node  *cnode
	body  []*cnode
}

// checkCaddy runs the Caddy rules over one Caddyfile.
// Rule basis: the Caddy documentation (admin endpoint, file_server browse,
// tls protocols, tls_insecure_skip_verify, debug, auto_https, tls internal)
// and OWASP Secure Headers (HSTS, nosniff, Referrer-Policy, Server header).
func checkCaddy(rel string, tree []*cnode) []report.DockerIssue {
	var out []report.DockerIssue
	add := func(line int, rule, sev string, title, detail i18n.T, fix string) {
		out = append(out, report.DockerIssue{File: rel, Line: line, Rule: rule, Severity: sev, Title: title, Detail: detail, Fix: fix})
	}
	var global *cnode
	snippets := map[string][]*cnode{}
	var sites []caddySite
	var loose []*cnode
	for i, n := range tree {
		switch {
		case n.Open && len(n.Tok) == 0 && i == 0:
			global = n
		case n.Open && len(n.Tok) > 0 && strings.HasPrefix(n.Tok[0], "(") && strings.HasSuffix(n.Tok[0], ")"):
			snippets[strings.Trim(n.Tok[0], "()")] = n.Block
		case n.Open:
			sites = append(sites, caddySite{addrs: splitAddrs(n.Tok), node: n, body: n.Block})
		default:
			loose = append(loose, n)
		}
	}
	if len(sites) == 0 && len(loose) > 0 { // single site without braces
		sites = append(sites, caddySite{addrs: splitAddrs(loose[0].Tok), node: loose[0], body: loose[1:]})
	}

	autoHTTPSOff := false
	if global != nil {
		cwalk(global.Block, nil, func(n *cnode) {
			switch n.Tok[0] {
			case "admin":
				if len(n.Tok) > 1 && !localAdmin(n.Tok[1]) {
					add(n.Line, "caddy-admin-exposed", "high",
						i18n.F("Caddy admin API şəbəkəyə açıqdır (%s)", "The Caddy admin API is open to the network (%s)", n.Tok[1]),
						i18n.F("Admin API ilə istənilən kəs Caddy konfiqurasiyasını oxuya və dəyişə bilər. Default localhost:2019-dur.", "Anyone who reaches the admin API can read and replace the whole Caddy config. The default is localhost:2019."),
						"admin localhost:2019")
				}
			case "debug":
				add(n.Line, "caddy-debug", "low",
					i18n.F("Debug rejimi açıqdır", "Debug mode is on"),
					i18n.F("Debug logları sorğu təfərrüatlarını yazır və həssas məlumat sızdıra bilər; yalnız problem axtararkən aç.", "Debug logs record request details and can leak sensitive data; turn it on only while troubleshooting."),
					"# debug")
			case "auto_https":
				if len(n.Tok) > 1 && n.Tok[1] == "off" {
					autoHTTPSOff = true
				}
			}
		})
	}

	for _, s := range sites {
		body, known := expand(s.body, snippets)
		public := false
		for _, a := range s.addrs {
			if publicHTTPS(a) {
				public = true
			}
		}
		hs := map[string]bool{}
		cwalk(body, nil, func(n *cnode) {
			switch n.Tok[0] {
			case "file_server":
				browse := false
				for _, t := range n.Tok[1:] {
					if t == "browse" {
						browse = true
					}
				}
				cwalk(n.Block, nil, func(c *cnode) {
					if c.Tok[0] == "browse" {
						browse = true
					}
				})
				if browse {
					add(n.Line, "caddy-browse", "medium",
						i18n.F("Qovluq siyahısı açıqdır (file_server browse)", "Directory listing is on (file_server browse)"),
						i18n.F("Hər kəs qovluqdakı faylların siyahısını görür: yedəklər, .env, köhnə build-lər təsadüfən açıq qala bilər.", "Anyone can list the files in the folder: backups, .env files and old builds can end up exposed."),
						"file_server")
				}
			case "protocols":
				for _, t := range n.Tok[1:] {
					if t == "tls1.0" || t == "tls1.1" {
						add(n.Line, "caddy-old-tls", "high",
							i18n.F("Köhnə TLS protokolu icazəlidir: %s", "An old TLS protocol is allowed: %s", t),
							i18n.F("TLS 1.0 və 1.1 köhnəlib (RFC 8996); Caddy-nin defaultu TLS 1.2+-dır, bu sətir onu zəiflədir.", "TLS 1.0 and 1.1 are deprecated (RFC 8996); Caddy defaults to TLS 1.2+, this line weakens it."),
							"protocols tls1.2 tls1.3")
						break
					}
				}
			case "tls_insecure_skip_verify":
				add(n.Line, "caddy-insecure-upstream", "high",
					i18n.F("Upstream sertifikatı yoxlanmır (tls_insecure_skip_verify)", "The upstream certificate is not verified (tls_insecure_skip_verify)"),
					i18n.F("Caddy ilə arxa servis arasındakı trafik ələ keçirilə bilər (MITM). Daxili CA-nı tls_trusted_ca_certs ilə ver.", "Traffic between Caddy and the backend can be intercepted (MITM). Trust your internal CA with tls_trusted_ca_certs instead."),
					"tls_trusted_ca_certs /path/to/ca.pem")
			case "tls":
				if len(n.Tok) > 1 && n.Tok[1] == "internal" && public {
					add(n.Line, "caddy-tls-internal", "medium",
						i18n.F("İctimai domendə «tls internal»", "“tls internal” on a public domain"),
						i18n.F("Daxili CA sertifikatına brauzerlər etibar etmir; ictimai sayt üçün Caddy-nin avtomatik Let's Encrypt/ZeroSSL sertifikatını istifadə et.", "Browsers do not trust the internal CA; for a public site let Caddy get a Let's Encrypt/ZeroSSL certificate automatically."),
						"# remove “tls internal”")
				}
			case "header":
				for _, h := range headerArgs(n) {
					hs[h] = true
				}
			}
		})
		if !known || !public || autoHTTPSOff {
			continue
		}
		if !hs["strict-transport-security"] {
			add(s.node.Line, "caddy-no-hsts", "medium",
				i18n.F("%s: HSTS başlığı yoxdur", "%s: no HSTS header", strings.Join(s.addrs, ", ")),
				i18n.F("Caddy HTTPS-i avtomatik açır, amma Strict-Transport-Security göndərmir; onsuz ilk sorğu HTTP ilə gedə bilər (SSL stripping).", "Caddy turns on HTTPS automatically but does not send Strict-Transport-Security; without it the first request can go over plain HTTP (SSL stripping)."),
				`header Strict-Transport-Security "max-age=31536000; includeSubDomains"`)
		}
		var miss []string
		if !hs["x-content-type-options"] {
			miss = append(miss, "X-Content-Type-Options")
		}
		if !hs["referrer-policy"] {
			miss = append(miss, "Referrer-Policy")
		}
		if !hs["-server"] {
			miss = append(miss, "-Server")
		}
		if len(miss) > 0 {
			add(s.node.Line, "caddy-missing-headers", "low",
				i18n.F("%s: təhlükəsizlik başlıqları yoxdur: %s", "%s: security headers missing: %s", strings.Join(s.addrs, ", "), strings.Join(miss, ", ")),
				i18n.F("nosniff və Referrer-Policy MIME sniffing və referrer sızmasının qarşısını alır; «-Server» Caddy-ni cavablardan gizlədir (OWASP Secure Headers). Tətbiq özü göndərirsə, nəzərə alma.", "nosniff and Referrer-Policy stop MIME sniffing and referrer leaks; “-Server” hides Caddy from responses (OWASP Secure Headers). Ignore this if your app already sends them."),
				map[string]string{"X-Content-Type-Options": "header X-Content-Type-Options nosniff", "Referrer-Policy": "header Referrer-Policy strict-origin-when-cross-origin", "-Server": "header -Server"}[miss[0]])
		}
	}
	return out
}

func cwalk(ns []*cnode, _ []*cnode, fn func(n *cnode)) {
	for _, n := range ns {
		if len(n.Tok) > 0 {
			fn(n)
		}
		if n.Open {
			cwalk(n.Block, nil, fn)
		}
	}
}

// expand inlines "import snippet" lines; false when an import names a file or an unknown snippet.
func expand(ns []*cnode, snippets map[string][]*cnode) ([]*cnode, bool) {
	known := true
	var out []*cnode
	var rec func(ns []*cnode, depth int)
	rec = func(ns []*cnode, depth int) {
		for _, n := range ns {
			if len(n.Tok) > 1 && n.Tok[0] == "import" {
				if sn, ok := snippets[n.Tok[1]]; ok && depth < 5 {
					rec(sn, depth+1)
				} else {
					known = false
				}
				continue
			}
			out = append(out, n)
		}
	}
	rec(ns, 0)
	return out, known
}

func headerArgs(n *cnode) []string {
	var out []string
	name := func(t string) string { return strings.ToLower(strings.TrimLeft(t, "+>?~")) }
	args := n.Tok[1:]
	if len(args) > 0 && (strings.HasPrefix(args[0], "/") || strings.HasPrefix(args[0], "@") || args[0] == "*") {
		args = args[1:]
	}
	if len(args) > 0 {
		out = append(out, name(args[0]))
	}
	for _, c := range n.Block {
		if len(c.Tok) > 0 {
			out = append(out, name(c.Tok[0]))
		}
	}
	return out
}

func splitAddrs(toks []string) []string {
	var out []string
	for _, t := range toks {
		for _, a := range strings.Split(t, ",") {
			if a = strings.TrimSpace(a); a != "" {
				out = append(out, a)
			}
		}
	}
	return out
}

func localAdmin(a string) bool {
	if a == "off" || strings.HasPrefix(a, "unix/") || strings.HasPrefix(a, "localhost") || strings.HasPrefix(a, "127.") || strings.HasPrefix(a, "[::1]") {
		return true
	}
	return false
}

// publicHTTPS reports whether Caddy serves the address over HTTPS on a public name.
func publicHTTPS(a string) bool {
	if strings.HasPrefix(a, "http://") {
		return false
	}
	a = strings.TrimPrefix(a, "https://")
	if i := strings.IndexAny(a, "/"); i >= 0 {
		a = a[:i]
	}
	host := a
	if h, _, err := net.SplitHostPort(a); err == nil {
		host = h
	}
	if strings.HasPrefix(host, "{$") || strings.HasPrefix(host, "{env.") {
		return true // a domain set through the environment
	}
	host = strings.TrimPrefix(host, "*.")
	if host == "" || host == "localhost" || net.ParseIP(strings.Trim(host, "[]")) != nil || !strings.Contains(host, ".") {
		return false
	}
	for _, s := range []string{".localhost", ".local", ".internal", ".test", ".lan", ".home.arpa"} {
		if strings.HasSuffix(host, s) {
			return false
		}
	}
	return true
}
