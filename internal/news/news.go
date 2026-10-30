// Package news builds DepGate's news page: what changed for the systems in the
// user's Docker files ("mine": images that reached end of life, new patch
// releases, nginx/Caddy versions with known vulnerabilities, fresh security
// records of the OS packages inside the images) and, apart from that, recent
// Linux and DevOps security news (CISA KEV additions, Ubuntu and Debian
// bulletins for core server software).
//
// Feed text comes from third parties: it is shown as text and passed to AI
// agents as data, never as instructions. Nothing about the user's stack is sent
// anywhere except package names to OSV (as for npm packages).
package news

import (
	"context"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
)

// Window is how far back news reach.
const Window = 30 * 24 * time.Hour

// Where is one place in the user's Docker files a news item is about.
type Where struct {
	Project string `json:"project"` // project name
	Dir     string `json:"dir"`     // project folder
	File    string `json:"file"`    // relative to Dir
	Line    int    `json:"line,omitempty"`
	Image   string `json:"image,omitempty"`
	Service string `json:"service,omitempty"`
}

// Item is one piece of news.
type Item struct {
	ID       string    `json:"id"`
	Mine     bool      `json:"mine"`            // about something in the user's Docker files
	Maybe    bool      `json:"maybe,omitempty"` // general news that names something in the user's stack
	Source   string    `json:"source"`
	URL      string    `json:"url,omitempty"`
	At       time.Time `json:"at"`
	Severity string    `json:"severity"` // critical | high | medium | low | eol | release | update
	KEV      bool      `json:"kev,omitempty"`
	Product  string    `json:"product"`
	Title    i18n.T    `json:"title"`
	Desc     i18n.T    `json:"desc,omitempty"`
	CVEs     []string  `json:"cves,omitempty"`
	Fix      string    `json:"fix,omitempty"`
	Cmd      string    `json:"cmd,omitempty"` // a suggestion only
	Where    []Where   `json:"where,omitempty"`
}

// Feed is the whole news page.
type Feed struct {
	Items   []Item    `json:"items"`
	Updated time.Time `json:"updated"`
	Errors  []string  `json:"errors,omitempty"`
}

// Options of one build.
type Options struct {
	Now      time.Time
	Offline  bool
	MaxOSV   int                  // package lookups at most (0: 40)
	FirstSee map[string]time.Time // when DepGate first saw an item without a date of its own
}

var cveRe = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

// Build makes the feed from the scanned projects and the public sources.
func Build(ctx context.Context, f sources.Fetcher, ps []*report.Project, o Options) Feed {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.MaxOSV == 0 {
		o.MaxOSV = 40
	}
	feed := Feed{Items: []Item{}, Updated: o.Now.UTC()}
	fail := func(err error) {
		if err != nil {
			feed.Errors = append(feed.Errors, err.Error())
		}
	}
	kev := map[string]sources.KEVEntry{}
	entries, err := sources.KEVEntries(ctx, f)
	fail(err)
	for _, e := range entries {
		kev[e.CVE] = e
	}
	isKEV := func(cves []string) bool {
		for _, c := range cves {
			if _, ok := kev[c]; ok {
				return true
			}
		}
		return false
	}

	byID := map[string]*Item{}
	add := func(it Item, w *Where) {
		if x, ok := byID[it.ID]; ok {
			if w != nil {
				x.Where = appendWhere(x.Where, *w)
			}
			return
		}
		if w != nil {
			it.Where = []Where{*w}
		}
		cp := it
		byID[it.ID] = &cp
	}
	first := func(id string) time.Time {
		if t, ok := o.FirstSee[id]; ok {
			return t
		}
		return o.Now.UTC()
	}

	// 1. mine: what DepGate already found about the images (no network here)
	for _, p := range ps {
		for _, d := range append(append([]report.DockerIssue(nil), p.Docker...), p.Server...) {
			sev, ok := issueKinds[d.Rule]
			if !ok {
				continue
			}
			if sev == "" {
				sev = d.Severity
			}
			cves := cveRe.FindAllString(d.Detail.En+" "+d.Title.En, -1)
			id := "img:" + d.Rule + ":" + d.Title.En
			w := Where{Project: p.Name, Dir: p.Dir, File: d.File, Line: d.Line, Service: d.Service, Image: imageAt(p, d.File, d.Line)}
			it := Item{ID: id, Mine: true, Source: issueSource[d.Rule], At: first(id), Severity: sev, KEV: isKEV(cves),
				Product: productOf(w.Image, d.Rule), Title: d.Title, Desc: d.Detail, CVEs: uniq(cves), Fix: d.Fix, Cmd: fixCmd(d.File, d.Service, d.Fix)}
			if it.KEV {
				it.Severity = "critical"
			}
			add(it, &w)
		}
	}

	// 2. mine: fresh security records of the OS packages inside the images
	type pkgKey struct{ eco, name, osName string }
	wheres := map[pkgKey][]Where{}
	var keys []pkgKey
	for _, p := range ps {
		for _, im := range p.Images {
			eco, osName := ecosystem(im)
			if eco == "" {
				continue
			}
			w := Where{Project: p.Name, Dir: p.Dir, File: im.File, Line: im.Line, Image: im.Image, Service: im.Service}
			for _, name := range append(append([]string(nil), basePackages[im.OS]...), im.Packages...) {
				k := pkgKey{eco, sourceName(name), osName}
				if _, ok := wheres[k]; !ok {
					keys = append(keys, k)
				}
				wheres[k] = appendWhere(wheres[k], w)
			}
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].eco+keys[i].name < keys[j].eco+keys[j].name })
	if len(keys) > o.MaxOSV {
		feed.Errors = append(feed.Errors, "OSV: only the first "+itoa(o.MaxOSV)+" of "+itoa(len(keys))+" system packages were checked")
		keys = keys[:o.MaxOSV]
	}
	osv := sources.NewOSV(f)
	for _, k := range keys {
		vs, err := osv.Recent(ctx, k.eco, k.name)
		if err != nil {
			fail(err)
			continue
		}
		n := 0
		sort.Slice(vs, func(i, j int) bool { return dateOf(vs[i]).After(dateOf(vs[j])) })
		for _, v := range vs {
			at := dateOf(v)
			if v.Withdrawn != "" || at.IsZero() || o.Now.Sub(at) > Window || n >= 5 {
				continue
			}
			fix := v.FixedIn(k.eco, k.name)
			if fix == "" {
				continue // nothing to update to yet
			}
			n++
			cves := cves(v)
			sev, _ := v.SeverityLevel()
			if sev == "moderate" {
				sev = "medium"
			}
			sum := strings.TrimSpace(v.Summary)
			if sum == "" {
				sum = strings.Join(cves, ", ")
			}
			id := "osv:" + k.eco + ":" + k.name + ":" + v.ID
			it := Item{ID: id, Mine: true, Source: "OSV · " + k.osName, URL: "https://osv.dev/vulnerability/" + v.ID, At: at, Severity: sev,
				KEV: isKEV(cves), Product: k.name + " · " + k.osName, CVEs: cves, Fix: k.name + " " + fix,
				Title: i18n.F("%s (%s): %s", "%s (%s): %s", k.name, k.osName, clip(sum, 160)),
				Desc:  i18n.F("Image-in içindəki sistem paketi. Düzəliş distributivin deposundadır: image-i --pull ilə yenidən qur və ya baza image-in yeni build-ini çək.", "A system package inside the image. The fix is in the distribution's repository: rebuild the image with --pull, or pull a new build of the base image.")}
			if it.KEV {
				it.Severity = "critical"
			}
			for _, w := range wheres[k] {
				w := w
				if it.Cmd == "" {
					it.Cmd = rebuildCmd(w)
				}
				add(it, &w)
			}
		}
	}

	// 3. general: CISA KEV additions about servers and DevOps software
	stackWords := stackKeywords(ps)
	for _, e := range entries {
		at, err := time.Parse("2006-01-02", e.Added)
		if err != nil || o.Now.Sub(at) > Window || !infra(e.Vendor+" "+e.Product) {
			continue
		}
		it := Item{ID: "kev:" + e.CVE, Source: "CISA KEV", URL: "https://nvd.nist.gov/vuln/detail/" + e.CVE, At: at.UTC(), Severity: "critical", KEV: true,
			Product: strings.TrimSpace(e.Vendor + " " + e.Product), CVEs: []string{e.CVE},
			Title: i18n.F("%s: %s", "%s: %s", e.CVE, clip(e.Name, 160)),
			Desc:  i18n.F("Real hücumlarda istifadə olunur. %s Tələb olunan: %s", "Exploited in real attacks. %s Required action: %s", clip(e.Description, 400), clip(e.Action, 200))}
		it.Maybe = mentions(stackWords, e.Vendor+" "+e.Product)
		add(it, nil)
	}

	// 4. general: Ubuntu and Debian bulletins for core server software
	for _, src := range []struct{ url, name string }{{sources.UbuntuUSN, "Ubuntu USN"}, {sources.DebianDSA, "Debian DSA"}} {
		items, err := sources.Feed(ctx, f, src.url)
		if err != nil {
			fail(err)
			continue
		}
		for _, fi := range items {
			if fi.At.IsZero() || o.Now.Sub(fi.At) > Window || !coreBulletin(fi.Title) {
				continue
			}
			cv := uniq(cveRe.FindAllString(fi.Title+" "+fi.Description, -1))
			it := Item{ID: "feed:" + strings.ToLower(firstWord(fi.Title)), Source: src.name, URL: fi.Link, At: fi.At, Severity: "update", KEV: isKEV(cv),
				Product: bulletinProduct(fi.Title), CVEs: cv, Title: i18n.F("%s", "%s", clip(fi.Title, 160)), Desc: i18n.F("%s", "%s", clip(stripTags(fi.Description), 400))}
			if it.KEV {
				it.Severity = "critical"
			}
			it.Maybe = mentions(stackWords, fi.Title)
			add(it, nil)
		}
	}

	for _, it := range byID {
		feed.Items = append(feed.Items, *it)
	}
	sort.Slice(feed.Items, func(i, j int) bool {
		a, b := feed.Items[i], feed.Items[j]
		if !a.At.Equal(b.At) {
			return a.At.After(b.At)
		}
		return a.ID < b.ID
	})
	if len(feed.Items) > 300 {
		feed.Items = feed.Items[:300]
	}
	return feed
}

// the image issues that are news, with their kind ("" keeps the issue's severity)
var issueKinds = map[string]string{
	"image-eol": "eol", "image-eol-soon": "eol", "image-os-eol": "eol", "image-outdated-patch": "release",
	"nginx-vulnerable": "", "caddy-vulnerable": "", "caddy-outdated": "release",
}

var issueSource = map[string]string{
	"image-eol": "endoflife.date", "image-eol-soon": "endoflife.date", "image-os-eol": "endoflife.date", "image-outdated-patch": "endoflife.date",
	"nginx-vulnerable": "nginx.org", "caddy-vulnerable": "OSV · Caddy", "caddy-outdated": "GitHub releases",
}

// packages every image of a distribution has, whatever the Dockerfile installs
var basePackages = map[string][]string{
	"debian": {"openssl", "glibc", "zlib"},
	"ubuntu": {"openssl", "glibc", "zlib"},
	"alpine": {"openssl", "musl", "busybox", "zlib"},
}

// sourceName maps a few binary package names to the source package OSV knows.
func sourceName(n string) string {
	switch n {
	case "libssl3", "libssl-dev", "libssl3t64":
		return "openssl"
	case "libc6", "libc-bin", "libc6-dev":
		return "glibc"
	case "zlib1g", "zlib1g-dev":
		return "zlib"
	case "libcurl4", "libcurl4-openssl-dev":
		return "curl"
	case "openssh-client", "openssh-server":
		return "openssh"
	case "python3":
		return "python3-defaults"
	}
	return n
}

// ecosystem names the OSV ecosystem of an image's OS ("" when the version is unknown).
func ecosystem(im report.ImageItem) (eco, name string) {
	if im.OSVersion == "" {
		return "", ""
	}
	switch im.OS {
	case "debian":
		return "Debian:" + im.OSVersion, "Debian " + im.OSVersion
	case "ubuntu":
		eco = "Ubuntu:" + im.OSVersion
		if strings.HasSuffix(im.OSVersion, ".04") && atoi(im.OSVersion[:2])%2 == 0 {
			eco += ":LTS"
		}
		return eco, "Ubuntu " + im.OSVersion
	case "alpine":
		return "Alpine:v" + im.OSVersion, "Alpine " + im.OSVersion
	}
	return "", ""
}

func dateOf(v sources.Vuln) time.Time {
	for _, s := range []string{v.Published, v.Modified} {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func cves(v sources.Vuln) []string {
	out := []string{}
	for _, a := range append([]string{v.ID}, v.Aliases...) {
		if m := cveRe.FindString(a); m != "" {
			out = append(out, m)
		}
	}
	return uniq(out)
}

// infra tells whether a KEV vendor/product is server or DevOps software.
func infra(s string) bool {
	s = strings.ToLower(s)
	for _, k := range infraWords {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

var infraWords = []string{"linux", "kernel", "openssh", "openssl", "sudo", "glibc", "gnu c", "systemd", "polkit", "docker", "kubernetes", "runc",
	"containerd", "nginx", "apache", "tomcat", "postgres", "mysql", "mariadb", "redis", "mongodb", "elastic", "jenkins", "gitlab", "github",
	"git", "atlassian", "jira", "confluence", "bitbucket", "grafana", "hashicorp", "terraform", "traefik", "haproxy", "node.js", "nodejs",
	"python", "php", "xz", "exim", "postfix", "bind", "samba", "vmware", "citrix", "f5 big-ip", "rabbitmq", "kafka", "openvpn", "wireguard"}

// coreBulletin tells whether a distribution bulletin is about core server software.
func coreBulletin(title string) bool {
	t := " " + strings.ToLower(title) + " "
	for _, k := range coreWords {
		if strings.Contains(t, k) {
			return true
		}
	}
	return false
}

var coreWords = []string{" linux", "kernel", "openssh", "openssl", " sudo", "glibc", "systemd", "polkit", "docker", "containerd", " runc", "nginx",
	"apache2", "postgresql", "mysql", "mariadb", "redis", " git ", " git:", " curl", "bind9", "xz-utils", "libssh", "gnutls", "python3", "nodejs",
	"haproxy", "exim", "postfix", "samba", "openvpn", "rsync", "squid", "dnsmasq", "nss "}

func bulletinProduct(title string) string {
	t := title
	if i := strings.Index(t, ":"); i >= 0 && strings.HasPrefix(strings.ToUpper(t), "USN") { // "USN-1-1: OpenSSL vulnerabilities"
		t = strings.TrimSpace(t[i+1:])
		for _, suf := range []string{" vulnerabilities", " vulnerability", " regression", " regressions", " update"} {
			t = strings.TrimSuffix(t, suf)
		}
		return t
	}
	if f := strings.Fields(t); len(f) >= 2 && strings.HasPrefix(strings.ToUpper(f[0]), "DSA") { // "DSA-5800-1 openssl - security update"
		return f[1]
	}
	return t
}

func firstWord(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return s
	}
	return strings.TrimSuffix(f[0], ":")
}

// stackKeywords are the names in the user's stack a general item may mention.
func stackKeywords(ps []*report.Project) map[string]bool {
	m := map[string]bool{}
	for _, p := range ps {
		for _, im := range p.Images {
			for _, n := range append(append([]string{im.Product}, im.Packages...), basePackages[im.OS]...) {
				if n != "" && len(n) > 2 {
					m[strings.ToLower(n)] = true
				}
			}
			if im.Product == "postgres" {
				m["postgresql"] = true
			}
			if im.Product == "node" {
				m["node.js"], m["nodejs"] = true, true
			}
		}
	}
	return m
}

var wordRe = regexp.MustCompile(`[a-z0-9.+-]+`)

func mentions(words map[string]bool, s string) bool {
	for _, w := range wordRe.FindAllString(strings.ToLower(s), -1) {
		if words[w] {
			return true
		}
	}
	return false
}

func imageAt(p *report.Project, file string, line int) string {
	for _, im := range p.Images {
		if im.File == file && (im.Line == line || line == 0) {
			return im.Image
		}
	}
	return ""
}

func productOf(image, rule string) string {
	if image == "" {
		return strings.SplitN(rule, "-", 2)[0]
	}
	n := image
	if i := strings.LastIndex(n, ":"); i > strings.LastIndex(n, "/") {
		n = n[:i]
	}
	return n[strings.LastIndex(n, "/")+1:]
}

// fixCmd suggests the line to write for an image fix.
func fixCmd(file, service, fix string) string {
	if fix == "" || strings.ContainsAny(fix, " \n") {
		return ""
	}
	if service != "" {
		return "image: " + fix + "   # " + filepath.Base(file) + " · docker compose pull " + service + " && docker compose up -d " + service
	}
	return "FROM " + fix + "   # " + filepath.Base(file)
}

func rebuildCmd(w Where) string {
	if w.Service != "" {
		return "docker compose pull " + w.Service + " && docker compose up -d " + w.Service
	}
	return "docker build --pull --no-cache -f " + filepath.ToSlash(w.File) + " ."
}

func appendWhere(ws []Where, w Where) []Where {
	for _, x := range ws {
		if x.Dir == w.Dir && x.File == w.File && x.Line == w.Line {
			return ws
		}
		// a compose file shared by a monorepo's projects: once
		if filepath.Clean(filepath.Join(x.Dir, x.File)) == filepath.Clean(filepath.Join(w.Dir, w.File)) && x.Line == w.Line {
			return ws
		}
	}
	return append(ws, w)
}

var tagRe = regexp.MustCompile(`<[^>]*>`)

func stripTags(s string) string {
	return strings.Join(strings.Fields(tagRe.ReplaceAllString(s, " ")), " ")
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func uniq(xs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
