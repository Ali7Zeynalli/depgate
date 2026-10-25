package sources

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
)

// Info describes one public data source DepGate decides with.
type Info struct {
	ID     string
	Name   string
	Home   string
	Use    i18n.T
	prefix []string // request URL prefixes that belong to this source
}

// Catalog lists every source, in the order the UI shows them.
var Catalog = []Info{
	{ID: "osv", Name: "OSV.dev", Home: "https://osv.dev",
		Use:    i18n.F("Zəifliklər (CVE/GHSA) və zərərli paketlər — GitHub Advisory Database və OpenSSF Malicious Packages bura daxildir; Caddy versiyasının zəiflikləri də buradan (Go vulndb)", "Vulnerabilities (CVE/GHSA) and malicious packages — includes the GitHub Advisory Database and OpenSSF Malicious Packages; also the vulnerabilities of your Caddy version (Go vulndb)"),
		prefix: []string{"https://api.osv.dev/"}},
	{ID: "npmaudit", Name: "npm advisories (npm audit)", Home: "https://docs.npmjs.com/cli/commands/npm-audit",
		Use:    i18n.F("npm audit-in mənbəyi: GitHub Advisory Database birbaşa, zərərli paketlər daxil — OSV-nin hələ almadığı qeydləri tutur", "The source of npm audit: the GitHub Advisory Database directly, malware included — catches records OSV has not imported yet"),
		prefix: []string{npmBulkURL}},
	{ID: "kev", Name: "CISA KEV", Home: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
		Use:    i18n.F("Real hücumlarda istifadə olunan zəifliklər — prioriteti qaldırır", "Vulnerabilities exploited in real attacks — raises priority"),
		prefix: []string{"https://www.cisa.gov/"}},
	{ID: "epss", Name: "FIRST EPSS", Home: "https://www.first.org/epss/",
		Use:    i18n.F("Yaxın 30 gündə istismar olunma ehtimalı — prioritetə təsir edir", "Probability of exploitation in the next 30 days — feeds the priority"),
		prefix: []string{"https://api.first.org/"}},
	{ID: "depsdev", Name: "deps.dev (Google)", Home: "https://deps.dev",
		Use:    i18n.F("Paketin bütün versiyaları və buraxılış tarixləri — ən təhlükəsiz hədəf versiya və gözləmə müddəti", "Every version of a package and its publish date — safest target version and release cooldown"),
		prefix: []string{"https://api.deps.dev/"}},
	{ID: "npm", Name: "npm registry", Home: "https://www.npmjs.com",
		Use:    i18n.F("Hədəf versiyanın engines, peer asılılıqları, install script-ləri, provenance və deprecated qeydi; lockfile-dakı versiyanın npm-dən silinib-silinmədiyi", "The target version's engines, peer dependencies, install scripts, provenance and deprecation; whether the locked version was removed from npm"),
		prefix: []string{"https://registry.npmjs.org/"}},
	{ID: "github", Name: "GitHub releases", Home: "https://docs.github.com/en/rest/releases/releases",
		Use:    i18n.F("Major yeniləmələrdə cari və hədəf versiya arasındakı release-lərin «breaking changes» bölmələri və Caddy-nin son versiyası (DEPGATE_GITHUB_TOKEN limiti artırır)", "The breaking-change sections of the releases between your version and the target, for major updates, and the latest Caddy release (DEPGATE_GITHUB_TOKEN raises the limit)"),
		prefix: []string{githubAPI}},
	{ID: "nginx", Name: "nginx security advisories", Home: NginxAdvisoriesURL,
		Use:    i18n.F("nginx-in rəsmi zəiflik siyahısı: hansı versiyalar zəifdir, hansında düzəlib — Docker-dəki nginx image versiyası buna görə yoxlanır", "nginx's own advisory list: which versions are vulnerable and which fix them — the nginx image version in your Docker files is checked against it"),
		prefix: []string{"https://nginx.org/"}},
	{ID: "endoflife", Name: "endoflife.date", Home: "https://endoflife.date",
		Use:    i18n.F("Docker image-lərinin (postgres, redis, nginx, python, alpine, debian…) dəstək müddəti və son patch versiyaları", "Support dates and latest patch releases of the Docker images you use (postgres, redis, nginx, python, alpine, debian…)"),
		prefix: []string{eolAPI}},
	{ID: "node", Name: "Node.js releases", Home: "https://nodejs.org/en/about/previous-releases",
		Use:    i18n.F("Node.js versiyaları, təhlükəsizlik buraxılışları, EOL tarixləri və versiyana aid CVE-lər (nodejs.org, nodejs/Release, Node.js Security WG)", "Node.js versions, security releases, end-of-life dates and the CVEs that affect your version (nodejs.org, nodejs/Release, Node.js security WG)"),
		prefix: []string{"https://nodejs.org/", "https://raw.githubusercontent.com/nodejs/"}},
}

// SourceOf returns the catalog ID a request URL belongs to ("" if none).
func SourceOf(url string) string {
	id, best := "", 0
	for _, s := range Catalog {
		for _, p := range s.prefix {
			if len(p) > best && strings.HasPrefix(url, p) {
				id, best = s.ID, len(p)
			}
		}
	}
	return id
}

// Usage is how one source answered during a scan.
type Usage struct {
	Requests int
	Failed   int
}

// Recorder wraps a Fetcher and counts requests per source.
type Recorder struct {
	F  Fetcher
	mu sync.Mutex
	m  map[string]*Usage
}

func NewRecorder(f Fetcher) *Recorder { return &Recorder{F: f, m: map[string]*Usage{}} }

func (r *Recorder) Do(ctx context.Context, method, url string, body []byte, headers map[string]string, ttl time.Duration) ([]byte, error) {
	b, err := r.F.Do(ctx, method, url, body, headers, ttl)
	if id := SourceOf(url); id != "" {
		r.mu.Lock()
		u := r.m[id]
		if u == nil {
			u = &Usage{}
			r.m[id] = u
		}
		u.Requests++
		if err != nil && !errors.Is(err, ErrNotFound) && ctx.Err() == nil {
			u.Failed++
		}
		r.mu.Unlock()
	}
	return b, err
}

// Usage returns a copy of the counters.
func (r *Recorder) Usage() map[string]Usage {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]Usage, len(r.m))
	for k, v := range r.m {
		out[k] = *v
	}
	return out
}
