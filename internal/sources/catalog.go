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
		Use:    i18n.F("Zəifliklər (CVE/GHSA) və zərərli paketlər — GitHub Advisory Database və OpenSSF Malicious Packages bura daxildir", "Vulnerabilities (CVE/GHSA) and malicious packages — includes the GitHub Advisory Database and OpenSSF Malicious Packages"),
		prefix: []string{"https://api.osv.dev/"}},
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
		Use:    i18n.F("Hədəf versiyanın engines, peer asılılıqları, install script-ləri, provenance və deprecated qeydi", "The target version's engines, peer dependencies, install scripts, provenance and deprecation"),
		prefix: []string{"https://registry.npmjs.org/"}},
	{ID: "node", Name: "Node.js releases", Home: "https://nodejs.org/en/about/previous-releases",
		Use:    i18n.F("Node.js versiyaları, təhlükəsizlik buraxılışları və EOL tarixləri (nodejs.org, nodejs/Release)", "Node.js versions, security releases and end-of-life dates (nodejs.org, nodejs/Release)"),
		prefix: []string{"https://nodejs.org/", "https://raw.githubusercontent.com/nodejs/Release/"}},
}

// SourceOf returns the catalog ID a request URL belongs to ("" if none).
func SourceOf(url string) string {
	for _, s := range Catalog {
		for _, p := range s.prefix {
			if strings.HasPrefix(url, p) {
				return s.ID
			}
		}
	}
	return ""
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
