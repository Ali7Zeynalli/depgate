package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strings"
	"sync"
	"time"
)

const osvBase = "https://api.osv.dev/v1"

// Query is one name@version to check.
type Query struct {
	Name    string
	Version string
}

// Vuln is the subset of an OSV record DepGate uses.
type Vuln struct {
	ID               string     `json:"id"`
	Aliases          []string   `json:"aliases"`
	Summary          string     `json:"summary"`
	Details          string     `json:"details"`
	Published        string     `json:"published"`
	Withdrawn        string     `json:"withdrawn"`
	Severity         []osvSev   `json:"severity"`
	Affected         []Affected `json:"affected"`
	References       []osvRef   `json:"references"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`

	// set for records that come from the npm bulk advisory endpoint
	NpmRange  string `json:"-"` // npm semver range of affected versions
	Malicious bool   `json:"-"` // CWE-506 malware advisory
	Link      string `json:"-"` // advisory page
	From      string `json:"-"` // "npm" when not (yet) known to OSV
}

type osvSev struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges   []OSVRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

type OSVRange struct {
	Type   string `json:"type"`
	Events []struct {
		Introduced   string `json:"introduced,omitempty"`
		Fixed        string `json:"fixed,omitempty"`
		LastAffected string `json:"last_affected,omitempty"`
	} `json:"events"`
}

// IsMalware reports whether the record is an OpenSSF malicious-package entry.
func (v *Vuln) IsMalware() bool { return strings.HasPrefix(v.ID, "MAL-") || v.Malicious }

// CVEs returns the CVE aliases (or the ID itself when it is a CVE).
func (v *Vuln) CVEs() []string {
	var out []string
	if strings.HasPrefix(v.ID, "CVE-") {
		out = append(out, v.ID)
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			out = append(out, a)
		}
	}
	return out
}

// URL returns a human page for the advisory.
func (v *Vuln) URL() string {
	if v.Link != "" {
		return v.Link
	}
	if strings.HasPrefix(v.ID, "GHSA-") {
		return "https://github.com/advisories/" + v.ID
	}
	return "https://osv.dev/vulnerability/" + url.PathEscape(v.ID)
}

// FixCommits returns references of type FIX (used for reachability later).
func (v *Vuln) FixCommits() []string {
	var out []string
	for _, r := range v.References {
		if r.Type == "FIX" {
			out = append(out, r.URL)
		}
	}
	return out
}

// SeverityLevel returns critical|high|moderate|low and the CVSS base score (0 when unknown).
func (v *Vuln) SeverityLevel() (string, float64) {
	score := 0.0
	for _, s := range v.Severity {
		if strings.HasPrefix(s.Type, "CVSS_V3") {
			if sc, ok := CVSS3Base(s.Score); ok {
				score = sc
			}
		}
	}
	switch strings.ToUpper(v.DatabaseSpecific.Severity) {
	case "CRITICAL":
		return "critical", score
	case "HIGH":
		return "high", score
	case "MODERATE", "MEDIUM":
		return "moderate", score
	case "LOW":
		return "low", score
	}
	switch {
	case score >= 9:
		return "critical", score
	case score >= 7:
		return "high", score
	case score >= 4:
		return "moderate", score
	case score > 0:
		return "low", score
	}
	if v.IsMalware() {
		return "critical", score
	}
	return "moderate", score // unknown: assume moderate rather than hide it
}

// OSV queries api.osv.dev.
type OSV struct {
	F Fetcher

	mu    sync.Mutex
	vulns map[string]*Vuln
}

func NewOSV(f Fetcher) *OSV { return &OSV{F: f, vulns: map[string]*Vuln{}} }

type osvBatchReq struct {
	Queries []osvQuery `json:"queries"`
}
type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}
type osvBatchResp struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

// Batch returns, for each query index, the matching vulnerability IDs.
func (o *OSV) Batch(ctx context.Context, qs []Query) ([][]string, error) {
	out := make([][]string, len(qs))
	for start := 0; start < len(qs); start += 1000 {
		end := min(start+1000, len(qs))
		var req osvBatchReq
		for _, q := range qs[start:end] {
			var oq osvQuery
			oq.Package.Name, oq.Package.Ecosystem, oq.Version = q.Name, "npm", q.Version
			req.Queries = append(req.Queries, oq)
		}
		body, _ := json.Marshal(req)
		b, err := o.F.Do(ctx, "POST", osvBase+"/querybatch", body, nil, 6*time.Hour)
		if err != nil {
			return nil, fmt.Errorf("OSV: %w", err)
		}
		var resp osvBatchResp
		if err := json.Unmarshal(b, &resp); err != nil {
			return nil, fmt.Errorf("OSV: bad response: %w", err)
		}
		for i, r := range resp.Results {
			if start+i >= len(out) {
				break
			}
			for _, v := range r.Vulns {
				out[start+i] = append(out[start+i], v.ID)
			}
		}
	}
	return out, nil
}

// Query returns the IDs of the vulnerabilities affecting one package version
// of any OSV ecosystem (e.g. "Go", "github.com/caddyserver/caddy/v2", "2.7.6").
func (o *OSV) Query(ctx context.Context, ecosystem, name, version string) ([]string, error) {
	var q osvQuery
	q.Package.Name, q.Package.Ecosystem, q.Version = name, ecosystem, version
	body, _ := json.Marshal(q)
	b, err := o.F.Do(ctx, "POST", osvBase+"/query", body, nil, 6*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("OSV: %w", err)
	}
	var resp struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, fmt.Errorf("OSV: bad response: %w", err)
	}
	var ids []string
	for _, v := range resp.Vulns {
		ids = append(ids, v.ID)
	}
	return ids, nil
}

// FixedFor returns the lowest "fixed" event above version for the package, from
// the record's ranges ("" when none). Versions compare as dotted numbers.
func (v *Vuln) FixedFor(name, version string) string {
	best := ""
	for _, a := range v.Affected {
		if a.Package.Name != name {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if f := strings.TrimPrefix(e.Fixed, "v"); f != "" && CompareDotted(f, version) > 0 && (best == "" || CompareDotted(f, best) < 0) {
					best = f
				}
			}
		}
	}
	return best
}

// Get returns the full record (cached in memory and on disk).
func (o *OSV) Get(ctx context.Context, id string) (*Vuln, error) {
	o.mu.Lock()
	if v, ok := o.vulns[id]; ok {
		o.mu.Unlock()
		return v, nil
	}
	o.mu.Unlock()
	b, err := o.F.Do(ctx, "GET", osvBase+"/vulns/"+url.PathEscape(id), nil, nil, 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("OSV %s: %w", id, err)
	}
	var v Vuln
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("OSV %s: %w", id, err)
	}
	o.mu.Lock()
	o.vulns[id] = &v
	o.mu.Unlock()
	return &v, nil
}

// CVSS3Base computes the CVSS v3.0/v3.1 base score from a vector string.
func CVSS3Base(vector string) (float64, bool) {
	if !strings.HasPrefix(vector, "CVSS:3") {
		return 0, false
	}
	m := map[string]string{}
	for _, p := range strings.Split(vector, "/")[1:] {
		k, v, ok := strings.Cut(p, ":")
		if ok {
			m[k] = v
		}
	}
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	changed := m["S"] == "C"
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if changed {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if changed {
			pr = 0.5
		}
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, i, a := cia[m["C"]], cia[m["I"]], cia[m["A"]]
	if av == 0 || ac == 0 || ui == 0 || pr == 0 || m["C"] == "" || m["I"] == "" || m["A"] == "" || (m["S"] != "U" && m["S"] != "C") {
		return 0, false
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}
	expl := 8.22 * av * ac * pr * ui
	var base float64
	if changed {
		base = roundup(math.Min(1.08*(impact+expl), 10))
	} else {
		base = roundup(math.Min(impact+expl, 10))
	}
	return base, true
}

// roundup is the CVSS 3.1 Roundup function.
func roundup(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}
