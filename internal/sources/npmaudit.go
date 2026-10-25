package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const npmBulkURL = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"

// NpmAdvisory is one entry of the npm registry bulk advisory response — the
// same data `npm audit` uses (GitHub Advisory Database, malware included).
type NpmAdvisory struct {
	ID                 int      `json:"id"`
	URL                string   `json:"url"`
	Title              string   `json:"title"`
	Severity           string   `json:"severity"`
	VulnerableVersions string   `json:"vulnerable_versions"`
	CWE                []string `json:"cwe"`
	CVSS               struct {
		Score  float64 `json:"score"`
		Vector string  `json:"vectorString"`
	} `json:"cvss"`
}

// GHSA returns the GitHub advisory ID from the URL ("" if none).
func (a NpmAdvisory) GHSA() string {
	if i := strings.Index(a.URL, "/GHSA-"); i >= 0 {
		return a.URL[i+1:]
	}
	return ""
}

// Malicious reports CWE-506 (embedded malicious code), which GitHub uses for malware advisories.
func (a NpmAdvisory) Malicious() bool {
	for _, c := range a.CWE {
		if c == "CWE-506" {
			return true
		}
	}
	return false
}

// NpmBulk asks the npm registry which advisories apply to the given versions.
// The answer lists advisories per package; callers match versions themselves.
func NpmBulk(ctx context.Context, f Fetcher, pkgs map[string][]string) (map[string][]NpmAdvisory, error) {
	out := map[string][]NpmAdvisory{}
	names := make([]string, 0, len(pkgs))
	for n := range pkgs {
		names = append(names, n)
	}
	sort.Strings(names)
	for start := 0; start < len(names); start += 500 {
		end := min(start+500, len(names))
		req := map[string][]string{}
		for _, n := range names[start:end] {
			req[n] = pkgs[n]
		}
		body, _ := json.Marshal(req)
		b, err := f.Do(ctx, "POST", npmBulkURL, body, map[string]string{"Content-Type": "application/json"}, 6*time.Hour)
		if err != nil {
			return out, fmt.Errorf("npm advisories: %w", err)
		}
		var resp map[string][]NpmAdvisory
		if err := json.Unmarshal(b, &resp); err != nil {
			return out, fmt.Errorf("npm advisories: bad response: %w", err)
		}
		for k, v := range resp {
			out[k] = append(out[k], v...)
		}
	}
	return out, nil
}

// FromNpm turns an npm advisory into a Vuln record. The npm range is kept as
// NpmRange so matching follows the advisory exactly (prereleases included).
func FromNpm(name string, a NpmAdvisory) *Vuln {
	id := a.GHSA()
	if id == "" {
		id = fmt.Sprintf("NPM-%d", a.ID)
	}
	v := &Vuln{ID: id, Summary: a.Title, NpmRange: a.VulnerableVersions, Malicious: a.Malicious(), Link: a.URL, From: "npm"}
	v.DatabaseSpecific.Severity = a.Severity
	v.DatabaseSpecific.CWEIDs = a.CWE
	if a.CVSS.Vector != "" {
		v.Severity = []osvSev{{Type: "CVSS_V3", Score: a.CVSS.Vector}}
	}
	var af Affected
	af.Package.Ecosystem, af.Package.Name = "npm", name
	v.Affected = []Affected{af}
	return v
}
