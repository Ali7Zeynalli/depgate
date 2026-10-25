package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// NodeRelease is one entry of nodejs.org/dist/index.json.
type NodeRelease struct {
	Version  string `json:"version"` // "v22.23.4"
	Date     string `json:"date"`
	LTS      any    `json:"lts"` // false or codename
	Security bool   `json:"security"`
}

func (r NodeRelease) Codename() string {
	if s, ok := r.LTS.(string); ok {
		return s
	}
	return ""
}

// NodeLine is one entry of nodejs/Release schedule.json.
type NodeLine struct {
	Start       string `json:"start"`
	LTS         string `json:"lts"`
	Maintenance string `json:"maintenance"`
	End         string `json:"end"`
	Codename    string `json:"codename"`
}

type NodeData struct {
	Releases []NodeRelease
	Schedule map[int]NodeLine // keyed by major
}

// Node loads release and schedule data.
func Node(ctx context.Context, f Fetcher) (*NodeData, error) {
	b, err := f.Do(ctx, "GET", "https://nodejs.org/dist/index.json", nil, nil, 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("nodejs.org: %w", err)
	}
	nd := &NodeData{Schedule: map[int]NodeLine{}}
	if err := json.Unmarshal(b, &nd.Releases); err != nil {
		return nil, fmt.Errorf("nodejs.org index.json: %w", err)
	}
	sb, err := f.Do(ctx, "GET", "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json", nil, nil, 7*24*time.Hour)
	if err == nil {
		var raw map[string]NodeLine
		if json.Unmarshal(sb, &raw) == nil {
			for k, v := range raw {
				if n, err := strconv.Atoi(strings.TrimPrefix(k, "v")); err == nil {
					nd.Schedule[n] = v
				}
			}
		}
	}
	return nd, nil
}

// KEV returns the set of CVE IDs in CISA's Known Exploited Vulnerabilities catalog.
func KEV(ctx context.Context, f Fetcher) (map[string]bool, error) {
	b, err := f.Do(ctx, "GET", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", nil, nil, 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("CISA KEV: %w", err)
	}
	var doc struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("CISA KEV: %w", err)
	}
	out := make(map[string]bool, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		out[v.CveID] = true
	}
	return out, nil
}

// EPSS returns exploit-probability scores (0..1) for the given CVEs.
func EPSS(ctx context.Context, f Fetcher, cves []string) (map[string]float64, error) {
	out := map[string]float64{}
	for start := 0; start < len(cves); start += 100 {
		end := min(start+100, len(cves))
		u := "https://api.first.org/data/v1/epss?cve=" + strings.Join(cves[start:end], ",")
		b, err := f.Do(ctx, "GET", u, nil, nil, 24*time.Hour)
		if err != nil {
			return out, fmt.Errorf("EPSS: %w", err)
		}
		var doc struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			return out, fmt.Errorf("EPSS: %w", err)
		}
		for _, d := range doc.Data {
			if v, err := strconv.ParseFloat(d.EPSS, 64); err == nil {
				out[d.CVE] = v
			}
		}
	}
	return out, nil
}
