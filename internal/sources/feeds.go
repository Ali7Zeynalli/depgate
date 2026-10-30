package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"
)

// Feeds for the news page: CISA KEV entries, RSS/RDF/Atom bulletins of the Linux
// distributions, and the recent OSV records of one package.

// UbuntuUSN and DebianDSA are the distributions' security bulletin feeds.
const (
	UbuntuUSN = "https://ubuntu.com/security/notices/rss.xml"
	DebianDSA = "https://www.debian.org/security/dsa.rdf"
	kevURL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

// KEVEntry is one record of CISA's Known Exploited Vulnerabilities catalog.
type KEVEntry struct {
	CVE         string `json:"cveID"`
	Vendor      string `json:"vendorProject"`
	Product     string `json:"product"`
	Name        string `json:"vulnerabilityName"`
	Added       string `json:"dateAdded"` // YYYY-MM-DD
	Description string `json:"shortDescription"`
	Action      string `json:"requiredAction"`
	Ransomware  string `json:"knownRansomwareCampaignUse"`
}

// KEVEntries returns the whole KEV catalog (cached a few hours).
func KEVEntries(ctx context.Context, f Fetcher) ([]KEVEntry, error) {
	b, err := f.Do(ctx, "GET", kevURL, nil, nil, 6*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("CISA KEV: %w", err)
	}
	var doc struct {
		Vulnerabilities []KEVEntry `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("CISA KEV: %w", err)
	}
	return doc.Vulnerabilities, nil
}

// FeedItem is one entry of an RSS, RDF (RSS 1.0) or Atom feed.
type FeedItem struct {
	Title, Link, Description string
	At                       time.Time
}

// Feed reads an RSS, RDF or Atom feed (cached a few hours).
func Feed(ctx context.Context, f Fetcher, url string) ([]FeedItem, error) {
	b, err := f.Do(ctx, "GET", url, nil, nil, 3*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	items, err := ParseFeed(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	return items, nil
}

// ParseFeed reads <item> (RSS 2.0, RDF) and <entry> (Atom) elements by their
// local names, so namespaces do not matter.
func ParseFeed(b []byte) ([]FeedItem, error) {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = false
	d.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	var out []FeedItem
	var cur *FeedItem
	field := ""
	var text strings.Builder
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			if len(out) > 0 {
				break // keep what was read before the error
			}
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := t.Name.Local
			switch {
			case n == "item" || n == "entry":
				cur = &FeedItem{}
			case cur != nil:
				field = n
				text.Reset()
				if n == "link" { // Atom: <link href="…"/>
					for _, a := range t.Attr {
						if a.Name.Local == "href" && cur.Link == "" {
							cur.Link = a.Value
						}
					}
				}
			}
		case xml.CharData:
			if cur != nil && field != "" {
				text.Write(t)
			}
		case xml.EndElement:
			n := t.Name.Local
			if cur == nil {
				continue
			}
			if n == "item" || n == "entry" {
				out = append(out, *cur)
				cur = nil
				continue
			}
			if n == field {
				v := strings.TrimSpace(text.String())
				switch n {
				case "title":
					cur.Title = v
				case "link":
					if v != "" {
						cur.Link = v
					}
				case "description", "summary", "content":
					if cur.Description == "" {
						cur.Description = v
					}
				case "pubDate", "date", "published", "updated":
					if at, ok := parseFeedTime(v); ok && cur.At.IsZero() {
						cur.At = at
					}
				}
				field = ""
			}
		}
	}
	return out, nil
}

func parseFeedTime(v string) (time.Time, bool) {
	for _, l := range []string{time.RFC1123Z, time.RFC1123, time.RFC3339, "Mon, 2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 MST", "2006-01-02T15:04:05Z07:00", "2006-01-02"} {
		if t, err := time.Parse(l, v); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// Recent returns the OSV records of a package in an ecosystem (all versions:
// the version installed in an image is not known), e.g. ("Debian:12", "openssl").
func (o *OSV) Recent(ctx context.Context, ecosystem, name string) ([]Vuln, error) {
	body, _ := json.Marshal(map[string]any{"package": map[string]string{"name": name, "ecosystem": ecosystem}})
	b, err := o.F.Do(ctx, "POST", osvBase+"/query", body, nil, 6*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("OSV %s %s: %w", ecosystem, name, err)
	}
	var resp struct {
		Vulns []Vuln `json:"vulns"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, fmt.Errorf("OSV: bad response: %w", err)
	}
	return resp.Vulns, nil
}

// FixedIn returns the first "fixed" version of name in ecosystem ("" when none).
func (v *Vuln) FixedIn(ecosystem, name string) string {
	for _, a := range v.Affected {
		if a.Package.Name != name || a.Package.Ecosystem != ecosystem {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}
