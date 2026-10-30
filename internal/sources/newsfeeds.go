package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Topics of the general news, in the order the UI shows them.
var NewsTopics = []string{"zeroday", "security", "cve", "linux", "containers", "devops", "code", "ai", "cloud", "hot", "tools"}

// NewsSource is one public feed of the general news. Kind tells how it is read:
// rss (RSS/RDF/Atom), jsonfeed, nvd, ghsa, kev.
type NewsSource struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Topic string `json:"topic"`
	Kind  string `json:"kind"`
	URL   string `json:"url"`
	Home  string `json:"home"`
	// Official sources (advisories, CVE records) come before news sites when the
	// same story is told by several.
	Official bool `json:"official,omitempty"`
	Custom   bool `json:"custom,omitempty"`
}

// NewsSources are the built-in general news feeds. Each can be switched off
// in the news settings; any RSS/Atom feed can be added there too.
var NewsSources = []NewsSource{
	// zero-days and exploited vulnerabilities: the first places a new hole shows up
	{ID: "kev", Name: "CISA KEV", Topic: "zeroday", Kind: "kev", URL: kevURL, Home: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", Official: true},
	{ID: "oss-security", Name: "oss-security", Topic: "zeroday", Kind: "rss", URL: "https://seclists.org/rss/oss-sec.rss", Home: "https://www.openwall.com/lists/oss-security/", Official: true},
	{ID: "zdi-upcoming", Name: "ZDI upcoming", Topic: "zeroday", Kind: "rss", URL: "https://www.zerodayinitiative.com/rss/upcoming/", Home: "https://www.zerodayinitiative.com/advisories/upcoming/", Official: true},
	{ID: "zdi", Name: "ZDI advisories", Topic: "zeroday", Kind: "rss", URL: "https://www.zerodayinitiative.com/rss/published/", Home: "https://www.zerodayinitiative.com/advisories/published/", Official: true},
	{ID: "project-zero", Name: "Google Project Zero", Topic: "zeroday", Kind: "rss", URL: "https://googleprojectzero.blogspot.com/feeds/posts/default", Home: "https://googleprojectzero.blogspot.com", Official: true},
	{ID: "cisa", Name: "CISA advisories", Topic: "zeroday", Kind: "rss", URL: "https://www.cisa.gov/cybersecurity-advisories/all.xml", Home: "https://www.cisa.gov/news-events/cybersecurity-advisories", Official: true},
	// security news sites
	{ID: "thehackernews", Name: "The Hacker News", Topic: "security", Kind: "rss", URL: "https://feeds.feedburner.com/TheHackersNews", Home: "https://thehackernews.com"},
	{ID: "bleepingcomputer", Name: "BleepingComputer", Topic: "security", Kind: "rss", URL: "https://www.bleepingcomputer.com/feed/", Home: "https://www.bleepingcomputer.com"},
	{ID: "securityweek", Name: "SecurityWeek", Topic: "security", Kind: "rss", URL: "https://www.securityweek.com/feed/", Home: "https://www.securityweek.com"},
	{ID: "therecord", Name: "The Record", Topic: "security", Kind: "rss", URL: "https://therecord.media/feed/", Home: "https://therecord.media"},
	{ID: "darkreading", Name: "Dark Reading", Topic: "security", Kind: "rss", URL: "https://www.darkreading.com/rss.xml", Home: "https://www.darkreading.com"},
	{ID: "krebs", Name: "Krebs on Security", Topic: "security", Kind: "rss", URL: "https://krebsonsecurity.com/feed/", Home: "https://krebsonsecurity.com"},
	// CVE records
	{ID: "nvd", Name: "NVD (critical)", Topic: "cve", Kind: "nvd", URL: nvdAPI, Home: "https://nvd.nist.gov", Official: true},
	{ID: "ghsa", Name: "GitHub Advisory Database (critical)", Topic: "code", Kind: "ghsa", URL: ghsaAPI, Home: "https://github.com/advisories", Official: true},
	// Linux
	{ID: "usn", Name: "Ubuntu USN", Topic: "linux", Kind: "rss", URL: UbuntuUSN, Home: "https://ubuntu.com/security/notices", Official: true},
	{ID: "dsa", Name: "Debian DSA", Topic: "linux", Kind: "rss", URL: DebianDSA, Home: "https://www.debian.org/security/", Official: true},
	{ID: "lwn", Name: "LWN.net", Topic: "linux", Kind: "rss", URL: "https://lwn.net/headlines/rss", Home: "https://lwn.net"},
	{ID: "phoronix", Name: "Phoronix", Topic: "linux", Kind: "rss", URL: "https://www.phoronix.com/rss.php", Home: "https://www.phoronix.com"},
	// containers and Kubernetes
	{ID: "k8s-cve", Name: "Kubernetes CVE feed", Topic: "containers", Kind: "jsonfeed", URL: "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json", Home: "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/", Official: true},
	{ID: "k8s-blog", Name: "Kubernetes blog", Topic: "containers", Kind: "rss", URL: "https://kubernetes.io/feed.xml", Home: "https://kubernetes.io/blog/"},
	{ID: "docker", Name: "Docker blog", Topic: "containers", Kind: "rss", URL: "https://www.docker.com/blog/feed/", Home: "https://www.docker.com/blog/"},
	{ID: "cncf", Name: "CNCF blog", Topic: "containers", Kind: "rss", URL: "https://www.cncf.io/feed/", Home: "https://www.cncf.io/blog/"},
	// DevOps
	{ID: "github-changelog", Name: "GitHub Changelog", Topic: "devops", Kind: "rss", URL: "https://github.blog/changelog/feed/", Home: "https://github.blog/changelog/"},
	{ID: "hashicorp", Name: "HashiCorp blog", Topic: "devops", Kind: "rss", URL: "https://www.hashicorp.com/blog/feed.xml", Home: "https://www.hashicorp.com/blog"},
	{ID: "gitlab", Name: "GitLab releases", Topic: "devops", Kind: "rss", URL: "https://about.gitlab.com/all-releases.xml", Home: "https://about.gitlab.com/releases/"},
	// programming
	{ID: "go", Name: "The Go Blog", Topic: "code", Kind: "rss", URL: "https://go.dev/blog/feed.atom", Home: "https://go.dev/blog/"},
	{ID: "nodejs", Name: "Node.js blog", Topic: "code", Kind: "rss", URL: "https://nodejs.org/en/feed/blog.xml", Home: "https://nodejs.org/en/blog"},
	{ID: "python", Name: "Python Insider", Topic: "code", Kind: "rss", URL: "https://blog.python.org/feeds/posts/default", Home: "https://blog.python.org"},
	// AI
	{ID: "openai", Name: "OpenAI News", Topic: "ai", Kind: "rss", URL: "https://openai.com/news/rss.xml", Home: "https://openai.com/news/"},
	{ID: "google-ai", Name: "Google AI", Topic: "ai", Kind: "rss", URL: "https://blog.google/technology/ai/rss/", Home: "https://blog.google/technology/ai/"},
	{ID: "deepmind", Name: "Google DeepMind", Topic: "ai", Kind: "rss", URL: "https://deepmind.google/blog/rss.xml", Home: "https://deepmind.google/discover/blog/"},
	{ID: "huggingface", Name: "Hugging Face", Topic: "ai", Kind: "rss", URL: "https://huggingface.co/blog/feed.xml", Home: "https://huggingface.co/blog"},
	{ID: "simonwillison", Name: "Simon Willison", Topic: "ai", Kind: "rss", URL: "https://simonwillison.net/atom/everything/", Home: "https://simonwillison.net"},
	{ID: "techcrunch-ai", Name: "TechCrunch AI", Topic: "ai", Kind: "rss", URL: "https://techcrunch.com/category/artificial-intelligence/feed/", Home: "https://techcrunch.com/category/artificial-intelligence/"},
	{ID: "verge-ai", Name: "The Verge AI", Topic: "ai", Kind: "rss", URL: "https://www.theverge.com/rss/ai-artificial-intelligence/index.xml", Home: "https://www.theverge.com/ai-artificial-intelligence"},
	// cloud
	{ID: "aws-security", Name: "AWS security bulletins", Topic: "cloud", Kind: "rss", URL: "https://aws.amazon.com/security/security-bulletins/feed/", Home: "https://aws.amazon.com/security/security-bulletins/", Official: true},
	// what the tech world is talking about
	{ID: "hackernews", Name: "Hacker News (300+ points)", Topic: "hot", Kind: "rss", URL: "https://hnrss.org/frontpage?points=300", Home: "https://news.ycombinator.com"},
}

const (
	nvdAPI  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	ghsaAPI = "https://api.github.com/advisories"
)

// FeedTTL is how long a news feed is cached.
const FeedTTL = 50 * time.Minute

// FeedFor reads an RSS/RDF/Atom feed with the news cache time.
func FeedFor(ctx context.Context, f Fetcher, u string) ([]FeedItem, error) {
	b, err := f.Do(ctx, "GET", u, nil, nil, FeedTTL)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", host(u), err)
	}
	items, err := ParseFeed(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", host(u), err)
	}
	return items, nil
}

func host(u string) string {
	if p, err := url.Parse(u); err == nil && p.Host != "" {
		return p.Host
	}
	return u
}

// JSONFeed reads a JSON Feed (jsonfeed.org; the Kubernetes CVE feed is one).
func JSONFeed(ctx context.Context, f Fetcher, u string) ([]FeedItem, error) {
	b, err := f.Do(ctx, "GET", u, nil, nil, FeedTTL)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", host(u), err)
	}
	var doc struct {
		Items []struct {
			ID          string `json:"id"`
			Title       string `json:"title"`
			Summary     string `json:"summary"`
			ContentText string `json:"content_text"`
			ContentHTML string `json:"content_html"`
			URL         string `json:"url"`
			ExternalURL string `json:"external_url"`
			Published   string `json:"date_published"`
			Modified    string `json:"date_modified"`
		} `json:"items"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", host(u), err)
	}
	out := make([]FeedItem, 0, len(doc.Items))
	for _, x := range doc.Items {
		it := FeedItem{Title: first(x.Title, x.Summary, x.ID), Link: first(x.URL, x.ExternalURL), Description: first(x.ContentText, x.ContentHTML)}
		if it.Description == it.Title {
			it.Description = ""
		}
		if strings.HasPrefix(x.ID, "CVE-") && !strings.Contains(it.Title, x.ID) {
			it.Title = x.ID + ": " + it.Title
		}
		for _, s := range []string{x.Published, x.Modified} {
			if t, ok := parseFeedTime(s); ok {
				it.At = t
				break
			}
		}
		out = append(out, it)
	}
	return out, nil
}

func first(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return strings.TrimSpace(x)
		}
	}
	return ""
}

// CVERecord is one CVE of the NVD or one GitHub advisory.
type CVERecord struct {
	ID        string    // CVE id (or GHSA id when there is no CVE)
	Aliases   []string  // the other id
	Published time.Time // when the record was published
	Severity  string    // critical | high | medium | low
	Score     float64
	Summary   string
	Desc      string
	URL       string
	Packages  []string // ecosystem/name (GitHub advisories)
	Fixed     string   // first patched version of the first package (GitHub advisories)
}

// NVDRecent returns the critical CVEs the NVD published in the last days.
func NVDRecent(ctx context.Context, f Fetcher, now time.Time, days int) ([]CVERecord, error) {
	// whole days, so the cached answer is reused within the hour
	end := now.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	start := end.Add(-time.Duration(days+1) * 24 * time.Hour)
	const layout = "2006-01-02T15:04:05.000"
	u := nvdAPI + "?cvssV3Severity=CRITICAL&resultsPerPage=500&pubStartDate=" + start.Format(layout) + "&pubEndDate=" + end.Format(layout)
	b, err := f.Do(ctx, "GET", u, nil, nil, FeedTTL)
	if err != nil {
		return nil, fmt.Errorf("NVD: %w", err)
	}
	var doc struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				Status       string `json:"vulnStatus"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics map[string][]struct {
					Data struct {
						Score    float64 `json:"baseScore"`
						Severity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("NVD: %w", err)
	}
	var out []CVERecord
	for _, v := range doc.Vulnerabilities {
		c := v.CVE
		if c.Status == "Rejected" {
			continue
		}
		r := CVERecord{ID: c.ID, URL: "https://nvd.nist.gov/vuln/detail/" + c.ID, Severity: "critical"}
		for _, d := range c.Descriptions {
			if d.Lang == "en" {
				r.Desc = d.Value
				break
			}
		}
		for _, k := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30"} {
			if ms := c.Metrics[k]; len(ms) > 0 {
				r.Score = ms[0].Data.Score
				if s := strings.ToLower(ms[0].Data.Severity); s != "" {
					r.Severity = s
				}
				break
			}
		}
		for _, l := range []string{"2006-01-02T15:04:05.000", "2006-01-02T15:04:05", time.RFC3339} {
			if t, err := time.Parse(l, c.Published); err == nil {
				r.Published = t.UTC()
				break
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// GHSARecent returns the newest reviewed critical advisories of the GitHub
// Advisory Database (every ecosystem: npm, pip, Go, Maven, Rust…).
func GHSARecent(ctx context.Context, f Fetcher) ([]CVERecord, error) {
	h := map[string]string{"Accept": "application/vnd.github+json"}
	if t := firstEnv("DEPGATE_GITHUB_TOKEN", "GITHUB_TOKEN"); t != "" {
		h["Authorization"] = "Bearer " + t
	}
	b, err := f.Do(ctx, "GET", ghsaAPI+"?type=reviewed&severity=critical&per_page=60&sort=published&direction=desc", nil, h, FeedTTL)
	if err != nil {
		return nil, fmt.Errorf("GitHub advisories: %w", err)
	}
	var doc []struct {
		GHSA      string  `json:"ghsa_id"`
		CVE       string  `json:"cve_id"`
		URL       string  `json:"html_url"`
		Summary   string  `json:"summary"`
		Desc      string  `json:"description"`
		Severity  string  `json:"severity"`
		Published string  `json:"published_at"`
		Withdrawn *string `json:"withdrawn_at"`
		CVSS      struct {
			Score float64 `json:"score"`
		} `json:"cvss"`
		Vulns []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			Patched json.RawMessage `json:"first_patched_version"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("GitHub advisories: %w", err)
	}
	var out []CVERecord
	for _, a := range doc {
		if a.Withdrawn != nil {
			continue
		}
		r := CVERecord{ID: first(a.CVE, a.GHSA), URL: a.URL, Severity: strings.ToLower(a.Severity), Score: a.CVSS.Score, Summary: a.Summary, Desc: a.Desc}
		if a.CVE != "" {
			r.Aliases = []string{a.GHSA}
		}
		if t, err := time.Parse(time.RFC3339, a.Published); err == nil {
			r.Published = t.UTC()
		}
		for _, v := range a.Vulns {
			r.Packages = append(r.Packages, v.Package.Ecosystem+"/"+v.Package.Name)
			if r.Fixed == "" && len(v.Patched) > 0 {
				var s string
				if json.Unmarshal(v.Patched, &s) != nil { // the repository API nests it
					var o struct {
						ID string `json:"identifier"`
					}
					_ = json.Unmarshal(v.Patched, &o)
					s = o.ID
				}
				if s != "" {
					r.Fixed = v.Package.Name + " " + s
				}
			}
		}
		out = append(out, r)
	}
	return out, nil
}
