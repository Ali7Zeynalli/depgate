package sources

import (
	"context"
	"fmt"
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// NginxAdvisoriesURL is nginx's own list of security advisories.
const NginxAdvisoriesURL = "https://nginx.org/en/security_advisories.html"

// NginxAdvisory is one entry of nginx.org/en/security_advisories.html.
type NginxAdvisory struct {
	Title    string
	Severity string      // low | medium | major (as nginx writes it)
	CVEs     []string    // CVE ids
	Link     string      // advisory page
	Vuln     [][2]string // inclusive ranges "a-b" (b may equal a)
	Safe     []string    // "1.31.7+" entries without the "+"
}

// NginxAdvisories loads and parses the nginx advisory page (cached a day).
func NginxAdvisories(ctx context.Context, f Fetcher) ([]NginxAdvisory, error) {
	b, err := f.Do(ctx, "GET", NginxAdvisoriesURL, nil, nil, 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("nginx advisories: %w", err)
	}
	as := ParseNginxAdvisories(string(b))
	if len(as) == 0 {
		return nil, fmt.Errorf("nginx advisories: no entries found (page format changed?)")
	}
	return as, nil
}

var (
	reTag     = regexp.MustCompile(`(?s)<[^>]*>`)
	reBreak   = regexp.MustCompile(`(?i)<\s*(br|/p|p|li|/li|tr|/tr|/td|td)\b[^>]*>`)
	reHref    = regexp.MustCompile(`(?i)<a[^>]+href="([^"]+)"[^>]*>\s*Advisory\s*</a>`)
	reCVE     = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	reVersion = regexp.MustCompile(`^\d+(\.\d+){1,3}$`)
)

// ParseNginxAdvisories reads the advisory page. It works on the text of the
// page (tags removed, line breaks kept), so small markup changes do not break it:
// every advisory is "title / Severity: … / Advisory / CVE-… / Not vulnerable: … / Vulnerable: …".
func ParseNginxAdvisories(page string) []NginxAdvisory {
	links := reHref.FindAllStringSubmatch(page, -1)
	text := reBreak.ReplaceAllString(page, "\n")
	text = reTag.ReplaceAllString(text, "")
	var lines []string
	for _, l := range strings.Split(html.UnescapeString(text), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	var out []NginxAdvisory
	li := 0
	for i := 0; i < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "Severity:") || i == 0 {
			continue
		}
		a := NginxAdvisory{Title: lines[i-1], Severity: strings.ToLower(strings.TrimSpace(strings.TrimPrefix(lines[i], "Severity:")))}
		j := i + 1
		for ; j < len(lines) && j < i+12; j++ {
			l := lines[j]
			switch {
			case strings.HasPrefix(l, "Severity:"):
				j = len(lines) // next advisory without a Vulnerable line: stop
			case l == "Advisory":
				if li < len(links) {
					a.Link = html.UnescapeString(links[li][1])
					li++
				}
			case strings.HasPrefix(l, "Not vulnerable:"):
				for _, p := range strings.Split(strings.TrimPrefix(l, "Not vulnerable:"), ",") {
					p = strings.TrimSuffix(strings.TrimSpace(p), "+")
					if reVersion.MatchString(p) {
						a.Safe = append(a.Safe, p)
					}
				}
			case strings.HasPrefix(l, "Vulnerable:"):
				for _, p := range strings.Split(strings.TrimPrefix(l, "Vulnerable:"), ",") {
					p = strings.TrimSpace(p)
					lo, hi, ok := strings.Cut(p, "-")
					if !ok {
						hi = lo
					}
					if reVersion.MatchString(strings.TrimSpace(lo)) && reVersion.MatchString(strings.TrimSpace(hi)) {
						a.Vuln = append(a.Vuln, [2]string{strings.TrimSpace(lo), strings.TrimSpace(hi)})
					}
				}
				j = len(lines)
			default:
				for _, c := range reCVE.FindAllString(l, -1) {
					a.CVEs = append(a.CVEs, c)
				}
			}
		}
		if len(a.Vuln) > 0 {
			out = append(out, a)
		}
	}
	return out
}

// Affects reports whether nginx version v (e.g. "1.25.3") is vulnerable.
// A version inside a vulnerable range is still safe when a "Not vulnerable"
// entry covers it: "1.30.6+" covers 1.30.6 and later 1.30.x; the highest
// entry also covers every later version.
func (a NginxAdvisory) Affects(v string) bool {
	in := false
	for _, r := range a.Vuln {
		if CompareDotted(v, r[0]) >= 0 && CompareDotted(v, r[1]) <= 0 {
			in = true
			break
		}
	}
	if !in {
		return false
	}
	return !a.safe(v)
}

func (a NginxAdvisory) safe(v string) bool {
	top := ""
	for _, s := range a.Safe {
		if top == "" || CompareDotted(s, top) > 0 {
			top = s
		}
	}
	for _, s := range a.Safe {
		if CompareDotted(v, s) >= 0 && (minorOf(v) == minorOf(s) || s == top) {
			return true
		}
	}
	return false
}

// NginxFix returns the lowest version above v that none of the advisories
// affect, picked from their "Not vulnerable" entries ("" when unknown).
func NginxFix(as []NginxAdvisory, v string) string {
	var cands []string
	for _, a := range as {
		cands = append(cands, a.Safe...)
	}
	sort.Slice(cands, func(i, j int) bool { return CompareDotted(cands[i], cands[j]) < 0 })
	for _, c := range cands {
		if CompareDotted(c, v) <= 0 {
			continue
		}
		ok := true
		for _, a := range as {
			if a.Affects(c) {
				ok = false
				break
			}
		}
		if ok {
			return c
		}
	}
	return ""
}

func minorOf(v string) string {
	p := strings.SplitN(v, ".", 3)
	if len(p) < 2 {
		return v
	}
	return p[0] + "." + p[1]
}

// CompareDotted compares numeric dotted versions ("1.9.2" < "1.10.0").
func CompareDotted(a, b string) int {
	as, bs := strings.Split(strings.TrimPrefix(a, "v"), "."), strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
