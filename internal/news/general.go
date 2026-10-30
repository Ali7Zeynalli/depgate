package news

import (
	"context"
	"hash/fnv"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
)

// MaxGeneral is how many general items the feed keeps at most.
const MaxGeneral = 900

const (
	newsWindow = 14 * 24 * time.Hour // news sites
	perSource  = 30                  // newest items of one feed
	nvdDays    = 7
)

// Settings choose the general sources: built-in ones can be switched off (by
// id, or a whole topic as "topic:<name>"), RSS/Atom feeds added, and GitHub
// repositories watched for releases.
type Settings struct {
	Off   []string     `json:"off"`
	Feeds []CustomFeed `json:"feeds"`
	Watch []string     `json:"watch"` // owner/repo
}

// CustomFeed is an RSS/Atom feed the user added.
type CustomFeed struct {
	Name  string `json:"name"`
	URL   string `json:"url"`
	Topic string `json:"topic"`
}

var repoRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// Clean drops what cannot be used and returns the settings tidied up.
func (s Settings) Clean() Settings {
	out := Settings{Off: []string{}, Feeds: []CustomFeed{}, Watch: []string{}}
	seen := map[string]bool{}
	for _, x := range s.Off {
		if x = strings.TrimSpace(x); x != "" && !seen[x] && len(out.Off) < 200 {
			seen[x] = true
			out.Off = append(out.Off, x)
		}
	}
	topics := map[string]bool{}
	for _, t := range sources.NewsTopics {
		topics[t] = true
	}
	for _, f := range s.Feeds {
		f.URL = strings.TrimSpace(f.URL)
		u, err := url.Parse(f.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || seen[f.URL] || len(out.Feeds) >= 50 {
			continue
		}
		seen[f.URL] = true
		if !topics[f.Topic] {
			f.Topic = "security"
		}
		f.Name = clip(strings.TrimSpace(f.Name), 60)
		if f.Name == "" {
			f.Name = u.Host
		}
		out.Feeds = append(out.Feeds, f)
	}
	for _, r := range s.Watch {
		r = strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(r, "https://"), "github.com/")), "/")
		if repoRe.MatchString(r) && !seen["gh:"+strings.ToLower(r)] && len(out.Watch) < 100 {
			seen["gh:"+strings.ToLower(r)] = true
			out.Watch = append(out.Watch, r)
		}
	}
	return out
}

// Active returns the sources to read: the built-in ones that are on, the
// user's feeds and the watched repositories.
func (s Settings) Active() []sources.NewsSource {
	off := map[string]bool{}
	for _, x := range s.Off {
		off[x] = true
	}
	var out []sources.NewsSource
	for _, src := range All(s) {
		if !off[src.ID] && !off["topic:"+src.Topic] {
			out = append(out, src)
		}
	}
	return out
}

// All returns every source the settings know, on or off.
func All(s Settings) []sources.NewsSource {
	out := append([]sources.NewsSource(nil), sources.NewsSources...)
	for _, f := range s.Feeds {
		out = append(out, sources.NewsSource{ID: "custom:" + hash(f.URL), Name: f.Name, Topic: f.Topic, Kind: "rss", URL: f.URL, Home: f.URL, Custom: true})
	}
	for _, r := range s.Watch {
		out = append(out, sources.NewsSource{ID: "gh:" + strings.ToLower(r), Name: r, Topic: "tools", Kind: "rss",
			URL: "https://github.com/" + r + "/releases.atom", Home: "https://github.com/" + r + "/releases", Custom: true})
	}
	return out
}

// general reads every active source and merges the same story told by several.
func general(ctx context.Context, f sources.Fetcher, o Options, kev []sources.KEVEntry, isKEV func([]string) bool, stackWords map[string]bool, feed *Feed) []Item {
	type result struct {
		src   sources.NewsSource
		items []Item
		err   error
	}
	active := o.Settings.Active()
	res := make([]result, len(active))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for i, src := range active {
		wg.Add(1)
		go func(i int, src sources.NewsSource) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			its, err := readSource(ctx, f, src, o, kev, isKEV, stackWords)
			res[i] = result{src, its, err}
		}(i, src)
	}
	wg.Wait()
	var all []Item
	for _, r := range res {
		st := SourceStat{Items: len(r.items)}
		if r.err != nil {
			st.Err = r.err.Error()
			feed.Errors = append(feed.Errors, r.src.Name+": "+r.err.Error())
		}
		feed.Sources[r.src.ID] = st
		all = append(all, r.items...)
	}
	return merge(all, active)
}

var (
	zeroDayRe = regexp.MustCompile(`(?i)\b(zero[- ]?days?|0[- ]?days?|actively exploited|exploited in the wild|in[- ]the[- ]wild|under active exploitation|unpatched|no (?:fix|patch)(?: is)?(?: available)?(?: yet)?|not (?:yet )?(?:fixed|patched)|(?:until|before) a fix(?:ed)?)\b`)
	cvssRe    = regexp.MustCompile(`(?i)(?:cvss[^0-9]{0,24}(\d{1,2}\.\d)|(\d{1,2}\.\d)\s*cvss)`)
	idRe      = regexp.MustCompile(`^(?i)(usn|dsa|dla)-\d+(-\d+)?$`)
)

// topic words: a story from a security site about the Linux kernel is Linux news too
var topicWords = map[string]*regexp.Regexp{
	"linux":      regexp.MustCompile(`(?i)\b(linux|kernel|ubuntu|debian|red ?hat|rhel|fedora|centos|almalinux|rocky linux|suse|alpine|glibc|systemd|openssh|sudo|polkit)\b`),
	"containers": regexp.MustCompile(`(?i)\b(docker|kubernetes|k8s|containers?|containerd|runc|podman|helm|cri-o)\b`),
	"devops":     regexp.MustCompile(`(?i)\b(devops|terraform|opentofu|ansible|jenkins|gitlab|github actions|ci/cd|argo ?cd|prometheus|grafana|nginx|haproxy|traefik|vault|consul|pipelines?)\b`),
	"ai":         regexp.MustCompile(`(?i)\b(ai|a\.i\.|artificial intelligence|llms?|gpt-?\d*|chatgpt|openai|anthropic|claude|gemini|llama|mistral|deepseek|hugging ?face|pytorch|tensorflow|langchain|ollama|vllm|mcp|machine learning|copilot|agentic|ai agents?)\b`),
	"cloud":      regexp.MustCompile(`(?i)\b(aws|amazon web services|azure|google cloud|gcp|cloudflare|s3 buckets?)\b`),
	"code":       regexp.MustCompile(`(?i)\b(npm|pypi|node\.js|nodejs|python|golang|rust|java|maven|php|ruby|supply[- ]chain|open[- ]source packages?)\b`),
}

func readSource(ctx context.Context, f sources.Fetcher, src sources.NewsSource, o Options, kev []sources.KEVEntry, isKEV func([]string) bool, stackWords map[string]bool) ([]Item, error) {
	now := o.Now
	window := newsWindow
	if src.Official || src.Topic == "tools" {
		window = Window
	}
	finish := func(it Item, text string) Item {
		it.Topics = topicsOf(src.Topic, text)
		if zeroDayRe.MatchString(text) || src.ID == "zdi-upcoming" {
			it.ZeroDay = true
			it.Topics = addTopic(it.Topics, "zeroday")
		}
		if !it.KEV {
			it.KEV = isKEV(it.CVEs)
		}
		if it.KEV {
			it.Severity = "critical"
			it.Topics = addTopic(it.Topics, "zeroday")
		}
		if !it.Maybe {
			it.Maybe = mentions(stackWords, it.Product+" "+it.Title.En)
		}
		return it
	}
	var out []Item
	switch src.Kind {
	case "kev":
		for _, e := range kev {
			at, err := time.Parse("2006-01-02", e.Added)
			if err != nil || now.Sub(at) > Window {
				continue
			}
			it := Item{ID: "kev:" + e.CVE, Source: src.Name, URL: "https://nvd.nist.gov/vuln/detail/" + e.CVE, At: at.UTC(), Severity: "critical", KEV: true, ZeroDay: true,
				Product: strings.TrimSpace(e.Vendor + " " + e.Product), CVEs: []string{e.CVE},
				Title: i18n.F("%s: %s", "%s: %s", e.CVE, clip(e.Name, 160)),
				Desc:  i18n.F("Real hücumlarda istifadə olunur. %s Tələb olunan: %s", "Exploited in real attacks. %s Required action: %s", clip(e.Description, 400), clip(e.Action, 200))}
			it.Maybe = mentions(stackWords, e.Vendor+" "+e.Product)
			out = append(out, finish(it, e.Vendor+" "+e.Product+" "+e.Name))
		}
		return out, nil
	case "nvd", "ghsa":
		var recs []sources.CVERecord
		var err error
		if src.Kind == "nvd" {
			recs, err = sources.NVDRecent(ctx, f, now, nvdDays)
		} else {
			recs, err = sources.GHSARecent(ctx, f)
		}
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			if r.Published.IsZero() || now.Sub(r.Published) > window {
				continue
			}
			text := r.Summary + " " + r.Desc + " " + strings.Join(r.Packages, " ")
			// the NVD publishes hundreds of critical CVEs a week, most for web plugins
			// nobody here runs: keep the ones about servers, DevOps, AI and the stack
			if src.Kind == "nvd" && !infra(text) && !topicWords["ai"].MatchString(text) && !topicWords["containers"].MatchString(text) && !mentions(stackWords, text) {
				continue
			}
			title := r.Summary
			if title == "" {
				title = r.Desc
			}
			product := ""
			if len(r.Packages) > 0 {
				product = r.Packages[0]
			}
			cv := uniq(cveRe.FindAllString(r.ID+" "+strings.Join(r.Aliases, " "), -1))
			it := Item{ID: src.ID + ":" + r.ID, Source: src.Name, URL: r.URL, At: r.Published, Severity: sevOf(r.Severity, r.Score), Product: product, CVEs: cv, Fix: r.Fixed,
				Title: i18n.F("%s: %s", "%s: %s", r.ID, clip(title, 160)), Desc: i18n.F("%s", "%s", clip(r.Desc, 400))}
			if r.Score > 0 {
				it.Desc = i18n.F("CVSS %s. %s", "CVSS %s. %s", strconv.FormatFloat(r.Score, 'f', 1, 64), clip(r.Desc, 400))
			}
			out = append(out, finish(it, text))
		}
		return out, nil
	}
	var fis []sources.FeedItem
	var err error
	if src.Kind == "jsonfeed" {
		fis, err = sources.JSONFeed(ctx, f, src.URL)
	} else {
		fis, err = sources.FeedFor(ctx, f, src.URL)
	}
	if err != nil {
		return nil, err
	}
	sort.SliceStable(fis, func(i, j int) bool { return fis[i].At.After(fis[j].At) })
	for _, fi := range fis {
		if len(out) >= perSource {
			break
		}
		at := fi.At
		if at.IsZero() {
			continue
		}
		if now.Sub(at) > window {
			continue
		}
		desc := stripTags(fi.Description)
		cv := uniq(cveRe.FindAllString(fi.Title+" "+desc, -1))
		id := "n:" + src.ID + ":" + hash(canon(fi.Link)+"|"+fi.Title)
		if w := strings.ToLower(firstWord(fi.Title)); idRe.MatchString(w) {
			id = "feed:" + w // USN/DSA ids, as before
		}
		sev := "news"
		if src.ID == "usn" || src.ID == "dsa" {
			sev = "update"
		}
		if m := cvssRe.FindStringSubmatch(fi.Title + " " + desc); m != nil {
			sc, _ := strconv.ParseFloat(m[1]+m[2], 64)
			if s := sevOf("", sc); s != "" {
				sev = s
			}
		}
		product := src.Name
		if src.ID == "usn" || src.ID == "dsa" {
			product = bulletinProduct(fi.Title)
		}
		if src.Topic == "tools" {
			product = src.Name
			sev = "release"
		}
		it := Item{ID: id, Source: src.Name, URL: fi.Link, At: at, Severity: sev, Product: product, CVEs: cv,
			Title: i18n.F("%s", "%s", clip(stripTags(fi.Title), 200)), Desc: i18n.F("%s", "%s", clip(desc, 360))}
		out = append(out, finish(it, fi.Title+" "+desc))
	}
	return out, nil
}

func sevOf(s string, score float64) string {
	switch s {
	case "critical", "high", "medium", "low":
		return s
	case "moderate":
		return "medium"
	}
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	}
	return "high"
}

func topicsOf(topic, text string) []string {
	ts := []string{topic}
	for _, t := range sources.NewsTopics {
		if re := topicWords[t]; re != nil && t != topic && re.MatchString(text) {
			ts = append(ts, t)
		}
	}
	return ts
}

func addTopic(ts []string, t string) []string {
	for _, x := range ts {
		if x == t {
			return ts
		}
	}
	return append(ts, t)
}

// ---------- the same story from several sources ----------

var (
	wordSplit = regexp.MustCompile(`[a-z0-9]+`)
	stopWords = map[string]bool{"with": true, "from": true, "that": true, "this": true, "into": true, "over": true, "their": true, "after": true,
		"about": true, "your": true, "have": true, "more": true, "than": true, "what": true, "when": true, "will": true, "were": true, "been": true,
		"flaw": true, "flaws": true, "vulnerability": true, "vulnerabilities": true, "security": true, "update": true, "updates": true, "attacks": true,
		"attackers": true, "users": true, "could": true, "allow": true, "allows": true, "says": true, "warns": true, "new": true, "news": true}
)

func words(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range wordSplit.FindAllString(strings.ToLower(s), -1) {
		if len(w) >= 4 && !stopWords[w] {
			m[w] = true
		}
	}
	return m
}

func similar(a, b map[string]bool) bool {
	if len(a) < 4 || len(b) < 4 {
		return false
	}
	n := 0
	for w := range a {
		if b[w] {
			n++
		}
	}
	return float64(n)/float64(len(a)+len(b)-n) >= 0.5
}

func canon(u string) string {
	p, err := url.Parse(strings.TrimSpace(u))
	if err != nil || p.Host == "" {
		return strings.TrimSpace(u)
	}
	return strings.TrimPrefix(strings.ToLower(p.Host), "www.") + strings.TrimSuffix(p.Path, "/")
}

func merge(items []Item, active []sources.NewsSource) []Item {
	official := map[string]bool{}
	for _, s := range active {
		if s.Official {
			official[s.Name] = true
		}
	}
	n := len(items)
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	union := func(a, b int) { parent[find(a)] = find(b) }
	byKey := map[string]int{}
	link := func(key string, i int) {
		if j, ok := byKey[key]; ok {
			union(i, j)
		} else {
			byKey[key] = i
		}
	}
	ws := make([]map[string]bool, n)
	for i, it := range items {
		if it.ID != "" {
			link("id:"+it.ID, i)
		}
		if it.URL != "" {
			link("url:"+canon(it.URL), i)
		}
		if len(it.CVEs) > 0 && len(it.CVEs) <= 5 { // a bulletin listing 80 kernel CVEs is not one story
			for _, c := range it.CVEs {
				link("cve:"+c, i)
			}
		}
		ws[i] = words(it.Title.En)
	}
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			d := items[i].At.Sub(items[j].At)
			if d < 0 {
				d = -d
			}
			if d <= 3*24*time.Hour && find(i) != find(j) && similar(ws[i], ws[j]) {
				union(i, j)
			}
		}
	}
	groups := map[int][]int{}
	var roots []int
	for i := range items {
		r := find(i)
		if _, ok := groups[r]; !ok {
			roots = append(roots, r)
		}
		groups[r] = append(groups[r], i)
	}
	rank := func(it Item) int {
		switch {
		case strings.HasPrefix(it.ID, "kev:"):
			return 0
		case official[it.Source]:
			return 1
		}
		return 2
	}
	sevRank := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "update": 1, "release": 1, "news": 0}
	out := make([]Item, 0, len(roots))
	for _, r := range roots {
		g := groups[r]
		sort.SliceStable(g, func(a, b int) bool {
			x, y := items[g[a]], items[g[b]]
			if rank(x) != rank(y) {
				return rank(x) < rank(y)
			}
			if !x.At.Equal(y.At) {
				return x.At.Before(y.At)
			}
			return x.ID < y.ID
		})
		it := items[g[0]]
		seenID := map[string]bool{it.ID: true}
		seenSrc := map[string]bool{it.Source + "|" + canon(it.URL): true}
		for _, k := range g[1:] {
			x := items[k]
			if !seenID[x.ID] {
				seenID[x.ID] = true
				it.Alias = append(it.Alias, x.ID)
			}
			if !seenSrc[x.Source+"|"+canon(x.URL)] {
				seenSrc[x.Source+"|"+canon(x.URL)] = true
				it.Also = append(it.Also, Ref{Source: x.Source, URL: x.URL, Title: clip(x.Title.En, 160)})
			}
			it.KEV = it.KEV || x.KEV
			it.ZeroDay = it.ZeroDay || x.ZeroDay
			it.Maybe = it.Maybe || x.Maybe
			if sevRank[x.Severity] > sevRank[it.Severity] {
				it.Severity = x.Severity
			}
			if x.At.After(it.At) {
				it.At = x.At // newest coverage first in «newest»
			}
			for _, t := range x.Topics {
				it.Topics = addTopic(it.Topics, t)
			}
			if len(it.CVEs) < 20 {
				it.CVEs = uniq(append(it.CVEs, x.CVEs...))
			}
			if it.Fix == "" {
				it.Fix = x.Fix
			}
			if it.Desc.En == "" {
				it.Desc = x.Desc
			}
		}
		it.Score = score(it)
		out = append(out, it)
	}
	return out
}

// score is how important an item is, before its age is counted (the page
// subtracts that): in your stack, exploited, zero-day, severity, how many
// sources tell it, and the topics DepGate's users care about most.
func score(it Item) int {
	s := 0
	if it.Mine {
		s += 1000
	}
	if it.KEV {
		s += 500
	}
	if it.ZeroDay {
		s += 300
	}
	if it.Maybe {
		s += 300
	}
	s += map[string]int{"critical": 200, "high": 120, "medium": 40, "eol": 150, "release": 30, "update": 30}[it.Severity]
	s += 40 * min(len(it.Also), 5)
	best := 0
	for _, t := range it.Topics {
		best = max(best, map[string]int{"linux": 60, "containers": 60, "devops": 60, "ai": 60, "zeroday": 40, "security": 40, "cve": 40, "tools": 60, "code": 30, "cloud": 30, "hot": 20}[t])
	}
	return s + best
}

func hash(s string) string {
	h := fnv.New64a()
	h.Write([]byte(s))
	return strconv.FormatUint(h.Sum64(), 36)
}
