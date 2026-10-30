package news

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
	"github.com/Ali7Zeynalli/depgate/internal/sources/sourcestest"
)

func vuln(t *testing.T, js string) sources.Vuln {
	var v sources.Vuln
	if err := json.Unmarshal([]byte(js), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestBuild(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	f := sourcestest.New(now)
	f.KEVFull = []sources.KEVEntry{
		{CVE: "CVE-2026-0001", Vendor: "Linux", Product: "Kernel", Name: "Linux Kernel Privilege Escalation", Added: "2026-10-29", Description: "x", Action: "patch"},
		{CVE: "CVE-2026-0002", Vendor: "Microsoft", Product: "Word", Name: "Word RCE", Added: "2026-10-29"},
		{CVE: "CVE-2026-0003", Vendor: "OpenSSL", Product: "OpenSSL", Name: "OpenSSL RCE", Added: "2026-10-28"},
		{CVE: "CVE-2020-0004", Vendor: "Linux", Product: "Kernel", Name: "old", Added: "2020-01-01"},
	}
	f.OSVRecent["Debian:12|openssl"] = []sources.Vuln{
		vuln(t, `{"id":"DEBIAN-CVE-2026-0003","aliases":["CVE-2026-0003"],"summary":"TLS handshake RCE","published":"2026-10-27T10:00:00Z","affected":[{"package":{"ecosystem":"Debian:12","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.15-1~deb12u3"}]}]}]}`),
		vuln(t, `{"id":"DEBIAN-CVE-2025-9999","summary":"old","published":"2025-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Debian:12","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1"}]}]}]}`),
		vuln(t, `{"id":"DEBIAN-CVE-2026-0005","summary":"no fix yet","published":"2026-10-27T10:00:00Z","affected":[{"package":{"ecosystem":"Debian:12","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`),
	}
	f.Feeds[sources.UbuntuUSN] = `<?xml version="1.0"?><rss version="2.0"><channel><title>USN</title>
<item><title>USN-7100-1: OpenSSH vulnerability</title><link>https://ubuntu.com/security/notices/USN-7100-1</link><description>&lt;p&gt;CVE-2026-0010 fixed&lt;/p&gt;</description><pubDate>Wed, 28 Oct 2026 14:44:52 +0000</pubDate></item>
<item><title>USN-7101-1: Thunderbird vulnerabilities</title><link>x</link><pubDate>Wed, 28 Oct 2026 14:44:52 +0000</pubDate></item>
</channel></rss>`
	f.Feeds[sources.DebianDSA] = `<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">
<item rdf:about="https://www.debian.org/security/2026/dsa-6000"><title>DSA-6000-1 postgresql-15 - security update</title><link>https://www.debian.org/security/2026/dsa-6000</link><description>Several issues</description><dc:date>2026-10-26</dc:date></item>
</rdf:RDF>`
	p := &report.Project{Name: "shop-web", Dir: "/p/shop-web",
		Images: []report.ImageItem{{File: "Dockerfile", Line: 1, Image: "node:22-bookworm-slim", Product: "node", OS: "debian", OSVersion: "12", Packages: []string{"curl"}},
			{File: "docker-compose.yml", Line: 4, Service: "db", Image: "postgres:16.4", Product: "postgres", OS: "debian", OSGuess: true}},
		Docker: []report.DockerIssue{{File: "docker-compose.yml", Line: 4, Service: "db", Rule: "image-outdated-patch", Severity: "medium",
			Title: i18n.F("postgres:16.4 köhnə", "postgres:16.4 is an old patch release (latest: 16.6)"), Fix: "postgres:16.6"}},
	}
	feed := Build(context.Background(), f, []*report.Project{p, {Name: "other", Dir: "/p/other", Images: p.Images}}, Options{Now: now})
	by := map[string]Item{}
	for _, it := range feed.Items {
		by[it.ID] = it
	}
	osv := by["osv:Debian:12:openssl:DEBIAN-CVE-2026-0003"]
	if !osv.Mine || !osv.KEV || osv.Severity != "critical" || osv.Fix != "openssl 3.0.15-1~deb12u3" || len(osv.Where) != 2 || osv.Cmd == "" {
		t.Fatalf("osv item %+v", osv)
	}
	if _, ok := by["osv:Debian:12:openssl:DEBIAN-CVE-2025-9999"]; ok {
		t.Fatal("old record kept")
	}
	if _, ok := by["osv:Debian:12:openssl:DEBIAN-CVE-2026-0005"]; ok {
		t.Fatal("record without a fix kept")
	}
	img := by["img:image-outdated-patch:postgres:16.4 is an old patch release (latest: 16.6)"]
	if !img.Mine || img.Severity != "release" || img.Where[0].Image != "postgres:16.4" || img.Cmd == "" {
		t.Fatalf("image item %+v", img)
	}
	if k := by["kev:CVE-2026-0001"]; k.Mine || !k.KEV || k.Maybe || !k.ZeroDay || !has(k.Topics, "zeroday") || !has(k.Topics, "linux") {
		t.Fatalf("kev %+v", k)
	}
	if k := by["kev:CVE-2026-0003"]; !k.Maybe {
		t.Fatalf("kev openssl should be maybe-mine %+v", k)
	}
	if _, ok := by["kev:CVE-2026-0002"]; !ok {
		t.Fatal("every KEV addition is news")
	}
	if _, ok := by["kev:CVE-2020-0004"]; ok {
		t.Fatal("old KEV kept")
	}
	if u := by["feed:usn-7100-1"]; u.Product != "OpenSSH" || len(u.CVEs) != 1 || u.Desc.En != "CVE-2026-0010 fixed" {
		t.Fatalf("usn %+v", u)
	}
	if u := by["feed:usn-7101-1"]; !has(u.Topics, "linux") {
		t.Fatalf("usn topics %+v", u)
	}
	if d := by["feed:dsa-6000-1"]; d.Product != "postgresql-15" || !d.At.Equal(time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("dsa %+v", d)
	}
	if feed.Stack.Images != 4 || feed.Stack.OSKnown != 2 || feed.Stack.Projects != 2 {
		t.Fatalf("stack %+v", feed.Stack)
	}
	if feed.Sources["usn"].Items != 2 || feed.Sources["kev"].Items != 3 {
		t.Fatalf("source stats %+v", feed.Sources)
	}
}

func has(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func rss(items ...string) string {
	return `<?xml version="1.0"?><rss version="2.0"><channel><title>x</title>` + strings.Join(items, "") + `</channel></rss>`
}

func rssItem(title, link, desc, date string) string {
	return "<item><title>" + title + "</title><link>" + link + "</link><description>" + desc + "</description><pubDate>" + date + "</pubDate></item>"
}

func TestGeneral(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	f := sourcestest.New(now)
	day := "Thu, 29 Oct 2026 10:00:00 +0000"
	f.Feeds["https://feeds.feedburner.com/TheHackersNews"] = rss(
		rssItem("Linux Kernel TCP Flaw With 9.8 CVSS Score Affects Ubuntu", "https://thehackernews.com/2026/10/tcp.html", "CVE-2026-98432 lets attackers…", day),
		rssItem("Old story", "https://thehackernews.com/old", "x", "Mon, 01 Jun 2026 10:00:00 +0000"))
	f.Feeds["https://www.bleepingcomputer.com/feed/"] = rss(
		rssItem("Ubuntu kernel bug CVE-2026-98432 gets a fix date", "https://www.bleepingcomputer.com/news/tcp/", "", "Thu, 29 Oct 2026 18:00:00 +0000"),
		rssItem("Hackers exploit Chrome zero-day in attacks", "https://www.bleepingcomputer.com/news/chrome/", "", day))
	f.Feeds["https://www.securityweek.com/feed/"] = rss(
		rssItem("Hackers Exploit Chrome Zero-Day in Attacks, Google Warns", "https://www.securityweek.com/chrome/", "", day))
	f.Feeds["https://openai.com/news/rss.xml"] = rss(rssItem("Introducing a new model", "https://openai.com/news/model", "", day))
	f.Feeds["https://github.com/caddyserver/caddy/releases.atom"] = `<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>v2.10.3</title><link href="https://github.com/caddyserver/caddy/releases/tag/v2.10.3"/><updated>2026-10-20T10:00:00Z</updated></entry></feed>`
	f.Feeds["https://example.org/feed.xml"] = rss(rssItem("My feed item", "https://example.org/1", "", day))
	f.Feeds["https://services.nvd.nist.gov/rest/json/cves/2.0*"] = `{"vulnerabilities":[
{"cve":{"id":"CVE-2026-98432","published":"2026-10-15T10:00:00.000","descriptions":[{"lang":"en","value":"In the Linux kernel, tcp: use-after-free"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]}}},
{"cve":{"id":"CVE-2026-55555","published":"2026-10-28T10:00:00.000","descriptions":[{"lang":"en","value":"The Foo Gallery plugin for WordPress allows SQL injection"}],"metrics":{}}}]}`
	f.Feeds["https://api.github.com/advisories*"] = `[{"ghsa_id":"GHSA-aaaa-bbbb-cccc","cve_id":"CVE-2026-77777","html_url":"https://github.com/advisories/GHSA-aaaa-bbbb-cccc","summary":"RCE in langchain-core","severity":"critical","published_at":"2026-10-27T10:00:00Z","vulnerabilities":[{"package":{"ecosystem":"pip","name":"langchain-core"},"first_patched_version":"0.3.80"}]}]`

	set := Settings{Off: []string{"topic:hot", "lwn"}, Feeds: []CustomFeed{{Name: "Mine", URL: "https://example.org/feed.xml", Topic: "ai"}}, Watch: []string{"https://github.com/caddyserver/caddy"}}.Clean()
	if len(set.Watch) != 1 || set.Watch[0] != "caddyserver/caddy" {
		t.Fatalf("watch %v", set.Watch)
	}
	feed := Build(context.Background(), f, nil, Options{Now: now, Settings: set})
	var tcp, chrome *Item
	by := map[string]Item{}
	for i, it := range feed.Items {
		by[it.Source] = it
		for _, c := range it.CVEs {
			if c == "CVE-2026-98432" {
				tcp = &feed.Items[i]
			}
		}
		if strings.Contains(it.Title.En, "Chrome") {
			if chrome != nil {
				t.Fatal("the Chrome story twice")
			}
			chrome = &feed.Items[i]
		}
		if strings.Contains(it.Title.En, "Old story") || strings.Contains(it.Title.En, "WordPress") {
			t.Fatalf("kept %q", it.Title.En)
		}
	}
	// one story, three sources: the NVD record leads, the news sites are «also»
	if tcp == nil || tcp.Source != "NVD (critical)" || len(tcp.Also) != 2 || tcp.Severity != "critical" || !has(tcp.Topics, "linux") || len(tcp.Alias) != 2 {
		t.Fatalf("tcp %+v", tcp)
	}
	if chrome == nil || !chrome.ZeroDay || len(chrome.Also) != 1 || !has(chrome.Topics, "zeroday") {
		t.Fatalf("chrome %+v", chrome)
	}
	if g := by["GitHub Advisory Database (critical)"]; g.Fix != "langchain-core 0.3.80" || !has(g.Topics, "ai") || g.Product != "pip/langchain-core" {
		t.Fatalf("ghsa %+v", g)
	}
	if r := by["caddyserver/caddy"]; r.Severity != "release" || !has(r.Topics, "tools") {
		t.Fatalf("watched %+v", r)
	}
	if c := by["Mine"]; !has(c.Topics, "ai") {
		t.Fatalf("custom %+v", c)
	}
	if _, ok := feed.Sources["hackernews"]; ok {
		t.Fatal("a topic that is off was read")
	}
	if _, ok := feed.Sources["lwn"]; ok {
		t.Fatal("a source that is off was read")
	}
	if !IsRead(*tcp, map[string]bool{tcp.Alias[0]: true}) {
		t.Fatal("a merged item's read mark")
	}
	if tcp.Score <= by["OpenAI News"].Score {
		t.Fatal("a 9.8 kernel CVE told by three should outrank a product launch")
	}
}

func TestStore(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	at := time.Now().UTC().Add(-time.Hour)
	if err := s.Save(Feed{Items: []Item{{ID: "a", At: at}}}); err != nil {
		t.Fatal(err)
	}
	if !s.FirstSeen()["a"].Equal(at) || len(s.Feed().Items) != 1 {
		t.Fatal("not saved")
	}
	_ = s.MarkRead([]string{"a"}, false)
	if !s.Read()["a"] {
		t.Fatal("not read")
	}
	_ = s.MarkRead([]string{"a"}, true)
	if s.Read()["a"] {
		t.Fatal("still read")
	}
}
