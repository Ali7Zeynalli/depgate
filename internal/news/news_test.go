package news

import (
	"context"
	"encoding/json"
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
	if k := by["kev:CVE-2026-0001"]; k.Mine || !k.KEV || k.Maybe {
		t.Fatalf("kev %+v", k)
	}
	if k := by["kev:CVE-2026-0003"]; !k.Maybe {
		t.Fatalf("kev openssl should be maybe-mine %+v", k)
	}
	if _, ok := by["kev:CVE-2026-0002"]; ok {
		t.Fatal("non-infra KEV kept")
	}
	if _, ok := by["kev:CVE-2020-0004"]; ok {
		t.Fatal("old KEV kept")
	}
	if u := by["feed:usn-7100-1"]; u.Product != "OpenSSH" || len(u.CVEs) != 1 || u.Desc.En != "CVE-2026-0010 fixed" {
		t.Fatalf("usn %+v", u)
	}
	if _, ok := by["feed:usn-7101-1"]; ok {
		t.Fatal("desktop bulletin kept")
	}
	if d := by["feed:dsa-6000-1"]; d.Product != "postgresql-15" || !d.At.Equal(time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("dsa %+v", d)
	}
	if len(feed.Errors) != 0 {
		t.Fatalf("errors %v", feed.Errors)
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
