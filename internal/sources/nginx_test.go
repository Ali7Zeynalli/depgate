package sources

import "testing"

// NginxPage is a trimmed copy of the structure of nginx.org/en/security_advisories.html.
const NginxPage = `<html><body><div id="content"><h2>nginx security advisories</h2>
<p>All nginx security issues should be reported to ...</p>
<ul>
<li><p>Buffer overflow when using map and regex<br>Severity: <b>major</b><br><a href="https://my.f5.com/manage/s/article/K000162097">Advisory</a><br><a href="https://www.cve.org/CVERecord?id=CVE-2026-42533">CVE-2026-42533</a><br>Not vulnerable: 1.31.3+, 1.30.4+<br>Vulnerable: 0.9.6-1.31.2<br>The patch &nbsp;<a href="/download/patch.2026.map.txt">pgp</a></p></li>
<li><p>Memory disclosure when using ngx_http_slice_module<br>Severity: medium<br><a href="https://my.f5.com/manage/s/article/K000162100">Advisory</a><br><a href="https://www.cve.org/CVERecord?id=CVE-2026-60005">CVE-2026-60005</a><br>Not vulnerable: 1.31.3+, 1.30.4+<br>Vulnerable: 1.15.8-1.31.2</p></li>
<li><p>Request smuggling in HTTP/3<br>Severity: low<br><a href="https://example.test/adv3">Advisory</a><br><a href="https://www.cve.org/CVERecord?id=CVE-2024-0001">CVE-2024-0001</a><br>Not vulnerable: 1.25.4+<br>Vulnerable: 1.25.0-1.25.3</p></li>
</ul></div></body></html>`

func TestParseNginxAdvisories(t *testing.T) {
	as := ParseNginxAdvisories(NginxPage)
	if len(as) != 3 {
		t.Fatalf("got %d advisories: %+v", len(as), as)
	}
	a := as[0]
	if a.Title != "Buffer overflow when using map and regex" || a.Severity != "major" || len(a.CVEs) != 1 || a.CVEs[0] != "CVE-2026-42533" ||
		a.Link != "https://my.f5.com/manage/s/article/K000162097" || len(a.Safe) != 2 || len(a.Vuln) != 1 || a.Vuln[0] != [2]string{"0.9.6", "1.31.2"} {
		t.Fatalf("bad first advisory: %+v", a)
	}
	if as[2].Link != "https://example.test/adv3" {
		t.Fatalf("links out of order: %+v", as[2])
	}
	cases := map[string]bool{"1.25.3": true, "1.30.3": true, "1.30.4": false, "1.30.9": false, "1.31.2": true, "1.31.3": false, "1.32.0": false, "0.9.5": false, "1.29.8": true}
	for v, want := range cases {
		if got := a.Affects(v); got != want {
			t.Errorf("Affects(%s) = %v, want %v", v, got, want)
		}
	}
	if f := NginxFix(as, "1.25.3"); f != "1.30.4" {
		t.Errorf("fix for 1.25.3 = %q, want 1.30.4", f)
	}
	if f := NginxFix(as, "1.31.0"); f != "1.31.3" {
		t.Errorf("fix for 1.31.0 = %q, want 1.31.3", f)
	}
}
