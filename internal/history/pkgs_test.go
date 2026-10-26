package history

import (
	"testing"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/report"
)

func TestDiffVersions(t *testing.T) {
	v := func(n, ver string, direct bool) report.Version { return report.Version{Name: n, Version: ver, Direct: direct} }
	old := []report.Version{v("next", "14.2.3", true), v("lodash", "4.17.21", true), v("follow-redirects", "1.15.6", false), v("moment", "2.29.4", true), v("ms", "2.1.2", false), v("ms", "2.1.3", false)}
	cur := []report.Version{v("next", "14.2.25", true), v("lodash", "4.17.20", true), v("follow-redirects", "1.15.9", false), v("left-pad", "1.3.0", false), v("ms", "2.1.3", false)}
	d := DiffVersions(old, cur)
	got := map[string]PkgChange{}
	for _, c := range d.Changes {
		got[c.Name+":"+c.Kind] = c
	}
	if c := got["next:up"]; c.From != "14.2.3" || c.To != "14.2.25" || !c.Direct {
		t.Fatalf("next %+v", d.Changes)
	}
	if c := got["lodash:down"]; c.From != "4.17.21" || c.To != "4.17.20" {
		t.Fatalf("lodash %+v", d.Changes)
	}
	if _, ok := got["follow-redirects:up"]; !ok {
		t.Fatalf("follow %+v", d.Changes)
	}
	if c := got["left-pad:add"]; c.To != "1.3.0" || c.Direct {
		t.Fatalf("left-pad %+v", d.Changes)
	}
	if c := got["moment:remove"]; c.From != "2.29.4" {
		t.Fatalf("moment %+v", d.Changes)
	}
	if c := got["ms:remove"]; c.From != "2.1.2" || len(d.Changes) != 6 {
		t.Fatalf("ms %+v", d.Changes)
	}
	// direct first, and among them "down" first
	if d.Changes[0].Name != "lodash" || d.Changes[len(d.Changes)-1].Direct {
		t.Fatalf("order %+v", d.Changes)
	}
	if DiffVersions(cur, cur) != nil {
		t.Fatal("no change must be nil")
	}
}

func TestAddScanStoresVersionChanges(t *testing.T) {
	l := &Log{Dir: t.TempDir()}
	p := &report.Project{Dir: "/x", ScannedAt: time.Now(), Versions: []report.Version{{Name: "a", Version: "1.0.0", Direct: true}}}
	if err := l.AddScan("/x", FromProject(p, "ui", "", "")); err != nil {
		t.Fatal(err)
	}
	p.Versions = []report.Version{{Name: "a", Version: "1.1.0", Direct: true}}
	_ = l.AddScan("/x", FromProject(p, "ui", "", ""))
	s := l.Scans("/x")
	if len(s) != 2 || s[1].Pkgs != nil || s[0].Pkgs == nil || s[0].Pkgs.Changes[0].To != "1.1.0" {
		t.Fatalf("%+v", s)
	}
	l.Forget("/x")
	_ = l.AddScan("/x", FromProject(p, "ui", "", ""))
	if s := l.Scans("/x"); len(s) != 1 || s[0].Pkgs != nil {
		t.Fatalf("after forget %+v", s)
	}
}
