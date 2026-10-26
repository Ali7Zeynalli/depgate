package store

import (
	"testing"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/report"
)

func TestAcceptRisk(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := &report.Project{Dir: "/w/app", Findings: []report.Finding{
		{Key: "vuln:express@4.19.2", Kind: "vuln", Pkg: "express", Current: "4.19.2", Group: report.GroupNowCode, Severity: "high"},
		{Key: "malware:debug@4.3.4", Kind: "malware", Pkg: "debug", Current: "4.3.4", Group: report.GroupNowEasy},
	}}
	p.Summary = report.Summarize(p.Findings)
	if err := s.SaveReport(p); err != nil {
		t.Fatal(err)
	}
	if s.Accept([]string{"/w/app"}, "vuln:express@4.19.2", " ", time.Now().Add(time.Hour)) != ErrNoReason {
		t.Fatal("reason required")
	}
	if s.Accept([]string{"/w/app"}, "malware:debug@4.3.4", "x", time.Now().Add(time.Hour)) != ErrMalware {
		t.Fatal("malware must not be accepted")
	}
	if err := s.Accept([]string{"/w/app"}, "vuln:express@4.19.2", "planned for April", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	r := s.Report("/w/app")
	f := r.Findings[0]
	if f.Group != report.GroupAccepted || f.Accepted == nil || f.Accepted.Group != report.GroupNowCode || f.Accepted.Reason != "planned for April" {
		t.Fatalf("not accepted: %+v", f)
	}
	if r.Summary.NowCode != 0 || r.Summary.High != 0 || r.Summary.Accepted != 1 || r.Summary.Malware != 1 {
		t.Fatalf("summary %+v", r.Summary)
	}
	// saving the (already applied) report again and re-reading stays the same
	_ = s.SaveReport(r)
	if r2 := s.Report("/w/app"); r2.Findings[0].Group != report.GroupAccepted || r2.Summary.Accepted != 1 {
		t.Fatal("not idempotent")
	}
	if err := s.Unaccept([]string{"/w/app"}, "vuln:express@4.19.2"); err != nil {
		t.Fatal(err)
	}
	if r3 := s.Report("/w/app"); r3.Findings[0].Group != report.GroupNowCode || r3.Findings[0].Accepted != nil || r3.Summary.NowCode != 1 {
		t.Fatalf("undo: %+v", r3.Findings[0])
	}
	// an acceptance that ended no longer applies
	_ = s.Accept([]string{"/w/app"}, "vuln:express@4.19.2", "old", time.Now().Add(-time.Minute))
	if s.Report("/w/app").Findings[0].Group != report.GroupNowCode {
		t.Fatal("expired acceptance applied")
	}
	if len(s.Acceptances("/w")) != 1 || len(s.Acceptances("/other")) != 0 {
		t.Fatal("acceptances by folder")
	}
}
