package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/report"
)

func TestAcceptFile(t *testing.T) {
	repo := t.TempDir()
	app := filepath.Join(repo, "apps", "api")
	_ = os.MkdirAll(app, 0o755)
	_ = os.MkdirAll(filepath.Join(repo, ".git"), 0o755)
	future := time.Now().AddDate(0, 1, 0).Format("2006-01-02")
	write := func(dir, s string) {
		if err := os.WriteFile(filepath.Join(dir, AcceptFileName), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(repo, `{"schema":"depgate/accept@1","accepted":[
	 {"key":"vuln:express@4.19.2","reason":"planned for April","until":"`+future+`"},
	 {"key":"vuln:axios@1.0.0","reason":"","until":"`+future+`"},
	 {"key":"malware:debug@4.3.4","reason":"x","until":"`+future+`"},
	 {"key":"vuln:old@1.0.0","reason":"x","until":"2020-01-01"},
	 {"key":"vuln:bad@1.0.0","reason":"x","until":"soon"}]}`)
	// a file above the repository root is not read
	write(filepath.Dir(repo), `{"accepted":[{"key":"vuln:outside@1.0.0","reason":"x","until":"`+future+`"}]}`)
	defer os.Remove(filepath.Join(filepath.Dir(repo), AcceptFileName))

	as := FileAcceptances(app)
	if len(as) != 2 || as[0].Key != "vuln:express@4.19.2" || as[0].Dir != app || as[0].File != filepath.Join(repo, AcceptFileName) {
		t.Fatalf("file acceptances %+v", as)
	}
	p := &report.Project{Dir: app, Findings: []report.Finding{
		{Key: "vuln:express@4.19.2", Kind: "vuln", Pkg: "express", Current: "4.19.2", Group: report.GroupNowCode, Severity: "high"},
		{Key: "vuln:old@1.0.0", Kind: "vuln", Pkg: "old", Current: "1.0.0", Group: report.GroupNowEasy, Severity: "high"},
	}}
	ApplyAcceptances(p, as)
	if p.Findings[0].Group != report.GroupAccepted || p.Findings[0].Accepted.File == "" || p.Findings[1].Group != report.GroupNowEasy || p.Summary.Accepted != 1 || p.Summary.High != 1 {
		t.Fatalf("apply %+v %+v", p.Findings, p.Summary)
	}
	// the store reads the file too, so the UI shows the same
	s, _ := Open(t.TempDir())
	_ = s.SaveReport(&report.Project{Dir: app, Findings: []report.Finding{{Key: "vuln:express@4.19.2", Kind: "vuln", Group: report.GroupNowCode}}})
	if s.Report(app).Findings[0].Group != report.GroupAccepted {
		t.Fatal("UI does not see the team file")
	}
	if len(LocalAcceptances(t.TempDir())) != 0 {
		t.Fatal("no local file")
	}
}
