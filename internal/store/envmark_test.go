package store

import (
	"path/filepath"
	"testing"

	"github.com/Ali7Zeynalli/depgate/internal/report"
)

func TestEnvMarks(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	api := filepath.Join(root, "apps", "api")
	p := &report.Project{Dir: api, DockerFiles: []string{"../../docker-compose.yml"}, Docker: []report.DockerIssue{{File: "../../docker-compose.yml", Rule: "x", Env: "prod"}}}
	if err := s.SaveReport(p); err != nil {
		t.Fatal(err)
	}
	// marked once by its absolute path; seen from the project as ../../docker-compose.yml
	if err := s.SetEnvMark(filepath.Join(root, "docker-compose.yml"), "dev"); err != nil {
		t.Fatal(err)
	}
	r := s.Report(api)
	if r.Docker[0].Env != "dev" || r.Docker[0].EnvWhy == nil || r.EnvMarks["../../docker-compose.yml"] != "dev" {
		t.Fatalf("%+v %+v", r.Docker, r.EnvMarks)
	}
	_ = s.SetEnvMark(filepath.Join(root, "docker-compose.yml"), "")
	if r := s.Report(api); r.Docker[0].Env != "prod" || len(r.EnvMarks) != 0 {
		t.Fatalf("after unmark %+v", r.Docker)
	}
}
