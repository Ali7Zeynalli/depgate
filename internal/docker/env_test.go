package docker

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Ali7Zeynalli/depgate/internal/report"
)

func TestEnvOfFile(t *testing.T) {
	for rel, want := range map[string]string{
		"Dockerfile": "", "Dockerfile.dev": "dev", "docker-compose.dev.yml": "dev", "compose.override.yaml": "dev",
		"docker-compose.prod.yml": "prod", "deploy/production/Dockerfile": "prod", "docker/local/Dockerfile": "dev",
		"../../docker-compose.yml": "", "deploy/nginx/site.conf": "", "Dockerfile.test": "dev", "devops/Dockerfile": "",
	} {
		if got, _ := EnvOfFile(rel); got != want {
			t.Errorf("%s: %q, want %q", rel, got, want)
		}
	}
}

func TestTagEnvStageAndProfile(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM node:22 AS dev\nUSER root\nFROM node:22-slim AS production\nUSER root\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("services:\n  web:\n    image: x\n  mail:\n    image: y\n    profiles: [dev]\n"), 0o644)
	is := []report.DockerIssue{{File: "Dockerfile", Line: 2}, {File: "Dockerfile", Line: 4}, {File: "docker-compose.yml", Service: "web", Line: 2}, {File: "docker-compose.yml", Service: "mail", Line: 4}}
	TagEnv(dir, is)
	if is[0].Env != "dev" || is[1].Env != "prod" || is[2].Env != "" || is[3].Env != "dev" || is[3].EnvWhy == nil || is[2].EnvWhy != nil {
		t.Fatalf("%+v", is)
	}
}
