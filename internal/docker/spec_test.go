package docker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComposeSpec(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, ".env.api"), []byte("A=1"), 0o644)
	_ = os.MkdirAll(filepath.Join(dir, "api"), 0o755)
	src := `version: "3.8"
services:
  api:
    build: ./api
    enviroment:
      A: 1
    env_file:
      - .env.api
      - .env.missing
      - path: .env.optional
        required: false
    depends_on:
      db:
        condition: service_healthy
      cache:
        condition: service_started
    networks: [backend, ghost]
    volumes:
      - data:/data
      - undeclared:/x
      - ./local:/y
    links: [db]
  db:
    image: postgres:17
    ports: ["127.0.0.1:5432:5432"]
  web:
    image: nginx:1.27
    build: ./web
    depends_on: [nobody]
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "true"]
    mem_limit: 256m
networks:
  backend:
volumes:
  data:
`
	got := map[string]int{}
	for _, is := range checkComposeAt("docker-compose.yml", src, dir) {
		got[is.Rule]++
		if is.Title.Az == "" || is.Title.En == "" || is.Detail.Az == "" || is.Detail.En == "" {
			t.Errorf("%s: not bilingual", is.Rule)
		}
		if is.Rule == "compose-unknown-key" && is.Fix != "environment:" {
			t.Errorf("typo fix %q", is.Fix)
		}
	}
	want := map[string]int{
		"compose-version-obsolete":            1,
		"compose-unknown-key":                 1, // enviroment
		"compose-missing-env-file":            1, // .env.missing (optional one skipped)
		"compose-healthy-without-healthcheck": 1, // db has none
		"compose-unknown-dependency":          2, // cache, nobody
		"compose-undefined-network":           1, // ghost
		"compose-undefined-volume":            1, // undeclared
		"compose-links":                       1,
		"compose-missing-build-context":       1, // ./web
		"compose-no-healthcheck":              1, // db (one aggregated issue)
		"compose-no-restart":                  1, // db
		"compose-no-memory-limit":             1, // api, db
	}
	for r, n := range want {
		if got[r] != n {
			t.Errorf("%s: got %d want %d", r, got[r], n)
		}
	}
	for r, n := range got {
		if _, ok := want[r]; !ok {
			t.Errorf("unexpected %s ×%d", r, n)
		}
	}
}

func TestComposeSpecClean(t *testing.T) {
	src := `services:
  app:
    image: postgres:17
    restart: unless-stopped
    mem_limit: 512m
    healthcheck:
      test: ["CMD", "pg_isready"]
    x-note: fine
x-common: &c
  a: 1
`
	if is := checkComposeAt("compose.yml", src, t.TempDir()); len(is) != 0 {
		t.Fatalf("clean file reported: %+v", is)
	}
}

func TestEditDistance(t *testing.T) {
	if closest("enviroment", serviceKeys) != "environment" || closest("prots", serviceKeys) != "ports" || closest("zzzzzzzz", serviceKeys) != "" {
		t.Fatal("closest")
	}
}

func TestImageRefs(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "apps", "web")
	_ = os.MkdirAll(app, 0o755)
	_ = os.WriteFile(filepath.Join(app, "Dockerfile"), []byte("FROM node:22-bookworm AS build\nRUN true\nFROM build AS test\nFROM gcr.io/distroless/nodejs22\nFROM scratch\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "docker-compose.yml"), []byte("services:\n  db:\n    image: postgres:15.2\n  web:\n    build: ./apps/web\n    image: acme/web:dev\n  x:\n    image: ${IMG}\n"), 0o644)
	got := map[string]string{}
	for _, r := range ImageRefs(app, root) {
		got[r.Ref] = r.File + ":" + r.Service
	}
	want := map[string]string{"node:22-bookworm": "Dockerfile:", "gcr.io/distroless/nodejs22": "Dockerfile:", "postgres:15.2": "../../docker-compose.yml:db"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q want %q", k, got[k], v)
		}
	}
}
