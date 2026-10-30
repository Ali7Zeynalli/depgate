package docker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDescribe(t *testing.T) {
	for ref, want := range map[string][5]string{ // product, version, os, osVersion, guess
		"node:22.20.0-bookworm-slim": {"node", "22.20.0", "debian", "12", ""},
		"postgres:16.4":              {"postgres", "16.4", "debian", "", "guess"},
		"nginx:1.25.3-alpine3.19":    {"nginx", "1.25.3", "alpine", "3.19", ""},
		"redis:7.2-alpine":           {"redis", "7.2", "alpine", "", ""},
		"ubuntu:24.04":               {"", "", "ubuntu", "24.04", ""},
		"debian:bookworm-slim":       {"", "", "debian", "12", ""},
		"alpine:3.20.3":              {"", "", "alpine", "3.20", ""},
		"ghcr.io/acme/app:1.2":       {"", "1.2", "", "", ""},
		"python:3.12-slim-noble":     {"python", "3.12", "ubuntu", "24.04", ""},
	} {
		it := describe(ref)
		g := ""
		if it.OSGuess {
			g = "guess"
		}
		got := [5]string{it.Product, it.Version, it.OS, it.OSVersion, g}
		if got != want {
			t.Errorf("%s: %v, want %v", ref, got, want)
		}
	}
	if it := describe("redis:latest"); !it.Unpinned || it.Version != "" {
		t.Errorf("latest: %+v", it)
	}
}

func TestStack(t *testing.T) {
	dir := t.TempDir()
	w := func(name, s string) { _ = os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644) }
	w("package.json", `{}`)
	w("Dockerfile", "FROM node:22-bookworm-slim AS build\nRUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl openssl=3.0.* \\\n  ca-certificates && rm -rf /var/lib/apt/lists/*\nFROM build AS app\nRUN apk add --no-cache tini || true\nFROM nginx:1.25.3-alpine\nRUN apk add --no-cache curl\n")
	w("docker-compose.yml", "services:\n  db:\n    image: postgres:16.4\n  app:\n    build: .\n  cache:\n    image: redis:latest\n")
	st := Stack(dir, "")
	by := map[string][]string{}
	for _, it := range st {
		by[it.Image] = it.Packages
	}
	if len(st) != 4 {
		t.Fatalf("%+v", st)
	}
	if p := by["node:22-bookworm-slim"]; len(p) != 4 || p[0] != "ca-certificates" || p[3] != "tini" {
		t.Fatalf("node packages %v", p)
	}
	if p := by["nginx:1.25.3-alpine"]; len(p) != 1 || p[0] != "curl" {
		t.Fatalf("nginx packages %v", p)
	}
	if _, ok := by["postgres:16.4"]; !ok {
		t.Fatal("compose image missing")
	}
}
