package images

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/docker"
	"github.com/Ali7Zeynalli/depgate/internal/sources/sourcestest"
)

var now = time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)

func fake() *sourcestest.Fake {
	f := sourcestest.New(now)
	f.EOL["postgresql"] = []map[string]any{
		{"cycle": "17", "eol": "2029-11-08", "latest": "17.6"},
		{"cycle": "15", "eol": "2027-11-11", "latest": "15.14"},
		{"cycle": "12", "eol": "2024-11-21", "latest": "12.22"},
	}
	f.EOL["redis"] = []map[string]any{{"cycle": "8.2", "eol": false, "latest": "8.2.2"}, {"cycle": "7.2", "eol": "2026-12-01", "latest": "7.2.11"}}
	f.EOL["debian"] = []map[string]any{
		{"cycle": "12", "codename": "Bookworm", "eol": "2028-06-10"},
		{"cycle": "11", "codename": "Bullseye", "eol": "2026-08-31"},
		{"cycle": "10", "codename": "Buster", "eol": "2024-06-30"},
	}
	f.EOL["alpine-linux"] = []map[string]any{{"cycle": "3.22", "eol": "2027-05-01"}, {"cycle": "3.16", "eol": "2024-05-23"}}
	f.EOL["python"] = []map[string]any{{"cycle": "3.13", "eol": "2029-10-31", "latest": "3.13.8"}, {"cycle": "3.8", "eol": "2024-10-07", "latest": "3.8.20"}}
	return f
}

func rules(t *testing.T, refs ...string) map[string]string {
	t.Helper()
	var rs []docker.ImageRef
	for i, r := range refs {
		rs = append(rs, docker.ImageRef{File: "docker-compose.yml", Line: i + 1, Service: "s", Ref: r})
	}
	out := map[string]string{}
	for _, is := range Check(context.Background(), fake(), rs, now) {
		out[refs[is.Line-1]+" "+is.Rule] = is.Fix
		if is.Title.Az == "" || is.Title.En == "" || is.Detail.Az == "" || is.Detail.En == "" {
			t.Errorf("%s: not bilingual", is.Rule)
		}
	}
	return out
}

func TestImageChecks(t *testing.T) {
	got := rules(t,
		"postgres:12",              // EOL
		"postgres:15.2",            // old patch
		"postgres:15",              // fine (floating patch)
		"postgres:17.6-alpine",     // latest patch, fine
		"redis:7.2",                // ends within 120 days
		"node:18-buster",           // OS variant EOL (node line itself is the Node card's job)
		"python:3.13-alpine3.16",   // OS variant EOL
		"python:3.8-slim-bookworm", // python EOL
		"debian:buster",            // EOL by codename
		"bitnami/postgresql:12",    // not an official image: skipped
		"postgres@sha256:abc",      // digest: skipped
		"postgres:latest",          // unpinned: reported elsewhere
	)
	want := map[string]string{
		"postgres:12 image-eol":               "postgres:17",
		"postgres:15.2 image-outdated-patch":  "postgres:15.14",
		"redis:7.2 image-eol-soon":            "redis:8.2",
		"node:18-buster image-os-eol":         "node:18-bookworm",
		"python:3.13-alpine3.16 image-os-eol": "python:3.13-alpine",
		"python:3.8-slim-bookworm image-eol":  "python:3.13-slim-bookworm",
		"debian:buster image-eol":             "debian:12",
	}
	for k, fix := range want {
		got_, ok := got[k]
		if !ok {
			t.Errorf("missing %s (got %v)", k, got)
			continue
		}
		if got_ != fix {
			t.Errorf("%s: fix %q, want %q", k, got_, fix)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected %s", k)
		}
	}
}

func TestUnknownProductIsQuiet(t *testing.T) {
	if got := rules(t, "nginx:1.25", "caddy:2.8"); len(got) != 0 { // no data in the fake: no guesses
		t.Fatalf("%v", got)
	}
}

func TestVersionParsing(t *testing.T) {
	for tag, want := range map[string]string{"3.12.1-slim-bookworm": "3.12.1|slim,bookworm", "bookworm": "bookworm|", "lts-alpine": "|lts,alpine", "v2.11": "2.11|"} {
		v, variant := versionOf(tag)
		if got := v + "|" + strings.Join(variant, ","); got != want {
			t.Errorf("%s: %s", tag, got)
		}
	}
	if !less("15.2", "15.10") || less("15.10", "15.2") || !precise("15.2", "15") || precise("15", "15") {
		t.Fatal("version helpers")
	}
}
