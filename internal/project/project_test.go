package project

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFindSkipsNodeModulesAndEmptyRoots(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "package.json"), `{"name":"mono","private":true}`)
	write(t, filepath.Join(d, "apps/web/package.json"), `{"dependencies":{"next":"^15"}}`)
	write(t, filepath.Join(d, "apps/api/package.json"), `{"dependencies":{"@nestjs/core":"^10"}}`)
	write(t, filepath.Join(d, "apps/web/node_modules/next/package.json"), `{"dependencies":{"x":"1"}}`)
	got, err := Find(d, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || filepath.Base(got[0]) != "api" || filepath.Base(got[1]) != "web" {
		t.Fatalf("got %v", got)
	}
}

func TestNodeSources(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "Dockerfile"), "FROM --platform=linux/amd64 node:22.20.0-bookworm-slim AS build\nRUN x\nFROM docker.io/library/node:22-alpine\n")
	write(t, filepath.Join(d, ".nvmrc"), "v22.20.0\n")
	write(t, filepath.Join(d, ".github/workflows/ci.yml"), "steps:\n  - uses: actions/setup-node@v4\n    with:\n      node-version: '20'\n  - with:\n      node-version: ${{ matrix.node }}\n")
	srcs := NodeSources(d, "", map[string]string{"node": ">=20"})
	want := []string{"node:22.20.0-bookworm-slim", "node:22-alpine", "v22.20.0", ">=20", "20"}
	if len(srcs) != len(want) {
		t.Fatalf("got %+v", srcs)
	}
	for i, w := range want {
		if srcs[i].Value != w {
			t.Fatalf("source %d: got %q want %q (%+v)", i, srcs[i].Value, w, srcs)
		}
	}
}

func TestNormRemoteAndID(t *testing.T) {
	cases := map[string]string{
		"git@github.com:Ali7Zeynalli/it-crm.git":           "github.com/Ali7Zeynalli/it-crm",
		"https://github.com/Ali7Zeynalli/it-crm.git":       "github.com/Ali7Zeynalli/it-crm",
		"https://user:pass@gitlab.com/group/sub/repo.git/": "gitlab.com/group/sub/repo",
		"ssh://git@github.com/a/b":                         "github.com/a/b",
	}
	for in, want := range cases {
		if got := normRemote(in); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
	if ID("/a", "github.com/x/y", "apps/web") != ID("/other/place", "github.com/x/y", "apps/web") {
		t.Fatal("ID must not depend on local path when the remote is known")
	}
}

func TestHygiene(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	d := t.TempDir()
	write(t, filepath.Join(d, ".gitignore"), "node_modules\n/package-lock.json\n")
	hs := Hygiene(d, "", "npm", "npm", false, 3)
	byID := map[string]bool{}
	for _, h := range hs {
		byID[h.ID] = h.OK
	}
	if byID["lockfile"] || byID["install-scripts"] || byID["cooldown"] || !byID["node-pin"] {
		t.Fatalf("got %+v", hs)
	}
	write(t, filepath.Join(d, ".npmrc"), "ignore-scripts=true\nmin-release-age=3\n")
	write(t, filepath.Join(d, ".gitignore"), "node_modules\n")
	for _, h := range Hygiene(d, "", "npm", "npm", true, 3) {
		if h.OK != (h.ID != "node-pin") {
			t.Fatalf("after fix: %+v", h)
		}
	}
	write(t, filepath.Join(d, "pnpm-workspace.yaml"), "packages: []\nminimumReleaseAge: 4320\nonlyBuiltDependencies:\n  - esbuild\n")
	for _, h := range Hygiene(d, "", "pnpm", "pnpm", false, 3) {
		if !h.OK {
			t.Fatalf("pnpm: %+v", h)
		}
	}
}
