package sources

import (
	"strings"
	"testing"
)

func TestGitHubRepo(t *testing.T) {
	for in, want := range map[string]string{
		"git+https://github.com/vercel/next.js.git":     "vercel/next.js",
		"https://github.com/facebook/react/tree/main/x": "facebook/react",
		"git@github.com:colinhacks/zod.git":             "colinhacks/zod",
		"github:expressjs/express":                      "expressjs/express",
		"prisma/prisma":                                 "prisma/prisma",
		"https://gitlab.com/a/b":                        "",
		"":                                              "",
	} {
		if got := GitHubRepo(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestReleaseVersion(t *testing.T) {
	cases := []struct {
		tag, pkg, want string
		ok             bool
	}{
		{"v16.0.0", "next", "16.0.0", true},
		{"5.1.0", "express", "5.1.0", true},
		{"@tanstack/react-query@5.0.0", "@tanstack/react-query", "5.0.0", true},
		{"@tanstack/vue-query@5.0.0", "@tanstack/react-query", "", false},
		{"zod@4.0.0", "zod", "4.0.0", true},
		{"react-query@5.0.0", "@tanstack/react-query", "5.0.0", true},
	}
	for _, c := range cases {
		got, ok := ReleaseVersion(c.tag, c.pkg)
		if got != c.want || ok != c.ok {
			t.Errorf("%s/%s: got %q %v", c.tag, c.pkg, got, ok)
		}
	}
}

func TestBreakingPart(t *testing.T) {
	body := "## Features\n- shiny\n\n## ⚠ Breaking Changes\n- removed `foo`\n### Details\nmore\n## Fixes\n- bug\n- BREAKING: renamed bar\n"
	got := BreakingPart(body, 2000)
	for _, want := range []string{"Breaking Changes", "removed `foo`", "### Details", "BREAKING: renamed bar"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if strings.Contains(got, "shiny") || strings.Contains(got, "- bug") {
		t.Errorf("non-breaking content kept: %q", got)
	}
	if BreakingPart("## Features\n- only features", 100) != "" {
		t.Error("release without breaking changes must be empty")
	}
	changesets := "## 2.0.0\n\n### Major Changes\n\n- dropped Node 18\n\n### Patch Changes\n\n- tiny fix"
	if g := BreakingPart(changesets, 500); !strings.Contains(g, "dropped Node 18") || strings.Contains(g, "tiny fix") {
		t.Errorf("changesets: %q", g)
	}
	long := "## Breaking\n" + strings.Repeat("- line\n", 500)
	if g := BreakingPart(long, 300); len(g) > 310 || !strings.HasSuffix(g, "…") {
		t.Errorf("not capped: %d", len(g))
	}
}
