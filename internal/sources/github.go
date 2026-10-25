package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

const githubAPI = "https://api.github.com/repos/"

// ErrRateLimited is returned when GitHub refuses more unauthenticated requests.
var ErrRateLimited = errors.New("GitHub rate limit reached — set DEPGATE_GITHUB_TOKEN to raise it")

// Release is one GitHub release.
type Release struct {
	Tag        string `json:"tag_name"`
	Name       string `json:"name"`
	URL        string `json:"html_url"`
	Body       string `json:"body"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

var ghRepo = regexp.MustCompile(`github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(\.git)?(/|#|$)`)

// GitHubRepo extracts owner/repo from a package.json repository URL ("" if not GitHub).
func GitHubRepo(u string) string {
	u = strings.TrimSpace(u)
	if strings.HasPrefix(u, "github:") {
		u = "github.com/" + strings.TrimPrefix(u, "github:")
	} else if m := regexp.MustCompile(`^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$`).FindStringSubmatch(u); m != nil {
		return m[1] + "/" + m[2] // npm shorthand "owner/repo"
	}
	if m := ghRepo.FindStringSubmatch(u); m != nil {
		return m[1] + "/" + strings.TrimSuffix(m[2], ".git")
	}
	return ""
}

// Releases loads the latest 100 releases of owner/repo (cached for a day).
// DEPGATE_GITHUB_TOKEN (or GITHUB_TOKEN) is sent when set.
func Releases(ctx context.Context, f Fetcher, repo string) ([]Release, error) {
	h := map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
	if t := firstEnv("DEPGATE_GITHUB_TOKEN", "GITHUB_TOKEN"); t != "" {
		h["Authorization"] = "Bearer " + t
	}
	b, err := f.Do(ctx, "GET", githubAPI+repo+"/releases?per_page=100", nil, h, 24*time.Hour)
	if err != nil {
		if e := err.Error(); strings.HasSuffix(e, "HTTP 403") || strings.HasSuffix(e, "HTTP 429") {
			return nil, ErrRateLimited
		}
		return nil, fmt.Errorf("GitHub %s: %w", repo, err)
	}
	var out []Release
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("GitHub %s: %w", repo, err)
	}
	return out, nil
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

var mdHeading = regexp.MustCompile(`^(#{1,6})\s+(.*)$`)
var breakingTitle = regexp.MustCompile(`(?i)breaking|major changes|⚠|migration|removed|backwards[- ]incompatible`)

// BreakingPart returns the breaking-change sections of a release body (markdown),
// or "" when the release has none. Lines marked BREAKING outside such a
// section are kept too. The result is capped at max bytes.
func BreakingPart(body string, max int) string {
	var out []string
	level := 0 // >0 while inside a breaking section of this heading level
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		if m := mdHeading.FindStringSubmatch(line); m != nil {
			l := len(m[1])
			if level > 0 && l <= level {
				level = 0
			}
			if level == 0 && breakingTitle.MatchString(m[2]) {
				level = l
				out = append(out, line)
			} else if level > 0 {
				out = append(out, line)
			}
			continue
		}
		if level > 0 {
			out = append(out, line)
		} else if strings.Contains(line, "BREAKING") || strings.Contains(strings.ToLower(line), "**breaking") {
			out = append(out, line)
		}
	}
	s := strings.TrimSpace(strings.Join(out, "\n"))
	for strings.Contains(s, "\n\n\n") {
		s = strings.ReplaceAll(s, "\n\n\n", "\n\n")
	}
	if len(s) > max {
		cut := strings.LastIndex(s[:max], "\n")
		if cut < max/2 {
			cut = max
		}
		s = s[:cut] + "\n…"
	}
	return s
}

// ReleaseVersion returns the version a tag stands for and whether the tag belongs
// to pkg ("v1.2.3", "1.2.3", "pkg@1.2.3", "@scope/pkg@1.2.3"; other packages of
// a monorepo are rejected).
func ReleaseVersion(tag, pkg string) (string, bool) {
	if i := strings.LastIndex(tag, "@"); i > 0 {
		if tag[:i] != pkg && !strings.HasSuffix(pkg, "/"+tag[:i]) {
			return "", false
		}
		tag = tag[i+1:]
	}
	tag = strings.TrimPrefix(strings.TrimPrefix(tag, "release-"), "v")
	return tag, tag != ""
}
