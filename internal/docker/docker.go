// Package docker reviews a project's Dockerfiles and docker-compose files for
// common security mistakes. It only reads files and suggests fixes.
package docker

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Ali7Zeynalli/depgate/internal/report"
)

const maxFileSize = 1 << 20

func isDockerfile(name string) bool {
	return name == "Dockerfile" || name == "dockerfile" ||
		strings.HasPrefix(name, "Dockerfile.") && !strings.HasSuffix(name, ".dockerignore") ||
		strings.HasSuffix(name, ".Dockerfile") || strings.HasSuffix(name, ".dockerfile")
}

func isCompose(name string) bool {
	ext := filepath.Ext(name)
	if ext != ".yml" && ext != ".yaml" {
		return false
	}
	base := strings.TrimSuffix(name, ext)
	return base == "docker-compose" || base == "compose" ||
		strings.HasPrefix(base, "docker-compose.") || strings.HasPrefix(base, "compose.")
}

// Scan inspects the Dockerfiles and compose files of a project and returns issues.
// dir is the project directory; repoRoot is the git repo root ("" or == dir if none).
// It looks in dir and, when different, repoRoot (monorepos keep compose at the root).
// files lists the files it inspected (relative to dir, e.g. "Dockerfile", "../../docker-compose.yml").
func Scan(dir, repoRoot string) (issues []report.DockerIssue, files []string) {
	dirs := []string{dir}
	if repoRoot != "" {
		a, errA := filepath.Abs(dir)
		b, errB := filepath.Abs(repoRoot)
		if errA == nil && errB == nil && a != b {
			dirs = append(dirs, repoRoot)
		}
	}
	type found struct{ path, rel string }
	var dfs, composes []found
	seen := map[string]bool{}
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			name := e.Name()
			if name == "node_modules" || !e.Type().IsRegular() {
				continue
			}
			p := filepath.Join(d, name)
			abs, _ := filepath.Abs(p)
			if seen[abs] {
				continue
			}
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				rel = p
			}
			rel = filepath.ToSlash(rel)
			switch {
			case isDockerfile(name):
				seen[abs] = true
				dfs = append(dfs, found{p, rel})
			case isCompose(name):
				seen[abs] = true
				composes = append(composes, found{p, rel})
			}
		}
	}
	read := func(p string) (string, bool) {
		st, err := os.Stat(p)
		if err != nil || st.Size() > maxFileSize {
			return "", false
		}
		b, err := os.ReadFile(p)
		return string(b), err == nil
	}
	health := false
	for _, f := range composes {
		files = append(files, f.rel)
		src, ok := read(f.path)
		if !ok {
			continue
		}
		health = health || composeHasHealthcheck(src)
		issues = append(issues, checkComposeAt(f.rel, src, filepath.Dir(f.path))...)
	}
	for _, f := range dfs {
		files = append(files, f.rel)
		src, ok := read(f.path)
		if !ok {
			continue
		}
		issues = append(issues, checkDockerfile(&dfCtx{file: f.rel, path: f.path, src: src, healthElse: health})...)
	}
	sort.Strings(files)
	sortIssues(issues)
	return issues, files
}

var sevRank = map[string]int{"high": 0, "medium": 1, "low": 2}

func sortIssues(is []report.DockerIssue) {
	sort.SliceStable(is, func(i, j int) bool {
		a, b := is[i], is[j]
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] < sevRank[b.Severity]
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
}
