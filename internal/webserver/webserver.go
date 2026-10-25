// Package webserver checks the nginx and Caddy configurations of a project
// (security rules on the config files) and the nginx / Caddy versions of the
// images it runs (known vulnerabilities, newer releases). Like the rest of
// DepGate it only reads: nothing is changed.
package webserver

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Ali7Zeynalli/depgate/internal/docker"
	"github.com/Ali7Zeynalli/depgate/internal/report"
)

const (
	maxFile  = 512 << 10
	maxFiles = 60
	maxDepth = 4
)

var skipDir = map[string]bool{"node_modules": true, ".git": true, "dist": true, "build": true, ".next": true, ".nuxt": true, ".output": true,
	"coverage": true, "vendor": true, ".turbo": true, "out": true, ".cache": true, "tmp": true, ".svelte-kit": true, ".vercel": true, ".idea": true, ".vscode": true}

// kind returns "nginx", "caddy" or "" for a file found at rel.
func kind(rel string) string {
	base := strings.ToLower(filepath.Base(rel))
	if base == "caddyfile" || strings.HasPrefix(base, "caddyfile.") || strings.HasSuffix(base, ".caddyfile") || strings.HasSuffix(base, ".caddy") {
		return "caddy"
	}
	if base == "nginx.conf" || strings.HasSuffix(base, ".nginx") || strings.HasSuffix(base, ".nginx.conf") {
		return "nginx"
	}
	if strings.HasSuffix(base, ".conf") || strings.HasSuffix(base, ".conf.template") {
		low := strings.ToLower(filepath.ToSlash(rel))
		for _, d := range []string{"nginx", "conf.d", "sites-available", "sites-enabled", "default.d", "snippets"} {
			if strings.Contains(low, d+"/") || strings.Contains(low, "/"+d) {
				return "nginx"
			}
		}
	}
	return ""
}

type found struct{ path, rel, kind string }

// discover finds nginx and Caddy configs in dir and the repository root (a few
// levels deep, skipping build output and folders of other packages).
func discover(dir, repoRoot string) []found {
	roots := []string{dir}
	if repoRoot != "" {
		a, errA := filepath.Abs(dir)
		b, errB := filepath.Abs(repoRoot)
		if errA == nil && errB == nil && a != b {
			roots = append(roots, repoRoot)
		}
	}
	absDir, _ := filepath.Abs(dir)
	var out []found
	seen := map[string]bool{}
	for _, root := range roots {
		var rec func(d string, depth int)
		rec = func(d string, depth int) {
			if len(out) >= maxFiles {
				return
			}
			ents, err := os.ReadDir(d)
			if err != nil {
				return
			}
			for _, e := range ents {
				p := filepath.Join(d, e.Name())
				if e.IsDir() {
					if depth >= maxDepth || skipDir[e.Name()] {
						continue
					}
					if a, _ := filepath.Abs(p); a == absDir {
						continue // the project itself is its own root
					}
					if _, err := os.Stat(filepath.Join(p, "package.json")); err == nil {
						continue // another package of the repository
					}
					rec(p, depth+1)
					continue
				}
				if !e.Type().IsRegular() {
					continue
				}
				rel, err := filepath.Rel(dir, p)
				if err != nil {
					rel = p
				}
				rel = filepath.ToSlash(rel)
				k := kind(rel)
				if k == "" {
					continue
				}
				abs, _ := filepath.Abs(p)
				if seen[abs] {
					continue
				}
				seen[abs] = true
				out = append(out, found{p, rel, k})
			}
		}
		rec(root, 0)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out
}

// Scan checks every nginx and Caddy config of the project.
func Scan(dir, repoRoot string) (issues []report.DockerIssue, files []string) {
	var ngx []ngxFile
	for _, f := range discover(dir, repoRoot) {
		st, err := os.Stat(f.path)
		if err != nil || st.Size() > maxFile {
			continue
		}
		b, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		files = append(files, f.rel)
		if f.kind == "caddy" {
			issues = append(issues, checkCaddy(f.rel, parseCaddy(string(b)))...)
		} else {
			ngx = append(ngx, ngxFile{rel: f.rel, tree: parseNginx(string(b))})
		}
	}
	if len(ngx) > 0 {
		issues = append(issues, checkNginx(ngx)...)
	}
	docker.SortIssues(issues)
	return issues, files
}

func sortStrings(s []string) { sort.Strings(s) }
