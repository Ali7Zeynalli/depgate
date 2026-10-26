// Package project finds Node.js projects on disk and reads their
// non-lockfile facts: Node version sources, git remote, hygiene settings.
package project

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Ali7Zeynalli/depgate/internal/report"
)

// skipDirs are never descended into while discovering projects.
var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, ".next": true, "dist": true, "build": true, "out": true,
	".turbo": true, ".cache": true, "coverage": true, "vendor": true, ".pnpm-store": true, ".yarn": true,
	".svelte-kit": true, ".nuxt": true, ".output": true, "target": true,
}

// Find returns directories under root that contain a package.json, up to depth.
// When root itself is a project, it is returned first; workspace members of a
// monorepo are returned as separate projects.
func Find(root string, depth int) ([]string, error) {
	dirs, _, err := FindAll(root, depth)
	return dirs, err
}

// FindAll is Find that also returns the package.json folders it left out
// because they declare no dependencies (a workspace root, a config package).
func FindAll(root string, depth int) (dirs, skipped []string, err error) {
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, nil, err
	}
	var out []string
	base := strings.Count(root, string(os.PathSeparator))
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root {
				return err
			}
			return nil
		}
		if d.IsDir() {
			if p != root && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			if strings.Count(p, string(os.PathSeparator))-base > depth {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "package.json" {
			dir := filepath.Dir(p)
			if isRealProject(dir) {
				out = append(out, dir)
			} else if dir != root {
				skipped = append(skipped, dir)
			}
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i] == root {
			return true
		}
		if out[j] == root {
			return false
		}
		return out[i] < out[j]
	})
	return out, skipped, err
}

// isRealProject skips package.json files that only describe a monorepo root with no deps.
func isRealProject(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return false
	}
	var m struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	return len(m.Dependencies)+len(m.DevDependencies) > 0
}

// Git returns the remote URL (normalised to host/owner/repo) and the path of dir inside the repo.
func Git(dir string) (remote, rel string) {
	d := dir
	for {
		if st, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			cfg := filepath.Join(d, ".git", "config")
			if !st.IsDir() { // worktree / submodule: ".git" file with "gitdir: ..."
				if b, err := os.ReadFile(filepath.Join(d, ".git")); err == nil {
					gd := strings.TrimSpace(strings.TrimPrefix(string(b), "gitdir:"))
					if !filepath.IsAbs(gd) {
						gd = filepath.Join(d, gd)
					}
					cfg = filepath.Join(gd, "config")
				}
			}
			remote = originURL(cfg)
			rel, _ = filepath.Rel(d, dir)
			return normRemote(remote), filepath.ToSlash(rel)
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", ""
		}
		d = parent
	}
}

func originURL(cfg string) string {
	f, err := os.Open(cfg)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	in := false
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(l, "[") {
			in = l == `[remote "origin"]`
			continue
		}
		if in && strings.HasPrefix(l, "url") {
			if _, v, ok := strings.Cut(l, "="); ok {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

var scpLike = regexp.MustCompile(`^[\w.-]+@([\w.-]+):(.+)$`)

func normRemote(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	if m := scpLike.FindStringSubmatch(u); m != nil {
		u = m[1] + "/" + m[2]
	}
	for _, p := range []string{"https://", "http://", "ssh://", "git://", "git+ssh://", "git+https://"} {
		u = strings.TrimPrefix(u, p)
	}
	if at := strings.Index(u, "@"); at >= 0 && at < strings.Index(u+"/", "/") {
		u = u[at+1:]
	}
	u = strings.TrimSuffix(strings.TrimSuffix(u, "/"), ".git")
	return u
}

// ID is stable across machines when the project is in git (remote + path), else the absolute path.
func ID(dir, remote, rel string) string {
	key := dir
	if remote != "" {
		key = remote + "#" + rel
	}
	s := sha256.Sum256([]byte(key))
	return "sha256:" + hex.EncodeToString(s[:])[:16]
}

var (
	fromNode  = regexp.MustCompile(`(?i)^\s*FROM\s+(?:--platform=\S+\s+)?(?:\S+/)?node:([^\s@]+)`)
	nvmLine   = regexp.MustCompile(`^\s*v?(\d+(?:\.\d+){0,2}|lts/\S+|node)\s*$`)
	actionsNV = regexp.MustCompile(`node-version:\s*['"]?([^'"\s#]+)`)
)

// NodeSources collects every place the project pins its Node.js version.
func NodeSources(dir, repoRoot string, engines map[string]string) []report.NodeSource {
	var out []report.NodeSource
	add := func(file, v string) {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, report.NodeSource{File: file, Value: v})
		}
	}
	dirs := []string{dir}
	if repoRoot != "" && repoRoot != dir {
		dirs = append(dirs, repoRoot)
	}
	seen := map[string]bool{}
	for _, d := range dirs {
		for _, name := range []string{"Dockerfile", "Dockerfile.prod", "Containerfile"} {
			p := filepath.Join(d, name)
			if seen[p] {
				continue
			}
			seen[p] = true
			if b, err := os.ReadFile(p); err == nil {
				for _, l := range strings.Split(string(b), "\n") {
					if m := fromNode.FindStringSubmatch(l); m != nil {
						add(rel(dir, p), "node:"+m[1])
					}
				}
			}
		}
		for _, name := range []string{".nvmrc", ".node-version"} {
			p := filepath.Join(d, name)
			if seen[p] {
				continue
			}
			seen[p] = true
			if b, err := os.ReadFile(p); err == nil {
				l := strings.SplitN(string(b), "\n", 2)[0]
				if nvmLine.MatchString(l) {
					add(rel(dir, p), strings.TrimSpace(l))
				}
			}
		}
		if p := filepath.Join(d, ".tool-versions"); !seen[p] {
			seen[p] = true
			if b, err := os.ReadFile(p); err == nil {
				for _, l := range strings.Split(string(b), "\n") {
					f := strings.Fields(l)
					if len(f) >= 2 && (f[0] == "nodejs" || f[0] == "node") {
						add(rel(dir, p), f[1])
					}
				}
			}
		}
	}
	if e := engines["node"]; e != "" {
		add("package.json engines", e)
	}
	root := repoRoot
	if root == "" {
		root = dir
	}
	wf := filepath.Join(root, ".github", "workflows")
	if ents, err := os.ReadDir(wf); err == nil {
		for _, e := range ents {
			if e.IsDir() || !(strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml")) {
				continue
			}
			if b, err := os.ReadFile(filepath.Join(wf, e.Name())); err == nil {
				for _, m := range actionsNV.FindAllStringSubmatch(string(b), -1) {
					if !strings.Contains(m[1], "${{") {
						add(rel(dir, filepath.Join(wf, e.Name())), m[1])
					}
				}
			}
		}
	}
	return out
}

func rel(base, p string) string {
	r, err := filepath.Rel(base, p)
	if err != nil {
		return p
	}
	return filepath.ToSlash(r)
}

// RepoRoot returns the nearest ancestor (or dir itself) containing .git, else "".
func RepoRoot(dir string) string {
	d := dir
	for {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			return ""
		}
		d = parent
	}
}

// ReadFirst returns the content of the first existing file among names in dirs.
func ReadFirst(dirs []string, names ...string) (string, string) {
	for _, d := range dirs {
		if d == "" {
			continue
		}
		for _, n := range names {
			if b, err := os.ReadFile(filepath.Join(d, n)); err == nil {
				return string(b), filepath.Join(d, n)
			}
		}
	}
	return "", ""
}
