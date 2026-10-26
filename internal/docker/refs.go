package docker

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Ali7Zeynalli/depgate/internal/report"
)

// ImageRef is one base or service image a project uses.
type ImageRef struct {
	File    string // relative to the project dir
	Line    int
	Service string // compose service ("" for a Dockerfile)
	Ref     string // e.g. node:22.20.0-bookworm-slim
}

// ImageRefs lists the images of the project's Dockerfiles (every FROM that is
// not an earlier stage or scratch) and compose files (services without build).
func ImageRefs(dir, repoRoot string) []ImageRef {
	var out []ImageRef
	for _, f := range discover(dir, repoRoot) {
		b, err := os.ReadFile(f.path)
		if err != nil || len(b) > maxFileSize {
			continue
		}
		if f.compose {
			root, err := parseYAML(string(b))
			if err != nil || root == nil {
				continue
			}
			svcs := root.get("services")
			if svcs == nil || svcs.Kind != yMap {
				continue
			}
			for _, e := range svcs.Keys {
				img := e.Val.get("image")
				if img == nil || img.Kind != yScalar || e.Val.get("build") != nil || strings.Contains(img.Value, "$") {
					continue
				}
				out = append(out, ImageRef{File: f.rel, Line: img.Line, Service: e.Name, Ref: img.Value})
			}
			continue
		}
		names := map[string]bool{}
		for _, st := range stages(parseDockerfile(string(b))) {
			ref := st.Image
			low := strings.ToLower(ref)
			if !names[low] && low != "scratch" && ref != "" && !strings.Contains(ref, "$") {
				out = append(out, ImageRef{File: f.rel, Line: st.Line, Ref: ref})
			}
			if st.Name != "" {
				names[st.Name] = true
			}
		}
	}
	return out
}

type foundFile struct {
	path, rel string
	compose   bool
}

// discover finds the Dockerfiles and compose files of a project: in its folder
// and the repository root, their sub-folders (docker/, deploy/, infra/ …, but
// not other projects), and the files a compose file builds from or includes.
func discover(dir, repoRoot string) []foundFile {
	absDir, _ := filepath.Abs(dir)
	roots := []string{absDir}
	if repoRoot != "" {
		if b, err := filepath.Abs(repoRoot); err == nil && b != absDir {
			roots = append(roots, b)
		}
	}
	var out []foundFile
	seen := map[string]bool{}
	add := func(p string, compose bool) {
		abs, err := filepath.Abs(p)
		if err != nil || seen[abs] {
			return
		}
		if st, err := os.Stat(abs); err != nil || !st.Mode().IsRegular() {
			return
		}
		seen[abs] = true
		rel, err := filepath.Rel(absDir, abs)
		if err != nil {
			rel = abs
		}
		out = append(out, foundFile{abs, filepath.ToSlash(rel), compose})
	}
	// the project folder and the repository root, with their sub-folders
	// (docker/, deploy/, infra/ …), but not other projects: their files are theirs
	for _, root := range roots {
		var walk func(d string, depth int)
		walk = func(d string, depth int) {
			ents, err := os.ReadDir(d)
			if err != nil {
				return
			}
			for _, e := range ents {
				name, p := e.Name(), filepath.Join(d, e.Name())
				if e.IsDir() {
					if depth >= walkDepth || walkSkip[name] || strings.HasPrefix(name, ".") && name != ".docker" && name != ".devcontainer" {
						continue
					}
					if p == absDir || isProjectDir(p) {
						continue
					}
					walk(p, depth+1)
					continue
				}
				if !e.Type().IsRegular() {
					continue
				}
				switch {
				case isDockerfile(name):
					add(p, false)
				case isCompose(name):
					add(p, true)
				}
			}
		}
		walk(root, 0)
	}
	// files a compose file points to: build context / dockerfile, include, extends
	for i := 0; i < len(out); i++ {
		if !out[i].compose {
			continue
		}
		b, err := os.ReadFile(out[i].path)
		if err != nil || len(b) > maxFileSize {
			continue
		}
		cdir := filepath.Dir(out[i].path)
		for _, ref := range composeRefs(string(b)) {
			if strings.Contains(ref.path, "$") || strings.Contains(ref.path, "://") || strings.HasPrefix(ref.path, "git@") {
				continue
			}
			p := ref.path
			if !filepath.IsAbs(p) {
				p = filepath.Join(cdir, p)
			}
			add(p, ref.compose)
		}
	}
	return out
}

// SortIssues orders issues by severity, file and line.
func SortIssues(is []report.DockerIssue) { sortIssues(is) }
