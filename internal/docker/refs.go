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

// discover finds Dockerfiles and compose files in dir and repoRoot.
func discover(dir, repoRoot string) []foundFile {
	dirs := []string{dir}
	if repoRoot != "" {
		a, errA := filepath.Abs(dir)
		b, errB := filepath.Abs(repoRoot)
		if errA == nil && errB == nil && a != b {
			dirs = append(dirs, repoRoot)
		}
	}
	var out []foundFile
	seen := map[string]bool{}
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			name := e.Name()
			if !e.Type().IsRegular() || !isDockerfile(name) && !isCompose(name) {
				continue
			}
			p := filepath.Join(d, name)
			abs, _ := filepath.Abs(p)
			if seen[abs] {
				continue
			}
			seen[abs] = true
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				rel = p
			}
			out = append(out, foundFile{p, filepath.ToSlash(rel), isCompose(name)})
		}
	}
	return out
}

// SortIssues orders issues by severity, file and line.
func SortIssues(is []report.DockerIssue) { sortIssues(is) }
