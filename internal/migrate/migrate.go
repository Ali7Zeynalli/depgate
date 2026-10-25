// Package migrate finds the places in a project's own code that must change
// when a package moves across a breaking version (Next.js 16, React 19, ...).
//
// It only reads files on the user's machine and never changes them. Patterns
// are text based: they point at likely places with the reason and the official
// guide, they do not replace build and tests.
package migrate

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/semver"
)

// step is one documented set of breaking changes, applied when a move crosses `crosses`.
type step struct {
	pkg      string
	crosses  string // the move cur → to applies when cur < crosses <= to
	topic    string
	docs     string
	codemod  string
	checks   []i18n.T
	patterns []pattern
	// files reports hits that depend on the file tree, not on file content
	files func(root string, files []string) []report.CodeHit
}

type pattern struct {
	id   string
	path *regexp.Regexp // which files (slash path relative to the project); nil = code files
	re   *regexp.Regexp
	ok   func(m []string) bool // extra check on the submatches; nil = always
	msg  i18n.T
	fix  string
}

var codeFile = regexp.MustCompile(`\.(m|c)?(j|t)sx?$|\.vue$|\.svelte$|\.astro$`)

// skipDirs are never scanned.
var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, ".next": true, "dist": true, "build": true, "out": true, "coverage": true,
	".turbo": true, ".vercel": true, ".output": true, ".nuxt": true, ".svelte-kit": true, "storybook-static": true,
	"vendor": true, ".cache": true, ".pnpm-store": true, ".yarn": true, "tmp": true,
}

const (
	maxFile    = 512 << 10 // bytes
	maxFiles   = 20000
	maxPerRule = 30
	maxPerStep = 150
)

// Project holds the files of one project, read once for all packages.
type Project struct {
	root  string
	files []string // slash paths relative to root
	cache map[string][]string
}

// Open lists the project's files. Nested packages (sub-folders with their own
// package.json) belong to other projects and are skipped.
func Open(root string) *Project {
	p := &Project{root: root, cache: map[string][]string{}}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			if skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".") && d.Name() != ".storybook" {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "package.json")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if len(p.files) >= maxFiles || !d.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		p.files = append(p.files, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(p.files)
	return p
}

func (p *Project) lines(rel string) []string {
	if l, ok := p.cache[rel]; ok {
		return l
	}
	var out []string
	full := filepath.Join(p.root, filepath.FromSlash(rel))
	if st, err := os.Stat(full); err == nil && st.Size() <= maxFile && !strings.HasSuffix(rel, ".min.js") {
		if b, err := os.ReadFile(full); err == nil && !bytes.Contains(b[:min(len(b), 8000)], []byte{0}) {
			sc := bufio.NewScanner(bytes.NewReader(b))
			sc.Buffer(make([]byte, 64<<10), 1<<20)
			for sc.Scan() {
				out = append(out, sc.Text())
			}
		}
	}
	p.cache[rel] = out
	return out
}

// For returns the migration for pkg moving cur → to, or nil when no documented
// breaking change is crossed.
func (p *Project) For(pkg, cur, to string) *report.Migration {
	cv, err1 := semver.Parse(cur)
	tv, err2 := semver.Parse(to)
	if err1 != nil || err2 != nil || !semver.Less(cv, tv) {
		return nil
	}
	m := &report.Migration{To: to}
	seen := map[string]bool{}
	for _, s := range steps {
		if s.pkg != pkg {
			continue
		}
		b, err := semver.Parse(s.crosses)
		if err != nil || !semver.Less(cv, b) || semver.Less(tv, b) {
			continue
		}
		ms := report.MigStep{Topic: s.topic, Docs: s.docs, Codemod: s.codemod, Checks: s.checks}
		for _, h := range p.scan(s) {
			// the same rule found again by a later step (next15-sync-params, next16-sync-params)
			_, kind, _ := strings.Cut(h.Rule, "-")
			k := h.File + ":" + strconv.Itoa(h.Line) + ":" + kind
			if !seen[k] {
				seen[k] = true
				ms.Hits = append(ms.Hits, h)
			}
		}
		m.Hits += len(ms.Hits)
		m.Steps = append(m.Steps, ms)
	}
	if len(m.Steps) == 0 {
		return nil
	}
	return m
}

func (p *Project) scan(s step) []report.CodeHit {
	var hits []report.CodeHit
	if s.files != nil {
		hits = append(hits, s.files(p.root, p.files)...)
	}
	for _, pt := range s.patterns {
		n := 0
		for _, f := range p.files {
			if pt.path != nil && !pt.path.MatchString(f) || pt.path == nil && !codeFile.MatchString(f) {
				continue
			}
			for i, line := range p.lines(f) {
				m := pt.re.FindStringSubmatch(line)
				if m == nil || pt.ok != nil && !pt.ok(m) || isComment(line) {
					continue
				}
				hits = append(hits, report.CodeHit{File: f, Line: i + 1, Code: clip(strings.TrimSpace(line)), Rule: pt.id, Msg: pt.msg, Fix: pt.fix})
				if n++; n >= maxPerRule {
					break
				}
			}
			if n >= maxPerRule {
				break
			}
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].File != hits[j].File {
			return hits[i].File < hits[j].File
		}
		return hits[i].Line < hits[j].Line
	})
	if len(hits) > maxPerStep {
		hits = hits[:maxPerStep]
	}
	return hits
}

func isComment(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "#")
}

func clip(s string) string {
	if len(s) > 160 {
		return s[:157] + "…"
	}
	return s
}

// fileHit is a hit on a whole file (line 1).
func fileHit(rel, rule string, msg i18n.T, fix string) report.CodeHit {
	return report.CodeHit{File: rel, Line: 1, Code: rel, Rule: rule, Msg: msg, Fix: fix}
}
