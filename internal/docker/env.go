package docker

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/report"
)

// Environments: a finding in a file (or stage, or service) that only runs on a
// developer's machine matters less than one that reaches production. DepGate
// guesses from names; the user can mark a file in the UI when it guesses wrong.

// devWord matches a name part that means development: dev, development, local, debug, test…
var devWord = regexp.MustCompile(`(?i)(^|[._/-])(dev|develop|development|local|debug|test|testing|e2e|ci|override)([._/-]|$)`)

// prodWord matches a name part that means production.
var prodWord = regexp.MustCompile(`(?i)(^|[._/-])(prod|production|release|live|staging|stage)([._/-]|$)`)

var fromAsRe = regexp.MustCompile(`(?i)^\s*FROM\s+\S+(?:\s+AS\s+(\S+))?`)

// EnvOfFile guesses the environment of a Docker, Compose or web server file
// from its path: "dev", "prod" or "" (unknown — treated as production).
func EnvOfFile(rel string) (env string, why i18n.T) {
	name := filepath.ToSlash(rel)
	base := filepath.Base(name)
	// compose.override.yml is applied by `docker compose up` on the developer's machine
	if strings.HasPrefix(base, "docker-compose.override.") || strings.HasPrefix(base, "compose.override.") {
		return "dev", i18n.F("fayl adı: override (adətən lokal inkişaf üçün)", "file name: override (usually local development)")
	}
	// only the file name and its own folder decide; a repo called "my-test-app" does not
	part := strings.TrimPrefix(filepath.ToSlash(filepath.Join(filepath.Base(filepath.Dir(name)), base)), "./")
	if prodWord.MatchString(part) {
		return "prod", i18n.F("ad: %s", "name: %s", part)
	}
	if devWord.MatchString(part) {
		return "dev", i18n.F("ad: %s", "name: %s", part)
	}
	return "", i18n.T{}
}

// stageAt returns the name of the Dockerfile stage that contains line (1-based).
func stageAt(src string, line int) string {
	stage := ""
	for i, l := range strings.Split(src, "\n") {
		if i+1 > line {
			break
		}
		if m := fromAsRe.FindStringSubmatch(l); m != nil {
			stage = m[1]
		}
	}
	return stage
}

// composeProfiles returns the profiles of every service in a compose file.
func composeProfiles(src string) map[string][]string {
	out := map[string][]string{}
	root, err := parseYAML(src)
	if err != nil || root == nil {
		return out
	}
	svcs := root.get("services")
	if svcs == nil {
		return out
	}
	for _, k := range svcs.Keys {
		for _, it := range items(k.Val.get("profiles")) {
			out[k.Name] = append(out[k.Name], it.str())
		}
	}
	return out
}

// TagEnv sets Env and EnvWhy of every issue found under dir: from the file
// name, the Dockerfile stage the line is in, or the compose service's profiles.
func TagEnv(dir string, is []report.DockerIssue) {
	srcs := map[string]string{}
	src := func(rel string) string {
		if s, ok := srcs[rel]; ok {
			return s
		}
		s := ""
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if st, err := os.Stat(p); err == nil && st.Size() <= maxFileSize {
			if b, err := os.ReadFile(p); err == nil {
				s = string(b)
			}
		}
		srcs[rel] = s
		return s
	}
	profiles := map[string]map[string][]string{}
	for i := range is {
		d := &is[i]
		env, why := EnvOfFile(d.File)
		base := filepath.Base(d.File)
		switch {
		case isDockerfile(base) && d.Line > 0:
			if st := stageAt(src(d.File), d.Line); st != "" {
				if prodWord.MatchString(st) {
					env, why = "prod", i18n.F("mərhələ: %s", "stage: %s", st)
				} else if devWord.MatchString(st) {
					env, why = "dev", i18n.F("mərhələ: %s", "stage: %s", st)
				}
			}
		case isCompose(base) && d.Service != "":
			if profiles[d.File] == nil {
				profiles[d.File] = composeProfiles(src(d.File))
			}
			for _, pr := range profiles[d.File][d.Service] {
				if devWord.MatchString(pr) {
					env, why = "dev", i18n.F("profil: %s", "profile: %s", pr)
				}
			}
		}
		d.Env, d.EnvWhy = env, nil
		if env != "" {
			w := why
			d.EnvWhy = &w
		}
	}
}
