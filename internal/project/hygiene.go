package project

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/report"
)

// Hygiene checks the project's own supply-chain settings and returns one check per rule.
// manager is npm|pnpm|yarn|bun; lockKind is the parsed lockfile kind ("none" when absent).
func Hygiene(dir, repoRoot, manager, lockKind string, nodeMismatch bool, cooldownDays int) []report.Check {
	dirs := []string{dir}
	if repoRoot != "" && repoRoot != dir {
		dirs = append(dirs, repoRoot)
	}
	var out []report.Check

	// 1. lockfile present (and not ignored by git)
	lockOK := lockKind != "none" && lockKind != ""
	c := report.Check{ID: "lockfile", OK: lockOK, Title: i18n.F("Lockfile var", "Lockfile present")}
	if !lockOK {
		c.Detail = i18n.F("Lockfile olmadan versiyalar dəqiq bilinmir, dolayı paketlər yoxlanmır və hər install fərqli versiya gətirə bilər.", "Without a lockfile versions are not exact, transitive packages are not checked and every install can bring different versions.")
		c.Fix = map[string]string{"npm": "npm install --package-lock-only", "pnpm": "pnpm install --lockfile-only", "yarn": "yarn install --mode=update-lockfile", "bun": "bun install --save-text-lockfile"}[manager]
	} else if gi, _ := ReadFirst(dirs, ".gitignore"); gi != "" && ignoresLockfile(gi) {
		c.OK = false
		c.Detail = i18n.F(".gitignore lockfile-ı repodan çıxarır — CI və server başqa versiyalar quraşdıra bilər. Lockfile sətrini .gitignore-dan sil və lockfile-ı commit et.", ".gitignore keeps the lockfile out of the repo — CI and servers may install other versions. Remove the lockfile line from .gitignore and commit the lockfile.")
		c.Fix = "git add -f <lockfile>"
		c.File = ".gitignore"
	}
	out = append(out, c)

	// 2. install scripts disabled
	npmrc, npmrcPath := ReadFirst(dirs, ".npmrc")
	npmrc += "\n" + HomeNpmrc() // user-level ~/.npmrc applies too
	scriptsOff := iniBool(npmrc, "ignore-scripts")
	if manager == "yarn" {
		y, _ := ReadFirst(dirs, ".yarnrc.yml")
		scriptsOff = scriptsOff || regexp.MustCompile(`(?m)^\s*enableScripts:\s*false`).MatchString(y)
	}
	if manager == "pnpm" {
		ws, _ := ReadFirst(dirs, "pnpm-workspace.yaml")
		// pnpm 10+ blocks dependency build scripts by default unless listed in onlyBuiltDependencies
		scriptsOff = scriptsOff || strings.Contains(ws, "onlyBuiltDependencies") || strings.Contains(npmrc, "only-built-dependencies")
	}
	c = report.Check{ID: "install-scripts", OK: scriptsOff, Title: i18n.F("Install skriptləri söndürülüb", "Install scripts disabled")}
	if !scriptsOff {
		c.Detail = i18n.F("Supply-chain hücumlarının çoxu preinstall/postinstall skriptləri ilə işə düşür.", "Most supply-chain attacks run through preinstall/postinstall scripts.")
		switch manager {
		case "yarn":
			c.Fix, c.File = "enableScripts: false", ".yarnrc.yml"
		case "pnpm":
			c.Detail = i18n.F("pnpm 10+ skriptləri standart olaraq bloklayır; lazım olanlara pnpm-workspace.yaml-da onlyBuiltDependencies ilə icazə ver.", "pnpm 10+ blocks scripts by default; allow the ones you need with onlyBuiltDependencies in pnpm-workspace.yaml.")
			c.Fix, c.File = "onlyBuiltDependencies:\n  - esbuild", "pnpm-workspace.yaml"
		case "bun":
			c.Detail = i18n.F("bun standart olaraq yalnız trustedDependencies-dəki paketlərin skriptlərini işlədir.", "bun only runs scripts of packages listed in trustedDependencies by default.")
			c.File = "package.json"
			c.OK = true
		default:
			c.Fix, c.File = "ignore-scripts=true", ".npmrc"
		}
	}
	out = append(out, c)

	// 3. release cooldown
	cool := false
	var fix, file string
	minutes := strconv.Itoa(cooldownDays * 1440)
	switch manager {
	case "pnpm":
		ws, _ := ReadFirst(dirs, "pnpm-workspace.yaml")
		cool = regexp.MustCompile(`(?m)^\s*minimumReleaseAge:\s*[1-9]`).MatchString(ws) || iniHas(npmrc, "minimum-release-age")
		fix, file = "minimumReleaseAge: "+minutes+"   # minutes; pnpm 10.16+", "pnpm-workspace.yaml"
	case "yarn":
		y, _ := ReadFirst(dirs, ".yarnrc.yml")
		cool = strings.Contains(y, "npmMinimalAgeGate")
		fix, file = "npmMinimalAgeGate: "+strconv.Itoa(cooldownDays)+"d   # yarn 4.10+", ".yarnrc.yml"
	case "bun":
		b, _ := ReadFirst(dirs, "bunfig.toml")
		cool = strings.Contains(b, "minimumReleaseAge")
		fix, file = "[install]\nminimumReleaseAge = "+strconv.Itoa(cooldownDays*86400)+"   # seconds; bun 1.3+", "bunfig.toml"
	default:
		cool = iniHas(npmrc, "min-release-age")
		fix, file = "min-release-age="+strconv.Itoa(cooldownDays)+"   # days; npm 11.10+", ".npmrc"
	}
	c = report.Check{ID: "cooldown", OK: cool, Title: i18n.F("Yeni versiyalar üçün gözləmə müddəti", "Release cooldown for new versions")}
	if !cool {
		c.Detail = i18n.F("Ələ keçirilmiş versiyalar adətən saatlar içində silinir; bir neçə günlük gözləmə onları quraşdırmağın qarşısını alır.", "Compromised versions are usually removed within hours; waiting a few days keeps them out of your installs.")
		c.Fix, c.File = fix, file
	}
	out = append(out, c)

	// 4. Node version pinned consistently
	c = report.Check{ID: "node-pin", OK: !nodeMismatch, Title: i18n.F("Node versiyası hər yerdə eynidir", "Same Node.js version everywhere")}
	if nodeMismatch {
		c.Detail = i18n.F("Dockerfile, .nvmrc, engines və CI fərqli Node xətləri göstərir — hamısını eyni LTS xəttinə gətir.", "Dockerfile, .nvmrc, engines and CI name different Node lines — align them on one LTS line.")
	}
	out = append(out, c)
	_ = npmrcPath
	return out
}

func ignoresLockfile(gitignore string) bool {
	for _, l := range strings.Split(gitignore, "\n") {
		l = strings.TrimSpace(l)
		switch strings.TrimPrefix(l, "/") {
		case "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "*.lock":
			return true
		}
	}
	return false
}

func iniBool(s, key string) bool {
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s*=\s*true\s*$`)
	return re.MatchString(s)
}

func iniHas(s, key string) bool {
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s*=\s*[1-9]`)
	return re.MatchString(s)
}

// HomeNpmrc returns ~/.npmrc content (user-level settings also apply).
func HomeNpmrc() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	b, _ := os.ReadFile(filepath.Join(h, ".npmrc"))
	return string(b)
}
