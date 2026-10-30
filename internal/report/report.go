// Package report defines the JSON report DepGate produces (schema depgate/report@1).
// The schema is a stable contract: fields are only added within @1.
package report

import (
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
)

const Schema = "depgate/report@1"

// Need answers "① Do I need to update?".
type Need string

const (
	NeedNow      Need = "now"      // malware or critical/high vulnerability, EOL Node
	NeedSoon     Need = "soon"     // moderate/low vulnerability, Node EOL soon, deprecated
	NeedPlan     Need = "plan"     // only a new major exists
	NeedOptional Need = "optional" // newer patch/minor exists
	NeedNone     Need = "none"     // up to date
)

// Impact answers "② Does it affect my code?".
type Impact string

const (
	ImpactNo      Impact = "no"
	ImpactMaybe   Impact = "maybe"
	ImpactYes     Impact = "yes"
	ImpactUnknown Impact = "unknown"
)

// Group is the card group shown in the UI.
type Group string

const (
	GroupNowEasy  Group = "now_easy" // update needed, code unaffected
	GroupNowCode  Group = "now_code" // update needed, code changes needed
	GroupPlan     Group = "plan"     // only a new major, or Node line change planned
	GroupOptional Group = "optional" // newer patch/minor exists, nothing urgent
	GroupOK       Group = "ok"
	// GroupAccepted: the user accepted the risk for a while (reason and end date in Accepted)
	GroupAccepted Group = "accepted"
)

type Report struct {
	Schema    string    `json:"schema"`
	Tool      string    `json:"tool"`
	ScannedAt time.Time `json:"scannedAt"`
	Offline   bool      `json:"offline,omitempty"`
	Projects  []Project `json:"projects"`
	Errors    []string  `json:"errors,omitempty"`
	Sources   []Source  `json:"sources,omitempty"`
}

// Source is one public data source and how it answered during the scan.
type Source struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Use      i18n.T `json:"use"`
	Requests int    `json:"requests"` // 0: not needed for this scan
	Failed   int    `json:"failed,omitempty"`
}

type Project struct {
	ID          string            `json:"id"` // sha256 of repo remote + path, or of absolute path
	ScannedAt   time.Time         `json:"scannedAt,omitempty"`
	Name        string            `json:"name"`
	Dir         string            `json:"dir"`
	Repo        string            `json:"repo,omitempty"`
	Path        string            `json:"path,omitempty"` // path inside the repo
	Manager     string            `json:"manager"`
	Lockfile    string            `json:"lockfile,omitempty"`
	Approximate bool              `json:"approximate"`
	Packages    int               `json:"packages"`
	Node        *Node             `json:"node,omitempty"`
	Hygiene     []Check           `json:"hygiene"`
	Summary     Summary           `json:"summary"`
	Findings    []Finding         `json:"findings"`
	Errors      []string          `json:"errors,omitempty"`
	Sources     []Source          `json:"sources,omitempty"` // data sources used for this scan
	Bundles     []Bundle          `json:"bundles,omitempty"` // packages that must move together (react + react-dom, @nestjs/*, ...)
	Docker      []DockerIssue     `json:"docker,omitempty"`  // Dockerfile / compose findings
	DockerFiles []string          `json:"dockerFiles,omitempty"`
	Server      []DockerIssue     `json:"server,omitempty"`      // nginx / Caddy config and version findings
	ServerFiles []string          `json:"serverFiles,omitempty"` // nginx / Caddy configs that were checked
	FileEnv     map[string]string `json:"fileEnv,omitempty"`     // Docker/server file → "dev" | "prod" guessed from its name
	EnvMarks    map[string]string `json:"envMarks,omitempty"`    // Docker/server file → "dev" | "prod" the user chose (not saved in the report)
	AIRules     *AIRules          `json:"aiRules,omitempty"`     // version-aware instructions for AI coding agents
	// Images is what the project's Docker files run: images, their OS and the
	// system packages the Dockerfiles install — what the news are matched to.
	Images []ImageItem `json:"images,omitempty"`
	// Versions are the installed packages of this scan; only the history uses
	// them (to tell which versions changed), they are not saved in the report.
	Versions []Version `json:"-"`
}

// ImageItem is one image a project's Docker files use.
type ImageItem struct {
	File      string   `json:"file"` // relative to the project dir
	Line      int      `json:"line,omitempty"`
	Service   string   `json:"service,omitempty"`   // compose service
	Image     string   `json:"image"`               // as written, e.g. postgres:16.4-alpine
	Product   string   `json:"product,omitempty"`   // postgres, redis, nginx, node … ("" when not a known official image)
	Version   string   `json:"version,omitempty"`   // from the tag ("" when unpinned)
	OS        string   `json:"os,omitempty"`        // debian | ubuntu | alpine ("" unknown)
	OSVersion string   `json:"osVersion,omitempty"` // 12, 24.04, 3.19 ("" unknown)
	OSGuess   bool     `json:"osGuess,omitempty"`   // the OS is the image's default, not written in the tag
	Packages  []string `json:"packages,omitempty"`  // apt-get install / apk add in this stage
	Unpinned  bool     `json:"unpinned,omitempty"`  // no tag or :latest
}

// Version is one installed package version.
type Version struct {
	Name    string
	Version string
	Direct  bool
	Dev     bool
}

// Bundle is a family of packages released in lockstep; updating one without
// the others breaks the build (react/react-dom, all @angular/* core packages, ...).
type Bundle struct {
	ID      string       `json:"id"`   // react | next | nestjs | angular | ...
	Name    string       `json:"name"` // display name
	Target  string       `json:"target,omitempty"`
	Items   []BundleItem `json:"items"`
	Command string       `json:"command,omitempty"`
	Why     []i18n.T     `json:"why"`
	Impact  Impact       `json:"impact"`
	Docs    string       `json:"docs,omitempty"`
}

type BundleItem struct {
	Pkg     string `json:"pkg"`
	Current string `json:"current"`
	Target  string `json:"target,omitempty"` // "" when it can stay
	Dev     bool   `json:"dev,omitempty"`
	Note    i18n.T `json:"note"`
}

// DockerIssue is one finding in a Dockerfile or a compose file.
type DockerIssue struct {
	File     string `json:"file"`              // path relative to the project dir (may start with ../ for the repo root)
	Line     int    `json:"line,omitempty"`    // 1-based
	Service  string `json:"service,omitempty"` // compose service
	Rule     string `json:"rule"`              // stable id, e.g. dockerfile-root-user
	Severity string `json:"severity"`          // high | medium | low
	Title    i18n.T `json:"title"`
	Detail   i18n.T `json:"detail"`
	Fix      string `json:"fix,omitempty"` // suggested line (code only)
	// Env: "dev" when the file, stage or service is for development only,
	// "prod" when its name says production, "" unknown (treated as production)
	Env    string  `json:"env,omitempty"`
	EnvWhy *i18n.T `json:"envWhy,omitempty"`
}

// AIRules are instructions for AI coding agents, generated from the versions the
// project actually uses. English only: they go into AGENTS.md / CLAUDE.md.
type AIRules struct {
	Stack   []StackItem   `json:"stack"`
	Rules   []AIRule      `json:"rules"`
	Replace []Replacement `json:"replace,omitempty"`
}

type StackItem struct {
	Pkg     string `json:"pkg"`
	Version string `json:"version"`
	Docs    string `json:"docs,omitempty"`
}

type AIRule struct {
	Topic string `json:"topic"` // e.g. "next 16"
	Text  string `json:"text"`
	Docs  string `json:"docs,omitempty"`
}

type Replacement struct {
	Pkg  string `json:"pkg"`
	Use  string `json:"use"`
	Why  string `json:"why"`
	Docs string `json:"docs,omitempty"`
}

type Summary struct {
	NowEasy  int `json:"now_easy"`
	NowCode  int `json:"now_code"`
	Plan     int `json:"plan"`
	Optional int `json:"optional"`
	OK       int `json:"ok"`
	Accepted int `json:"accepted,omitempty"`
	Malware  int `json:"malware"`
	Critical int `json:"critical"`
	High     int `json:"high"`
}

// Node describes the project's Node.js runtime and what the release data says about it.
type Node struct {
	Version      string       `json:"version,omitempty"` // resolved x.y.z, "" when only a line is known
	Line         int          `json:"line,omitempty"`    // major
	Sources      []NodeSource `json:"sources"`
	Mismatch     bool         `json:"mismatch,omitempty"` // sources disagree on the line
	LatestInLine string       `json:"latestInLine,omitempty"`
	SecurityFix  string       `json:"securityFix,omitempty"` // newest security release in the line, when newer than Version
	LTS          string       `json:"lts,omitempty"`         // codename when LTS
	EOL          string       `json:"eol,omitempty"`         // YYYY-MM-DD
	DaysToEOL    *int         `json:"daysToEol,omitempty"`
	NextLTS      int          `json:"nextLts,omitempty"`
	Need         Need         `json:"need"`
	Impact       Impact       `json:"impact"`
	Why          []i18n.T     `json:"why"`
	Command      string       `json:"command,omitempty"` // e.g. FROM node:22.23.4-bookworm-slim
	Vulns        []NodeVuln   `json:"vulns,omitempty"`   // core vulnerabilities affecting Version (Node.js security WG)
}

// NodeVuln is a Node.js core vulnerability that affects the project's version.
type NodeVuln struct {
	ID       string   `json:"id"`
	CVE      []string `json:"cve,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Title    string   `json:"title"`
	Patched  string   `json:"patched,omitempty"`
	URL      string   `json:"url,omitempty"`
	Env      []string `json:"env,omitempty"` // e.g. win32 when it only affects Windows
}

type NodeSource struct {
	File  string `json:"file"`  // Dockerfile, .nvmrc, package.json engines, ...
	Value string `json:"value"` // raw value
}

type Check struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Title  i18n.T `json:"title"`
	Detail i18n.T `json:"detail"`
	Fix    string `json:"fix,omitempty"` // a line to add (code only)
	File   string `json:"file,omitempty"`
}

type Finding struct {
	Key        string   `json:"key"`  // stable: kind:pkg:advisory
	Kind       string   `json:"kind"` // vuln | malware | update | deprecated | suspicious
	Pkg        string   `json:"pkg"`
	About      string   `json:"about,omitempty"`    // the package's own description (npm)
	Homepage   string   `json:"homepage,omitempty"` // the package's homepage (npm)
	Direct     bool     `json:"direct"`
	Dev        bool     `json:"dev"`
	Chain      []string `json:"chain,omitempty"` // direct parent -> ... -> pkg for transitive packages
	Current    string   `json:"current"`
	Target     string   `json:"target,omitempty"`
	Latest     string   `json:"latest,omitempty"`
	Need       Need     `json:"needUpdate"`
	Impact     Impact   `json:"codeImpact"`
	Group      Group    `json:"group"`
	Priority   int      `json:"priority"`
	Severity   string   `json:"severity,omitempty"` // critical | high | moderate | low
	Title      string   `json:"title,omitempty"`
	Why        []i18n.T `json:"why"`
	ImpactWhy  []i18n.T `json:"impactWhy,omitempty"`
	Fix        *Fix     `json:"fix,omitempty"`
	Advisories []Adv    `json:"advisories,omitempty"`
	Warnings   []i18n.T `json:"warnings,omitempty"` // cooldown, approximate, ...
	// what changes in the project's own code when moving to Target (and, for
	// planning, to the newest major)
	Migrate []Migration `json:"migrate,omitempty"`
	// Accepted is set when the user accepted this risk; Group is then GroupAccepted.
	Accepted *Accepted `json:"accepted,omitempty"`
}

// Accepted records a risk the user chose to live with until a date.
type Accepted struct {
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
	Until  time.Time `json:"until"`
	Group  Group     `json:"group"` // the group DepGate gave it
	// File is set when the acceptance comes from a depgate-accept.json in the
	// project (shared with the team and CI); it is changed by editing that file.
	File string `json:"file,omitempty"`
}

// Summarize counts findings per group. Accepted findings count only as accepted.
func Summarize(fs []Finding) Summary {
	var s Summary
	for _, f := range fs {
		switch f.Group {
		case GroupNowEasy:
			s.NowEasy++
		case GroupNowCode:
			s.NowCode++
		case GroupPlan:
			s.Plan++
		case GroupOptional:
			s.Optional++
		case GroupAccepted:
			s.Accepted++
			continue
		default:
			s.OK++
		}
		switch {
		case f.Kind == "malware":
			s.Malware++
		case f.Kind == "vuln" && f.Severity == "critical":
			s.Critical++
		case f.Kind == "vuln" && f.Severity == "high":
			s.High++
		}
	}
	return s
}

// Migration describes the code changes for one move cur → To.
type Migration struct {
	To    string        `json:"to"`
	Plan  bool          `json:"plan,omitempty"` // to the newest major, beyond the suggested target
	Steps []MigStep     `json:"steps,omitempty"`
	Hits  int           `json:"hits"` // places in the project's code, all steps
	Notes []ReleaseNote `json:"notes,omitempty"`
	// NotesErr is set when release notes could not be loaded (rate limit, no GitHub repo)
	NotesErr string `json:"notesErr,omitempty"`
}

// MigStep is one documented breaking change set (e.g. "Next.js 16").
type MigStep struct {
	Topic   string    `json:"topic"`
	Docs    string    `json:"docs"`
	Codemod string    `json:"codemod,omitempty"` // official automatic migration command
	Hits    []CodeHit `json:"hits,omitempty"`
	Checks  []i18n.T  `json:"checks,omitempty"` // things to verify by hand (no pattern can find them)
}

// CodeHit is one place in the project's code that needs a change.
type CodeHit struct {
	File string `json:"file"` // relative to the project dir
	Line int    `json:"line"`
	Code string `json:"code"` // the line, trimmed
	Rule string `json:"rule"`
	Msg  i18n.T `json:"msg"`
	Fix  string `json:"fix,omitempty"`
}

// ReleaseNote is the breaking part of one upstream release.
type ReleaseNote struct {
	Version  string `json:"version"`
	URL      string `json:"url"`
	Breaking string `json:"breaking"` // markdown excerpt
}

// Fix is the concrete remediation DepGate suggests (never executed).
type Fix struct {
	Strategy string `json:"strategy"`          // upgrade | relock | parent | override | remove
	Command  string `json:"command,omitempty"` // shell command
	Snippet  string `json:"snippet,omitempty"` // e.g. package.json overrides block
	File     string `json:"file,omitempty"`    // where the snippet goes
	Parent   string `json:"parent,omitempty"`  // for strategy=parent: direct package to upgrade
	Note     i18n.T `json:"note"`
}

type Adv struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases,omitempty"`
	Summary  string   `json:"summary,omitempty"`
	Severity string   `json:"severity,omitempty"`
	CVSS     float64  `json:"cvss,omitempty"`
	EPSS     float64  `json:"epss,omitempty"`
	KEV      bool     `json:"kev,omitempty"`
	Fixed    string   `json:"fixed,omitempty"` // lowest fixed version above current
	URL      string   `json:"url,omitempty"`
	// what the weakness is and what it lets an attacker do (from the CWE ids)
	Weakness []Weakness `json:"weakness,omitempty"`
	// Details is the advisory's own description, shortened (English, as published)
	Details string `json:"details,omitempty"`
}

// Weakness explains one CWE in plain words.
type Weakness struct {
	ID   string `json:"id"` // CWE-1321
	URL  string `json:"url"`
	Name i18n.T `json:"name"` // empty when DepGate has no text for this CWE
	What i18n.T `json:"what"` // what the weakness is
	Risk i18n.T `json:"risk"` // what an attacker can do with it
}
