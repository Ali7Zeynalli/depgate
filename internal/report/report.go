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
	ID          string        `json:"id"` // sha256 of repo remote + path, or of absolute path
	Name        string        `json:"name"`
	Dir         string        `json:"dir"`
	Repo        string        `json:"repo,omitempty"`
	Path        string        `json:"path,omitempty"` // path inside the repo
	Manager     string        `json:"manager"`
	Lockfile    string        `json:"lockfile,omitempty"`
	Approximate bool          `json:"approximate"`
	Packages    int           `json:"packages"`
	Node        *Node         `json:"node,omitempty"`
	Hygiene     []Check       `json:"hygiene"`
	Summary     Summary       `json:"summary"`
	Findings    []Finding     `json:"findings"`
	Errors      []string      `json:"errors,omitempty"`
	Sources     []Source      `json:"sources,omitempty"` // data sources used for this scan
	Bundles     []Bundle      `json:"bundles,omitempty"` // packages that must move together (react + react-dom, @nestjs/*, ...)
	Docker      []DockerIssue `json:"docker,omitempty"`  // Dockerfile / compose findings
	DockerFiles []string      `json:"dockerFiles,omitempty"`
	AIRules     *AIRules      `json:"aiRules,omitempty"` // version-aware instructions for AI coding agents
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
}
