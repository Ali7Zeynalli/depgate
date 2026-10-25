package lockfile

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const fixtures = "../../testdata/lockfiles"

func parseFixture(t *testing.T, name string) *Result {
	t.Helper()
	r, err := Parse(filepath.Join(fixtures, name))
	if err != nil {
		t.Fatalf("Parse(%s): %v", name, err)
	}
	return r
}

// find returns the package name@version or fails.
func find(t *testing.T, r *Result, name, version string) Package {
	t.Helper()
	for _, p := range r.Packages {
		if p.Name == name && p.Version == version {
			return p
		}
	}
	t.Fatalf("%s@%s not found; have %v", name, version, versionsOf(r, name))
	return Package{}
}

func versionsOf(r *Result, name string) []string {
	var out []string
	for _, p := range r.Packages {
		if p.Name == name {
			out = append(out, p.Version)
		}
	}
	return out
}

func has(r *Result, name string) bool { return len(versionsOf(r, name)) > 0 }

func checkFlags(t *testing.T, p Package, direct, dev bool, rng string) {
	t.Helper()
	if p.Direct != direct || p.Dev != dev || p.Range != rng {
		t.Errorf("%s@%s: direct=%v dev=%v range=%q, want direct=%v dev=%v range=%q",
			p.Name, p.Version, p.Direct, p.Dev, p.Range, direct, dev, rng)
	}
}

func checkParents(t *testing.T, p Package, want ...string) {
	t.Helper()
	if !reflect.DeepEqual(p.Parents, want) {
		t.Errorf("%s@%s parents = %v, want %v", p.Name, p.Version, p.Parents, want)
	}
}

// The standard fixture project (same graph in every lockfile format):
//
//	deps:    axios ^1.6.8, express ^4.19.2, make-dir ^3.1.0, my-lodash npm:lodash@^4.17.21,
//	         next ^14.2.3, react ^18.2.0, react-dom ^18.2.0
//	devDeps: @types/node ^20.12.7, nodemon ^3.1.0, typescript ^5.4.5
//
// semver 7.6.0 (via next>sharp, and nodemon) and 6.3.1 (nested under make-dir);
// debug 2.6.9 (express) and 4.3.4 (nested under nodemon, dev only);
// sharp is an optional dep of next with an install script.
func checkStandard(t *testing.T, r *Result, wantScripts bool, rangesResolved bool) {
	t.Helper()
	if len(r.Packages) != 30 {
		t.Errorf("got %d packages, want 30", len(r.Packages))
	}
	if r.Approximate {
		t.Error("Approximate = true, want false")
	}
	checkFlags(t, find(t, r, "next", "14.2.3"), true, false, "^14.2.3")
	checkFlags(t, find(t, r, "react", "18.2.0"), true, false, "^18.2.0")
	checkFlags(t, find(t, r, "axios", "1.6.8"), true, false, "^1.6.8")
	checkFlags(t, find(t, r, "express", "4.19.2"), true, false, "^4.19.2")
	checkFlags(t, find(t, r, "typescript", "5.4.5"), true, true, "^5.4.5")
	checkFlags(t, find(t, r, "@types/node", "20.12.7"), true, true, "^20.12.7")
	checkFlags(t, find(t, r, "undici-types", "5.26.5"), false, true, "")

	// alias: installed as my-lodash, reported by its real name
	checkFlags(t, find(t, r, "lodash", "4.17.21"), true, false, "^4.17.21")
	if has(r, "my-lodash") {
		t.Error("alias name my-lodash leaked into packages")
	}

	// duplicate versions with correct parents
	if got := versionsOf(r, "semver"); len(got) != 2 {
		t.Errorf("semver versions = %v, want 6.3.1 and 7.6.0", got)
	}
	s7 := find(t, r, "semver", "7.6.0")
	checkParents(t, s7, "nodemon", "sharp", "simple-update-notifier")
	checkFlags(t, s7, false, false, "") // prod through next > sharp
	s6 := find(t, r, "semver", "6.3.1")
	checkParents(t, s6, "make-dir")
	checkFlags(t, s6, false, false, "")

	d4 := find(t, r, "debug", "4.3.4")
	checkParents(t, d4, "nodemon")
	checkFlags(t, d4, false, true, "") // only through devDependencies
	checkFlags(t, find(t, r, "ms", "2.1.2"), false, true, "")
	checkFlags(t, find(t, r, "debug", "2.6.9"), false, false, "")
	checkParents(t, find(t, r, "ms", "2.0.0"), "debug")

	// scoped transitive
	checkParents(t, find(t, r, "@next/env", "14.2.3"), "next")
	checkParents(t, find(t, r, "loose-envify", "1.4.0"), "react", "react-dom", "scheduler")

	sharp := find(t, r, "sharp", "0.33.3")
	checkParents(t, sharp, "next")
	if sharp.Scripts != wantScripts {
		t.Errorf("sharp Scripts = %v, want %v", sharp.Scripts, wantScripts)
	}
	if find(t, r, "react", "18.2.0").Scripts {
		t.Error("react Scripts = true")
	}

	// requires: own deps including optional ones
	next := find(t, r, "next", "14.2.3")
	if len(next.Requires) != 3 || next.Requires["sharp"] == "" || next.Requires["@next/env"] == "" {
		t.Errorf("next requires = %v", next.Requires)
	}
	if !rangesResolved {
		if next.Requires["sharp"] != "^0.33.3" {
			t.Errorf("next requires sharp %q, want ^0.33.3", next.Requires["sharp"])
		}
	} else if next.Requires["sharp"] != "0.33.3" {
		t.Errorf("next requires sharp %q, want 0.33.3", next.Requires["sharp"])
	}
	if len(find(t, r, "yallist", "4.0.0").Requires) != 0 {
		t.Error("yallist has requires")
	}
	for _, p := range r.Packages {
		for _, par := range p.Parents {
			if par == "" {
				t.Errorf("%s has empty parent", p.Name)
			}
		}
	}
}

func TestNpmV3(t *testing.T) {
	r := parseFixture(t, "npm-v3")
	if r.Kind != "npm" || r.File != "package-lock.json" || r.Manager != "npm" {
		t.Errorf("kind/file/manager = %s/%s/%s", r.Kind, r.File, r.Manager)
	}
	checkStandard(t, r, true, false)
}

func TestNpmV2(t *testing.T) {
	r := parseFixture(t, "npm-v2")
	if r.Kind != "npm" {
		t.Errorf("kind = %s", r.Kind)
	}
	checkStandard(t, r, true, false)
}

func TestNpmV1(t *testing.T) {
	r := parseFixture(t, "npm-v1")
	if r.Kind != "npm" {
		t.Errorf("kind = %s", r.Kind)
	}
	checkStandard(t, r, false, false) // v1 does not record install scripts
}

func TestPnpmV6(t *testing.T) {
	r := parseFixture(t, "pnpm-v6")
	if r.Kind != "pnpm" || r.File != "pnpm-lock.yaml" || r.Manager != "pnpm" {
		t.Errorf("kind/file/manager = %s/%s/%s", r.Kind, r.File, r.Manager)
	}
	checkStandard(t, r, true, true)
	// peer suffix stripped, edges kept: react-dom@18.2.0(react@18.2.0) -> scheduler
	checkParents(t, find(t, r, "scheduler", "0.23.2"), "react-dom")
	checkParents(t, find(t, r, "styled-jsx", "5.1.1"), "next")
}

func TestPnpmV9(t *testing.T) {
	r := parseFixture(t, "pnpm-v9")
	if r.Kind != "pnpm" || r.Manager != "pnpm" {
		t.Errorf("kind/manager = %s/%s", r.Kind, r.Manager)
	}
	checkStandard(t, r, false, true) // pnpm 9 dropped requiresBuild from the lockfile
	checkParents(t, find(t, r, "client-only", "0.0.1"), "styled-jsx")
}

func TestPnpmV9WorkspaceMember(t *testing.T) {
	dir := filepath.Join(fixtures, "pnpm-v9-workspace", "apps", "web")
	kind, file := Detect(dir)
	if kind != "pnpm" || file != filepath.Join("..", "..", "pnpm-lock.yaml") {
		t.Errorf("Detect = %s %s", kind, file)
	}
	r := parseFixture(t, "pnpm-v9-workspace/apps/web")
	if r.File != filepath.Join("..", "..", "pnpm-lock.yaml") {
		t.Errorf("File = %s", r.File)
	}
	checkFlags(t, find(t, r, "next", "14.2.3"), true, false, "^14.2.3")
	checkFlags(t, find(t, r, "axios", "1.6.8"), true, false, "^1.6.8")
	// other members' packages are not reported for this member
	for _, n := range []string{"express", "nodemon", "typescript", "debug", "@acme/ui"} {
		if has(r, n) {
			t.Errorf("%s should not be in apps/web", n)
		}
	}
	// parents restricted to this member's tree
	checkParents(t, find(t, r, "semver", "7.6.0"), "sharp")
	if len(r.Packages) != 17 {
		t.Errorf("got %d packages, want 17", len(r.Packages))
	}

	api := parseFixture(t, "pnpm-v9-workspace/apps/api")
	checkFlags(t, find(t, api, "express", "4.19.2"), true, false, "^4.19.2")
	checkFlags(t, find(t, api, "nodemon", "3.1.0"), true, true, "^3.1.0")
	checkFlags(t, find(t, api, "semver", "7.6.0"), false, true, "")
	if has(api, "next") {
		t.Error("next should not be in apps/api")
	}

	root := parseFixture(t, "pnpm-v9-workspace")
	if root.File != "pnpm-lock.yaml" || len(root.Packages) != 1 {
		t.Errorf("root: file=%s packages=%v", root.File, root.Packages)
	}
	checkFlags(t, find(t, root, "typescript", "5.4.5"), true, true, "^5.4.5")
}

func TestYarnV1(t *testing.T) {
	r := parseFixture(t, "yarn-v1")
	if r.Kind != "yarn" || r.Manager != "yarn" {
		t.Errorf("kind/manager = %s/%s", r.Kind, r.Manager)
	}
	checkStandard(t, r, false, false)
}

func TestYarnBerry(t *testing.T) {
	r := parseFixture(t, "yarn-berry")
	if r.Kind != "yarn-berry" || r.Manager != "yarn" || r.File != "yarn.lock" {
		t.Errorf("kind/manager/file = %s/%s/%s", r.Kind, r.Manager, r.File)
	}
	checkStandard(t, r, false, false)
	if has(r, "yarn-berry-app") {
		t.Error("workspace entry reported as a package")
	}
}

func TestBun(t *testing.T) {
	r := parseFixture(t, "bun")
	if r.Kind != "bun" || r.Manager != "bun" || r.File != "bun.lock" {
		t.Errorf("kind/manager/file = %s/%s/%s", r.Kind, r.Manager, r.File)
	}
	checkStandard(t, r, true, false) // sharp is in trustedDependencies
}

func TestNoLockApprox(t *testing.T) {
	r := parseFixture(t, "nolock-approx")
	if r.Kind != "none" || r.File != "" || !r.Approximate || r.Manager != "npm" {
		t.Errorf("kind/file/approx/manager = %s/%q/%v/%s", r.Kind, r.File, r.Approximate, r.Manager)
	}
	checkFlags(t, find(t, r, "next", "14.2.3"), true, false, "^14.2.3")
	checkFlags(t, find(t, r, "left-pad", "1.3.0"), true, false, "1.3.0")
	checkFlags(t, find(t, r, "typescript", "5.4.5"), true, true, "^5.4.5")
	checkFlags(t, find(t, r, "lodash", "4.17.21"), true, false, "^4.17.21")
	checkFlags(t, find(t, r, "lodash", "3.10.1"), true, false, "~3.10.1")
	for _, n := range []string{"@acme/shared", "local-lib", "gh-lib", "my-lodash", "lodash-legacy"} {
		if has(r, n) {
			t.Errorf("%s should be skipped", n)
		}
	}
	if len(r.Packages) != 12 {
		t.Errorf("got %d packages, want 12", len(r.Packages))
	}
}

func TestNoLockApproxCustomMinVersion(t *testing.T) {
	old := MinVersion
	defer func() { MinVersion = old }()
	MinVersion = func(rng string) (string, bool) {
		if rng == "^14.2.3" {
			return "14.2.3", true
		}
		return "", false
	}
	r := parseFixture(t, "nolock-approx")
	if len(r.Packages) != 1 || r.Packages[0].Name != "next" {
		t.Errorf("packages = %v, want only next", r.Packages)
	}
}

func TestNoLockNodeModules(t *testing.T) {
	r := parseFixture(t, "nolock-nodemodules")
	if r.Kind != "none" || r.File != "node_modules" || r.Approximate {
		t.Errorf("kind/file/approx = %s/%s/%v", r.Kind, r.File, r.Approximate)
	}
	checkStandard(t, r, true, false) // scripts.install in sharp's package.json
}

func TestDefaultMinVersion(t *testing.T) {
	for in, want := range map[string]string{
		"^1.2.3": "1.2.3", "~1.2.3": "1.2.3", ">=1.2.3": "1.2.3", "=1.2.3": "1.2.3", "v1.2.3": "1.2.3",
		"1.2.3-beta.1": "1.2.3-beta.1", "^1.2": "", "*": "", "latest": "", "workspace:*": "", ">=1 <2": "",
	} {
		got, ok := MinVersion(in)
		if got != want || ok != (want != "") {
			t.Errorf("MinVersion(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
}

// --- temp-dir cases --------------------------------------------------------

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestDetectPreference(t *testing.T) {
	pj := `{"name":"x","dependencies":{"a":"^1.0.0"}}`
	cases := []struct {
		files      []string
		kind, file string
	}{
		{[]string{"pnpm-lock.yaml", "package-lock.json", "yarn.lock", "bun.lock"}, "pnpm", "pnpm-lock.yaml"},
		{[]string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock"}, "npm", "package-lock.json"},
		{[]string{"npm-shrinkwrap.json", "yarn.lock"}, "npm", "npm-shrinkwrap.json"},
		{[]string{"yarn.lock", "bun.lock"}, "yarn", "yarn.lock"},
		{[]string{"bun.lock", "bun.lockb"}, "bun", "bun.lock"},
		{nil, "none", ""},
	}
	for _, c := range cases {
		fs := map[string]string{"package.json": pj, ".git/HEAD": "ref: refs/heads/main\n"}
		for _, f := range c.files {
			fs[f] = "{}"
		}
		dir := writeFiles(t, fs)
		if k, f := Detect(dir); k != c.kind || f != c.file {
			t.Errorf("%v: Detect = %s %q, want %s %q", c.files, k, f, c.kind, c.file)
		}
	}
	dir := writeFiles(t, map[string]string{"package.json": pj, "yarn.lock": "# yarn\n\n__metadata:\n  version: 8\n"})
	if k, _ := Detect(dir); k != "yarn-berry" {
		t.Errorf("berry detect = %s", k)
	}
}

func TestBunLockb(t *testing.T) {
	dir := writeFiles(t, map[string]string{"package.json": `{"name":"x"}`, "bun.lockb": "\x00binary"})
	_, err := Parse(dir)
	if err == nil || !strings.Contains(err.Error(), "bun install --save-text-lockfile") {
		t.Errorf("err = %v", err)
	}
}

func TestPackageManagerOverride(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"package.json":      `{"name":"x","packageManager":"yarn@4.1.1+sha512.abc","dependencies":{"a":"^1.0.0"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"dependencies":{"a":"^1.0.0"}},"node_modules/a":{"version":"1.0.0"}}}`,
	})
	r, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "npm" || r.Manager != "yarn" {
		t.Errorf("kind/manager = %s/%s", r.Kind, r.Manager)
	}
}

func TestNpmWorkspaceMember(t *testing.T) {
	lock := `{
  "name": "mono", "lockfileVersion": 3, "requires": true,
  "packages": {
    "": {"name": "mono", "workspaces": ["packages/*"], "devDependencies": {"typescript": "^5.4.5"}},
    "node_modules/@mono/lib": {"resolved": "packages/lib", "link": true},
    "node_modules/@mono/web": {"resolved": "packages/web", "link": true},
    "node_modules/typescript": {"version": "5.4.5", "dev": true},
    "node_modules/ms": {"version": "2.1.3"},
    "node_modules/debug": {"version": "4.3.4", "dependencies": {"ms": "2.1.2"}},
    "node_modules/debug/node_modules/ms": {"version": "2.1.2"},
    "packages/lib": {"name": "@mono/lib", "version": "1.0.0", "dependencies": {"ms": "^2.1.3"}},
    "packages/web": {"name": "@mono/web", "version": "1.0.0", "dependencies": {"@mono/lib": "*", "debug": "^4.3.4", "esbuild": "^0.20.2"}},
    "packages/web/node_modules/esbuild": {"version": "0.20.2", "hasInstallScript": true}
  }
}`
	dir := writeFiles(t, map[string]string{
		"package.json":              `{"name":"mono","workspaces":["packages/*"],"devDependencies":{"typescript":"^5.4.5"}}`,
		"package-lock.json":         lock,
		"packages/web/package.json": `{"name":"@mono/web","dependencies":{"@mono/lib":"*","debug":"^4.3.4","esbuild":"^0.20.2"}}`,
		"packages/lib/package.json": `{"name":"@mono/lib","dependencies":{"ms":"^2.1.3"}}`,
	})
	r, err := Parse(filepath.Join(dir, "packages", "web"))
	if err != nil {
		t.Fatal(err)
	}
	if r.File != filepath.Join("..", "..", "package-lock.json") {
		t.Errorf("File = %s", r.File)
	}
	checkFlags(t, find(t, r, "debug", "4.3.4"), true, false, "^4.3.4")
	es := find(t, r, "esbuild", "0.20.2")
	checkFlags(t, es, true, false, "^0.20.2")
	if !es.Scripts {
		t.Error("esbuild Scripts = false")
	}
	checkParents(t, find(t, r, "ms", "2.1.2"), "debug")
	// lib (a workspace sibling) is followed: ms 2.1.3 comes through it
	ms3 := find(t, r, "ms", "2.1.3")
	checkFlags(t, ms3, false, false, "")
	if has(r, "@mono/lib") || has(r, "typescript") {
		t.Errorf("unexpected packages: %v", r.Packages)
	}
}

func TestPnpmV5(t *testing.T) {
	lock := `lockfileVersion: 5.4

specifiers:
  next: ^13.0.0
  react: ^18.2.0
  typescript: ^4.9.0

dependencies:
  next: 13.0.0_react@18.2.0
  react: 18.2.0

devDependencies:
  typescript: 4.9.5

packages:

  /js-tokens/4.0.0:
    resolution: {integrity: sha512-x}
    dev: false

  /loose-envify/1.4.0:
    resolution: {integrity: sha512-x}
    hasBin: true
    dependencies:
      js-tokens: 4.0.0
    dev: false

  /next/13.0.0_react@18.2.0:
    resolution: {integrity: sha512-x}
    engines: {node: '>=14.6.0'}
    requiresBuild: true
    peerDependencies:
      react: ^18.2.0
    dependencies:
      react: 18.2.0
    dev: false

  /react/18.2.0:
    resolution: {integrity: sha512-x}
    dependencies:
      loose-envify: 1.4.0
    dev: false

  /typescript/4.9.5:
    resolution: {integrity: sha512-x}
    engines: {node: '>=4.2.0'}
    hasBin: true
    dev: true
`
	dir := writeFiles(t, map[string]string{
		"package.json":   `{"name":"x","dependencies":{"next":"^13.0.0","react":"^18.2.0"},"devDependencies":{"typescript":"^4.9.0"}}`,
		"pnpm-lock.yaml": lock,
	})
	r, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	next := find(t, r, "next", "13.0.0")
	checkFlags(t, next, true, false, "^13.0.0")
	if !next.Scripts {
		t.Error("next Scripts = false")
	}
	checkParents(t, find(t, r, "react", "18.2.0"), "next")
	checkParents(t, find(t, r, "js-tokens", "4.0.0"), "loose-envify")
	checkFlags(t, find(t, r, "typescript", "4.9.5"), true, true, "^4.9.0")
}

func TestPnpmSkipsLocalAndEnvDoc(t *testing.T) {
	lock := `---
lockfileVersion: '9.0'

importers:

  configDependencies: {}
---
lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      '@scope/pkg':
        specifier: ^1.0.0
        version: 1.0.0
      local:
        specifier: file:../local
        version: file:../local
      linked:
        specifier: link:../linked
        version: link:../linked

packages:

  '@scope/pkg@1.0.0':
    resolution: {integrity: sha512-x}

  local@file:../local:
    resolution: {directory: ../local, type: directory}

snapshots:

  '@scope/pkg@1.0.0': {}

  local@file:../local: {}
`
	dir := writeFiles(t, map[string]string{"package.json": `{"name":"x"}`, "pnpm-lock.yaml": lock})
	r, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages) != 1 {
		t.Fatalf("packages = %v", r.Packages)
	}
	checkFlags(t, r.Packages[0], true, false, "^1.0.0")
	if r.Packages[0].Name != "@scope/pkg" {
		t.Errorf("name = %s", r.Packages[0].Name)
	}
}

func TestPnpmMissingMember(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"package.json":        `{"name":"root"}`,
		"pnpm-workspace.yaml": "packages:\n  - 'apps/*'\n",
		"pnpm-lock.yaml":      "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n",
		"apps/x/package.json": `{"name":"x"}`,
	})
	_, err := Parse(filepath.Join(dir, "apps", "x"))
	if !errors.Is(err, errNoMember) {
		t.Errorf("err = %v, want errNoMember", err)
	}
}

func TestBunWorkspaceAndNested(t *testing.T) {
	lock := `{
  "lockfileVersion": 1,
  // comment
  "workspaces": {
    "": { "name": "root", "devDependencies": { "typescript": "^5.4.5", }, },
    "apps/web": { "name": "web", "dependencies": { "ui": "workspace:*", "debug": "^4.3.4", }, },
    "packages/ui": { "name": "ui", "dependencies": { "ms": "^2.1.3" } },
  },
  "packages": {
    "debug": ["debug@4.3.4", "", { "dependencies": { "ms": "2.1.2" } }, "sha512-x"],
    "debug/ms": ["ms@2.1.2", "", {}, "sha512-x"], /* nested */
    "ms": ["ms@2.1.3", "", {}, "sha512-x"],
    "typescript": ["typescript@5.4.5", "", { "bin": { "tsc": "bin/tsc" } }, "sha512-x"],
    "ui": ["ui@workspace:packages/ui"],
  }
}`
	dir := writeFiles(t, map[string]string{
		"package.json":          `{"name":"root","workspaces":["apps/*","packages/*"]}`,
		"bun.lock":              lock,
		"apps/web/package.json": `{"name":"web","dependencies":{"ui":"workspace:*","debug":"^4.3.4"}}`,
	})
	r, err := Parse(filepath.Join(dir, "apps", "web"))
	if err != nil {
		t.Fatal(err)
	}
	checkFlags(t, find(t, r, "debug", "4.3.4"), true, false, "^4.3.4")
	checkParents(t, find(t, r, "ms", "2.1.2"), "debug")
	find(t, r, "ms", "2.1.3") // through the ui workspace
	if has(r, "ui") || has(r, "typescript") {
		t.Errorf("unexpected packages %v", r.Packages)
	}
}

func TestDedupMergesParents(t *testing.T) {
	// two npm install locations of the same name@version merge into one Package
	lock := `{"lockfileVersion":3,"packages":{
  "":{"dependencies":{"a":"1.0.0","b":"1.0.0"}},
  "node_modules/a":{"version":"1.0.0","dependencies":{"x":"^1.0.0"}},
  "node_modules/a/node_modules/x":{"version":"1.0.0"},
  "node_modules/b":{"version":"1.0.0","dependencies":{"x":"^1.0.0"}},
  "node_modules/b/node_modules/x":{"version":"1.0.0"},
  "node_modules/x":{"version":"2.0.0"}}}`
	dir := writeFiles(t, map[string]string{"package.json": `{"name":"x","dependencies":{"a":"1.0.0","b":"1.0.0"}}`, "package-lock.json": lock})
	r, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := versionsOf(r, "x"); !reflect.DeepEqual(got, []string{"1.0.0", "2.0.0"}) {
		t.Errorf("x versions = %v", got)
	}
	checkParents(t, find(t, r, "x", "1.0.0"), "a", "b")
	if p := find(t, r, "x", "2.0.0"); len(p.Parents) != 0 || p.Direct || p.Dev {
		t.Errorf("x@2 = %+v", p)
	}
}

func TestYAMLSubset(t *testing.T) {
	src := `# comment
a: 1
'b@1.0.0': "two" # trailing
c:
  - x
  - 'y: z'
  - k: v
    k2: v2
d: {integrity: sha512-abc==, tarball: 'https://x/y.tgz'}
e: [1, "two", {f: g}]
"esc": "a\"b\u00e9"
it's: plain
empty:
`
	docs, err := parseYAMLDocs(src)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"a":       "1",
		"b@1.0.0": "two",
		"c":       []any{"x", "y: z", map[string]any{"k": "v", "k2": "v2"}},
		"d":       map[string]any{"integrity": "sha512-abc==", "tarball": "https://x/y.tgz"},
		"e":       []any{"1", "two", map[string]any{"f": "g"}},
		"esc":     "a\"b\u00e9",
		"it's":    "plain",
		"empty":   nil,
	}
	if len(docs) != 1 || !reflect.DeepEqual(docs[0], want) {
		t.Errorf("got %#v", docs)
	}
	if _, err := parseYAMLDocs("a:\n  b: 1\n c: 2\n"); err == nil {
		t.Error("bad indentation accepted")
	}
}

func TestJSONC(t *testing.T) {
	in := `{"a": "x // not a comment", /* c */ "b": [1, 2, ], // c
"c": {"d": "e\"f,}", }, }`
	got := string(jsoncToJSON([]byte(in)))
	if strings.Contains(got, ", ]") || strings.Contains(got, ", }") || !strings.Contains(got, `"x // not a comment"`) || !strings.Contains(got, `"e\"f,}"`) {
		t.Errorf("jsonc = %s", got)
	}
}
