// Package lockfile reads npm, pnpm, yarn (v1 and berry) and bun lockfiles
// into one flat package list, using only the standard library.
package lockfile

// Package is one installed package instance (name@version). The same name can
// appear several times with different versions.
type Package struct {
	Name     string            `json:"name"`
	Version  string            `json:"version"`
	Direct   bool              `json:"direct"`             // declared in the root package.json (or a workspace's)
	Dev      bool              `json:"dev"`                // only reachable through devDependencies
	Range    string            `json:"range,omitempty"`    // declared range, for direct packages
	Requires map[string]string `json:"requires,omitempty"` // its own dependencies: name -> range
	Parents  []string          `json:"parents,omitempty"`  // names of packages that depend on it ("" never; direct packages may have none)
	Scripts  bool              `json:"scripts,omitempty"`  // lockfile says it has install scripts (npm hasInstallScript, pnpm requiresBuild)
}

// Result is what Parse returns for one project directory.
type Result struct {
	Kind        string    `json:"kind"`    // "npm" | "pnpm" | "yarn" | "yarn-berry" | "bun" | "none"
	File        string    `json:"file"`    // lockfile path relative to the project dir ("" when none)
	Manager     string    `json:"manager"` // "npm" | "pnpm" | "yarn" | "bun" — for printing commands
	Packages    []Package `json:"packages"`
	Approximate bool      `json:"approximate"` // true when versions come from package.json ranges, not a lockfile
}

// Manifest is the subset of package.json DepGate needs.
type Manifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Engines              map[string]string `json:"engines"`
	Workspaces           any               `json:"workspaces"`     // []string or {packages: []string}
	PackageManager       string            `json:"packageManager"` // e.g. "pnpm@9.12.0"
	Overrides            map[string]any    `json:"overrides"`
	Pnpm                 *struct {
		Overrides map[string]string `json:"overrides"`
	} `json:"pnpm"`
	Resolutions map[string]string `json:"resolutions"`
}

// CONTRACT (implemented in parse.go and per-format files):
//
//	func ReadManifest(dir string) (*Manifest, error)
//	func Detect(dir string) (kind, file string)          // preference: pnpm-lock.yaml, package-lock.json, npm-shrinkwrap.json, yarn.lock, bun.lock; "none",""
//	func Parse(dir string) (*Result, error)              // detects + parses; with no lockfile: reads node_modules/*/package.json if present
//	                                                     // (Approximate=false), else MinVersion of each direct range (Approximate=true)
