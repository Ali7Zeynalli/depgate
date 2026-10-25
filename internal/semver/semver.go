// Package semver implements npm-compatible semantic versions and ranges
// (https://github.com/npm/node-semver), using only the standard library.
//
// CONTRACT (other packages depend on these exact signatures):
//
//	type Version struct { Major, Minor, Patch int; Pre []string; Build string; Raw string }
//	func Parse(s string) (Version, error)          // strict: "1.2.3", "1.2.3-beta.1", leading "v"/"=" allowed
//	func MustParse(s string) Version
//	func (v Version) String() string               // canonical "1.2.3-beta.1" (no build)
//	func (v Version) IsPrerelease() bool
//	func Compare(a, b Version) int                 // -1, 0, 1; semver 2.0 precedence, build ignored
//	func Less(a, b Version) bool
//	func Diff(from, to Version) string             // "major"|"minor"|"patch"|"prerelease"|"none" (npm semver.diff semantics, but 0.x: a minor bump counts as "major", 0.0.x patch bump counts as "major")
//
//	type Range struct { ... }                      // opaque
//	func ParseRange(s string) (Range, error)       // "^1.2.3", "~1.2", "1.x", "*", "", ">=1 <2", "1 - 2", "a || b", "latest" → error
//	func (r Range) Contains(v Version) bool        // npm satisfies() with includePrerelease=false semantics
//	func (r Range) String() string
//	func MinVersion(r Range) (Version, bool)       // npm semver.minVersion
//	func MaxSatisfying(vs []Version, r Range) (Version, bool)
//	func MinSatisfying(vs []Version, r Range) (Version, bool)
package semver
