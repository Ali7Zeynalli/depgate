package semver

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a parsed semantic version. Build metadata is kept in Build but
// ignored for precedence. Raw holds the original (trimmed) input.
type Version struct {
	Major, Minor, Patch int
	Pre                 []string
	Build               string
	Raw                 string
}

// Parse parses a strict semver 2.0 version. Surrounding whitespace and a
// single leading "=" and/or "v" are accepted ("v1.2.3", "=1.2.3", "=v1.2.3").
func Parse(s string) (Version, error) {
	raw := strings.TrimSpace(s)
	in := raw
	in = strings.TrimPrefix(in, "=")
	in = strings.TrimPrefix(in, "v")
	if in == "" {
		return Version{}, fmt.Errorf("semver: invalid version %q", s)
	}

	core, build, hasBuild := strings.Cut(in, "+")
	if hasBuild {
		if err := validateIdents(build, false); err != nil {
			return Version{}, fmt.Errorf("semver: invalid build metadata in %q: %w", s, err)
		}
	}
	main, pre, hasPre := strings.Cut(core, "-")
	var preIDs []string
	if hasPre {
		if err := validateIdents(pre, true); err != nil {
			return Version{}, fmt.Errorf("semver: invalid prerelease in %q: %w", s, err)
		}
		preIDs = strings.Split(pre, ".")
	}

	parts := strings.Split(main, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("semver: invalid version %q: want MAJOR.MINOR.PATCH", s)
	}
	var nums [3]int
	for i, p := range parts {
		n, err := parseNumeric(p)
		if err != nil {
			return Version{}, fmt.Errorf("semver: invalid version %q: %w", s, err)
		}
		nums[i] = n
	}
	return Version{Major: nums[0], Minor: nums[1], Patch: nums[2], Pre: preIDs, Build: build, Raw: raw}, nil
}

// MustParse is like Parse but panics on error.
func MustParse(s string) Version {
	v, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return v
}

// parseNumeric parses a numeric identifier: digits only, no leading zeros.
func parseNumeric(p string) (int, error) {
	if p == "" {
		return 0, fmt.Errorf("empty numeric identifier")
	}
	if !isDigits(p) {
		return 0, fmt.Errorf("non-numeric identifier %q", p)
	}
	if len(p) > 1 && p[0] == '0' {
		return 0, fmt.Errorf("numeric identifier %q has leading zero", p)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return 0, fmt.Errorf("numeric identifier %q out of range", p)
	}
	return n, nil
}

// validateIdents validates a dot-separated list of identifiers. For
// prerelease identifiers, numeric ones may not have leading zeros.
func validateIdents(s string, pre bool) error {
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return fmt.Errorf("empty identifier")
		}
		for i := 0; i < len(id); i++ {
			c := id[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
				return fmt.Errorf("invalid character %q in identifier %q", c, id)
			}
		}
		if pre && isDigits(id) && len(id) > 1 && id[0] == '0' {
			return fmt.Errorf("numeric identifier %q has leading zero", id)
		}
	}
	return nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// String returns the canonical form "MAJOR.MINOR.PATCH[-PRE]" (no build).
func (v Version) String() string {
	var b strings.Builder
	b.WriteString(strconv.Itoa(v.Major))
	b.WriteByte('.')
	b.WriteString(strconv.Itoa(v.Minor))
	b.WriteByte('.')
	b.WriteString(strconv.Itoa(v.Patch))
	if len(v.Pre) > 0 {
		b.WriteByte('-')
		b.WriteString(strings.Join(v.Pre, "."))
	}
	return b.String()
}

// IsPrerelease reports whether v has prerelease identifiers.
func (v Version) IsPrerelease() bool { return len(v.Pre) > 0 }

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func compareMain(a, b Version) int {
	if c := cmpInt(a.Major, b.Major); c != 0 {
		return c
	}
	if c := cmpInt(a.Minor, b.Minor); c != 0 {
		return c
	}
	return cmpInt(a.Patch, b.Patch)
}

// compareIdent compares two prerelease identifiers per semver 2.0 §11.4.
func compareIdent(a, b string) int {
	an, bn := isDigits(a), isDigits(b)
	switch {
	case an && bn:
		// No leading zeros, so longer means larger; avoids overflow.
		if c := cmpInt(len(a), len(b)); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	case an:
		return -1
	case bn:
		return 1
	}
	return strings.Compare(a, b)
}

func comparePre(a, b Version) int {
	switch {
	case len(a.Pre) == 0 && len(b.Pre) == 0:
		return 0
	case len(a.Pre) == 0:
		return 1
	case len(b.Pre) == 0:
		return -1
	}
	for i := 0; i < len(a.Pre) && i < len(b.Pre); i++ {
		if c := compareIdent(a.Pre[i], b.Pre[i]); c != 0 {
			return c
		}
	}
	return cmpInt(len(a.Pre), len(b.Pre))
}

// Compare returns -1, 0 or 1 by semver 2.0 precedence; build is ignored.
func Compare(a, b Version) int {
	if c := compareMain(a, b); c != 0 {
		return c
	}
	return comparePre(a, b)
}

// Less reports whether a has lower precedence than b.
func Less(a, b Version) bool { return Compare(a, b) < 0 }

// Diff classifies the change from one version to another:
// "major", "minor", "patch", "prerelease" or "none".
//
// Caret semantics are applied so that "major" means "breaking": for 0.x
// versions a minor change is "major", and for 0.0.x a patch change is
// "major". When the major/minor/patch tuple is equal but the versions
// differ, the result is "prerelease".
func Diff(from, to Version) string {
	if Compare(from, to) == 0 {
		return "none"
	}
	if from.Major != to.Major {
		return "major"
	}
	if from.Minor != to.Minor {
		if from.Major == 0 {
			return "major"
		}
		return "minor"
	}
	if from.Patch != to.Patch {
		if from.Major == 0 && from.Minor == 0 {
			return "major"
		}
		return "patch"
	}
	return "prerelease"
}
