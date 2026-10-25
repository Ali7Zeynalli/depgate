package semver

import (
	"fmt"
	"strings"
)

// comparator is a single primitive constraint such as ">=1.2.3". An "any"
// comparator matches every version (it comes from "*", "x" or "").
type comparator struct {
	op  string // "", "=", "<", "<=", ">", ">="
	v   Version
	any bool
}

func (c comparator) String() string {
	if c.any {
		return "*"
	}
	op := c.op
	if op == "=" {
		op = ""
	}
	return op + c.v.String()
}

func (c comparator) test(v Version) bool {
	if c.any {
		return true
	}
	cmp := Compare(v, c.v)
	switch c.op {
	case "", "=":
		return cmp == 0
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	}
	return false
}

// Range is a parsed npm version range: a union ("||") of comparator sets,
// each set being an intersection (space-separated) of comparators.
type Range struct {
	raw  string
	sets [][]comparator
}

// String returns the normalised range, e.g. "^1.2.3" -> ">=1.2.3 <2.0.0-0".
func (r Range) String() string {
	parts := make([]string, len(r.sets))
	for i, set := range r.sets {
		cs := make([]string, len(set))
		for j, c := range set {
			cs[j] = c.String()
		}
		parts[i] = strings.Join(cs, " ")
	}
	return strings.Join(parts, " || ")
}

// ParseRange parses an npm range. Dist-tags ("latest") and non-semver
// specifiers ("workspace:*", "npm:x@^1", "file:", git/github/URLs,
// "link:", "catalog:") return an error.
func ParseRange(s string) (Range, error) {
	raw := strings.TrimSpace(s)
	if strings.ContainsAny(raw, ":/@") {
		return Range{}, fmt.Errorf("semver: %q is not a semver range (protocol, alias, path or URL spec)", s)
	}
	r := Range{raw: raw}
	for _, part := range strings.Split(raw, "||") {
		set, err := parseSet(strings.TrimSpace(part))
		if err != nil {
			return Range{}, fmt.Errorf("semver: invalid range %q: %w", s, err)
		}
		r.sets = append(r.sets, set)
	}
	return r, nil
}

func isOpOnly(f string) bool {
	switch f {
	case "~", "~>", "^", "<", "<=", ">", ">=", "=":
		return true
	}
	return false
}

func parseSet(s string) ([]comparator, error) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return []comparator{{any: true}}, nil
	}
	// Hyphen range: exactly "A - B".
	if len(fields) == 3 && fields[1] == "-" {
		return hyphenRange(fields[0], fields[2])
	}
	// Join operators separated from their version by whitespace.
	var toks []string
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if isOpOnly(f) {
			if i+1 >= len(fields) {
				return nil, fmt.Errorf("operator %q without version", f)
			}
			f += fields[i+1]
			i++
		}
		toks = append(toks, f)
	}
	var out []comparator
	for _, t := range toks {
		cs, err := parseToken(t)
		if err != nil {
			return nil, err
		}
		out = append(out, cs...)
	}
	// Like node-semver, drop "any" comparators when others are present.
	if len(out) > 1 {
		filtered := out[:0:0]
		for _, c := range out {
			if !c.any {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) == 0 {
			filtered = []comparator{{any: true}}
		}
		out = filtered
	}
	return out, nil
}

// partial is a possibly incomplete version like "1", "1.x", "1.2.*",
// "1.2.3-beta". Missing or wildcard parts have x set.
type partial struct {
	major, minor, patch    int
	xMajor, xMinor, xPatch bool
	pre                    []string
}

func isXPart(p string) bool { return p == "x" || p == "X" || p == "*" }

func parsePartial(s string) (partial, error) {
	in := strings.TrimPrefix(strings.TrimPrefix(s, "="), "v")
	var p partial
	if in == "" {
		return p, fmt.Errorf("empty version in %q", s)
	}
	core, build, hasBuild := strings.Cut(in, "+")
	if hasBuild {
		if err := validateIdents(build, false); err != nil {
			return p, fmt.Errorf("invalid build in %q: %w", s, err)
		}
	}
	main, pre, hasPre := strings.Cut(core, "-")
	parts := strings.Split(main, ".")
	if len(parts) > 3 {
		return p, fmt.Errorf("invalid version %q", s)
	}
	if hasPre && len(parts) != 3 {
		return p, fmt.Errorf("prerelease requires full version in %q", s)
	}
	if hasPre {
		if err := validateIdents(pre, true); err != nil {
			return p, fmt.Errorf("invalid prerelease in %q: %w", s, err)
		}
		p.pre = strings.Split(pre, ".")
	}
	nums := [3]*int{&p.major, &p.minor, &p.patch}
	xs := [3]*bool{&p.xMajor, &p.xMinor, &p.xPatch}
	for i := 0; i < 3; i++ {
		if i >= len(parts) || isXPart(parts[i]) {
			*xs[i] = true
			continue
		}
		n, err := parseNumeric(parts[i])
		if err != nil {
			return p, fmt.Errorf("invalid version %q: %w", s, err)
		}
		*nums[i] = n
	}
	// A wildcard makes all lower parts wildcards too ("1.x.3" == "1.x").
	if p.xMajor {
		p.xMinor = true
	}
	if p.xMinor {
		p.xPatch = true
	}
	if p.xPatch {
		p.pre = nil
	}
	return p, nil
}

func ver(major, minor, patch int, pre ...string) Version {
	v := Version{Major: major, Minor: minor, Patch: patch}
	if len(pre) > 0 {
		v.Pre = append([]string(nil), pre...)
	}
	return v
}

func cmp(op string, v Version) comparator { return comparator{op: op, v: v} }

func splitOp(t string) (string, string) {
	for _, op := range []string{"~>", "~", "^", ">=", "<=", ">", "<", "="} {
		if strings.HasPrefix(t, op) {
			return op, t[len(op):]
		}
	}
	return "", t
}

func parseToken(t string) ([]comparator, error) {
	op, rest := splitOp(t)
	p, err := parsePartial(rest)
	if err != nil {
		return nil, err
	}
	switch op {
	case "^":
		return caret(p), nil
	case "~", "~>":
		return tilde(p), nil
	}
	return xrange(op, p), nil
}

func caret(p partial) []comparator {
	M, m, pt := p.major, p.minor, p.patch
	switch {
	case p.xMajor:
		return []comparator{{any: true}}
	case p.xMinor:
		return []comparator{cmp(">=", ver(M, 0, 0)), cmp("<", ver(M+1, 0, 0, "0"))}
	case p.xPatch:
		if M == 0 {
			return []comparator{cmp(">=", ver(M, m, 0)), cmp("<", ver(M, m+1, 0, "0"))}
		}
		return []comparator{cmp(">=", ver(M, m, 0)), cmp("<", ver(M+1, 0, 0, "0"))}
	}
	lo := cmp(">=", ver(M, m, pt, p.pre...))
	switch {
	case M == 0 && m == 0:
		return []comparator{lo, cmp("<", ver(M, m, pt+1, "0"))}
	case M == 0:
		return []comparator{lo, cmp("<", ver(M, m+1, 0, "0"))}
	}
	return []comparator{lo, cmp("<", ver(M+1, 0, 0, "0"))}
}

func tilde(p partial) []comparator {
	M, m, pt := p.major, p.minor, p.patch
	switch {
	case p.xMajor:
		return []comparator{{any: true}}
	case p.xMinor:
		return []comparator{cmp(">=", ver(M, 0, 0)), cmp("<", ver(M+1, 0, 0, "0"))}
	case p.xPatch:
		return []comparator{cmp(">=", ver(M, m, 0)), cmp("<", ver(M, m+1, 0, "0"))}
	}
	return []comparator{cmp(">=", ver(M, m, pt, p.pre...)), cmp("<", ver(M, m+1, 0, "0"))}
}

func xrange(op string, p partial) []comparator {
	anyX := p.xPatch
	if op == "=" && anyX {
		op = ""
	}
	M, m := p.major, p.minor
	switch {
	case p.xMajor:
		if op == ">" || op == "<" {
			// Nothing can satisfy ">*" or "<*".
			return []comparator{cmp("<", ver(0, 0, 0, "0"))}
		}
		return []comparator{{any: true}}
	case op != "" && anyX:
		if p.xMinor {
			m = 0
		}
		pt := 0
		var pre []string
		switch op {
		case ">":
			op = ">="
			if p.xMinor {
				M, m = M+1, 0
			} else {
				m++
			}
		case "<=":
			op = "<"
			if p.xMinor {
				M++
			} else {
				m++
			}
		}
		if op == "<" {
			pre = []string{"0"}
		}
		return []comparator{cmp(op, ver(M, m, pt, pre...))}
	case p.xMinor:
		return []comparator{cmp(">=", ver(M, 0, 0)), cmp("<", ver(M+1, 0, 0, "0"))}
	case p.xPatch:
		return []comparator{cmp(">=", ver(M, m, 0)), cmp("<", ver(M, m+1, 0, "0"))}
	}
	return []comparator{cmp(op, ver(M, m, p.patch, p.pre...))}
}

func hyphenRange(from, to string) ([]comparator, error) {
	f, err := parsePartial(from)
	if err != nil {
		return nil, err
	}
	t, err := parsePartial(to)
	if err != nil {
		return nil, err
	}
	var out []comparator
	switch {
	case f.xMajor:
	case f.xMinor:
		out = append(out, cmp(">=", ver(f.major, 0, 0)))
	case f.xPatch:
		out = append(out, cmp(">=", ver(f.major, f.minor, 0)))
	default:
		out = append(out, cmp(">=", ver(f.major, f.minor, f.patch, f.pre...)))
	}
	switch {
	case t.xMajor:
	case t.xMinor:
		out = append(out, cmp("<", ver(t.major+1, 0, 0, "0")))
	case t.xPatch:
		out = append(out, cmp("<", ver(t.major, t.minor+1, 0, "0")))
	default:
		out = append(out, cmp("<=", ver(t.major, t.minor, t.patch, t.pre...)))
	}
	if len(out) == 0 {
		out = []comparator{{any: true}}
	}
	return out, nil
}

func testSet(set []comparator, v Version) bool {
	for _, c := range set {
		if !c.test(v) {
			return false
		}
	}
	if !v.IsPrerelease() {
		return true
	}
	// includePrerelease=false: a prerelease only matches if some comparator
	// in the set is a prerelease on the same [major, minor, patch] tuple.
	for _, c := range set {
		if c.any || !c.v.IsPrerelease() {
			continue
		}
		if compareMain(c.v, v) == 0 {
			return true
		}
	}
	return false
}

// Contains reports whether v satisfies r (npm satisfies(), includePrerelease=false).
func (r Range) Contains(v Version) bool {
	for _, set := range r.sets {
		if testSet(set, v) {
			return true
		}
	}
	return false
}

// ContainsAll is Contains with includePrerelease=true: prereleases match by
// plain ordering. Advisory ranges use it so 2.0.0-beta.1 is not skipped.
func (r Range) ContainsAll(v Version) bool {
	for _, set := range r.sets {
		ok := true
		for _, c := range set {
			if !c.test(v) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// MinVersion returns the lowest version that can satisfy r, following
// npm's semver.minVersion algorithm.
func MinVersion(r Range) (Version, bool) {
	if v := ver(0, 0, 0); r.Contains(v) {
		return v, true
	}
	if v := ver(0, 0, 0, "0"); r.Contains(v) {
		return v, true
	}
	var minver *Version
	for _, set := range r.sets {
		var setMin *Version
		for _, c := range set {
			if c.any {
				continue
			}
			cv := ver(c.v.Major, c.v.Minor, c.v.Patch, c.v.Pre...)
			switch c.op {
			case ">":
				if cv.IsPrerelease() {
					cv.Pre = append(cv.Pre, "0")
				} else {
					cv.Patch++
				}
				fallthrough
			case "", "=", ">=":
				if setMin == nil || Compare(cv, *setMin) > 0 {
					c2 := cv
					setMin = &c2
				}
			}
		}
		if setMin != nil && (minver == nil || Compare(*minver, *setMin) > 0) {
			minver = setMin
		}
	}
	if minver != nil && r.Contains(*minver) {
		v := *minver
		v.Raw = v.String()
		return v, true
	}
	return Version{}, false
}

func pick(vs []Version, r Range, better func(a, b Version) bool) (Version, bool) {
	var best Version
	found := false
	for _, v := range vs {
		if !r.Contains(v) {
			continue
		}
		if !found || better(v, best) {
			best, found = v, true
		}
	}
	return best, found
}

// MaxSatisfying returns the highest version in vs that satisfies r.
func MaxSatisfying(vs []Version, r Range) (Version, bool) {
	return pick(vs, r, func(a, b Version) bool { return Compare(a, b) > 0 })
}

// MinSatisfying returns the lowest version in vs that satisfies r.
func MinSatisfying(vs []Version, r Range) (Version, bool) {
	return pick(vs, r, func(a, b Version) bool { return Compare(a, b) < 0 })
}
