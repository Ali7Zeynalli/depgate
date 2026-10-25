package decide

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/semver"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
)

var (
	exactRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)
	lineRe  = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?$`)
	lineLTS = regexp.MustCompile(`(?i)^lts/(\w+)$`)
)

// parseNodeSpec turns "node:22.20.0-bookworm-slim", "22", "v22.20.0", "lts/jod" into (exact, line, tagSuffix).
func parseNodeSpec(raw string, nd *sources.NodeData) (exact string, line int, suffix string) {
	s := strings.TrimSpace(raw)
	docker := strings.HasPrefix(s, "node:")
	s = strings.TrimPrefix(s, "node:")
	if docker {
		if i := strings.Index(s, "-"); i >= 0 {
			suffix, s = s[i:], s[:i] // "-bookworm-slim", "-alpine3.20"
		}
		switch s {
		case "lts", "current", "latest", "":
			if nd != nil {
				for _, r := range nd.Releases {
					if s == "lts" && r.Codename() == "" {
						continue
					}
					v, l := nodeVer(r.Version)
					_ = v
					return "", l, suffix
				}
			}
			return "", 0, suffix
		}
	}
	if m := exactRe.FindStringSubmatch(s); m != nil {
		l, _ := strconv.Atoi(m[1])
		return fmt.Sprintf("%s.%s.%s", m[1], m[2], m[3]), l, suffix
	}
	if m := lineRe.FindStringSubmatch(s); m != nil {
		l, _ := strconv.Atoi(m[1])
		return "", l, suffix
	}
	if m := lineLTS.FindStringSubmatch(s); m != nil && nd != nil {
		for _, r := range nd.Releases {
			if strings.EqualFold(r.Codename(), m[1]) {
				_, l := nodeVer(r.Version)
				return "", l, suffix
			}
		}
	}
	return "", 0, suffix
}

func nodeVer(v string) (string, int) {
	v = strings.TrimPrefix(v, "v")
	l, _ := strconv.Atoi(strings.SplitN(v, ".", 2)[0])
	return v, l
}

// EvalNode applies the Node.js runtime rules.
func EvalNode(srcs []report.NodeSource, nd *sources.NodeData, now time.Time) *report.Node {
	if len(srcs) == 0 {
		return nil
	}
	n := &report.Node{Sources: srcs, Need: report.NeedNone, Impact: report.ImpactNo}
	lines := map[int]bool{}
	var suffix, dockerSrc string
	for _, s := range srcs {
		if s.File == "package.json engines" {
			continue // a range, not a pin
		}
		ex, l, suf := parseNodeSpec(s.Value, nd)
		if l > 0 {
			lines[l] = true
		}
		if ex != "" && n.Version == "" {
			n.Version = ex
		}
		if strings.HasPrefix(s.Value, "node:") && dockerSrc == "" {
			dockerSrc, suffix = s.File, suf
		}
		if l > 0 && n.Line == 0 {
			n.Line = l
		}
	}
	if n.Version != "" {
		_, n.Line = nodeVer(n.Version)
	}
	n.Mismatch = len(lines) > 1
	if n.Line == 0 {
		// only an engines range: nothing pinned
		n.Why = append(n.Why, "Node versiyası heç yerdə sabitlənməyib (yalnız engines aralığı)")
		n.Need = report.NeedOptional
		return n
	}
	if nd == nil {
		n.Why = append(n.Why, "Node.js buraxılış məlumatı yüklənmədi (offline?)")
		n.Impact = report.ImpactUnknown
		return n
	}
	// releases of this line, newest first (index.json is newest first already)
	var inLine []sources.NodeRelease
	for _, r := range nd.Releases {
		if _, l := nodeVer(r.Version); l == n.Line {
			inLine = append(inLine, r)
		}
	}
	if len(inLine) > 0 {
		n.LatestInLine, _ = nodeVer(inLine[0].Version)
		n.LTS = inLine[0].Codename()
	}
	if n.Version != "" {
		cur, err := semver.Parse(n.Version)
		if err == nil {
			for _, r := range inLine {
				v, _ := nodeVer(r.Version)
				rv, err := semver.Parse(v)
				if err != nil || !semver.Less(cur, rv) {
					continue
				}
				if r.Security {
					n.SecurityFix = v // newest security release above current (list is newest first)
					break
				}
			}
		}
	} else {
		n.Why = append(n.Why, fmt.Sprintf("Yalnız xətt göstərilib (node %d): hər build-də fərqli versiya düşə bilər; dəqiq versiyanı sabitlə", n.Line))
	}

	// EOL
	if sch, ok := nd.Schedule[n.Line]; ok && sch.End != "" {
		n.EOL = sch.End
		if end, err := time.Parse("2006-01-02", sch.End); err == nil {
			d := int(end.Sub(now).Hours() / 24)
			n.DaysToEOL = &d
		}
	}
	n.NextLTS = nextLTS(nd, n.Line, now)

	cmdVer := n.LatestInLine
	switch {
	case n.DaysToEOL != nil && *n.DaysToEOL < 0:
		n.Need, n.Impact = report.NeedNow, report.ImpactYes
		n.Why = append(n.Why, fmt.Sprintf("Node %d xəttinin dəstəyi %s tarixində bitib — təhlükəsizlik düzəlişləri artıq çıxmır", n.Line, n.EOL))
		if n.NextLTS > 0 {
			n.Why = append(n.Why, fmt.Sprintf("Node %d LTS-ə keç: major dəyişiklikdir, build və testləri yoxla", n.NextLTS))
			cmdVer = latestOfLine(nd, n.NextLTS)
		}
	case n.SecurityFix != "":
		n.Need, n.Impact = report.NeedNow, report.ImpactNo
		n.Why = append(n.Why, fmt.Sprintf("%s → %s: xəttdə təhlükəsizlik relizi var (eyni major, kod dəyişmir)", n.Version, n.LatestInLine))
	case n.DaysToEOL != nil && *n.DaysToEOL <= 90:
		n.Need, n.Impact = report.NeedSoon, report.ImpactYes
		n.Why = append(n.Why, fmt.Sprintf("Node %d xəttinin dəstəyi %d gün sonra bitir (%s)", n.Line, *n.DaysToEOL, n.EOL))
		if n.NextLTS > 0 {
			cmdVer = latestOfLine(nd, n.NextLTS)
		}
	case n.Version != "" && n.LatestInLine != "" && n.Version != n.LatestInLine:
		n.Need = report.NeedOptional
		n.Why = append(n.Why, fmt.Sprintf("Xəttdə daha yeni versiya var: %s", n.LatestInLine))
	case n.Version == "":
		n.Need = report.NeedOptional
	default:
		n.Why = append(n.Why, "Xəttin ən son versiyasıdır")
	}
	if n.Line%2 == 1 {
		n.Why = append(n.Why, fmt.Sprintf("Node %d tək nömrəli xətdir — LTS olmur, production üçün tövsiyə edilmir", n.Line))
		if n.Need == report.NeedNone || n.Need == report.NeedOptional {
			n.Need = report.NeedSoon
		}
	}
	if n.Mismatch {
		ls := make([]int, 0, len(lines))
		for l := range lines {
			ls = append(ls, l)
		}
		sort.Ints(ls)
		n.Why = append(n.Why, fmt.Sprintf("Fərqli fayllar fərqli xətlər göstərir: %v", ls))
	}
	if cmdVer != "" && n.Need != report.NeedNone {
		if dockerSrc != "" {
			if suffix == "" {
				suffix = "-bookworm-slim"
			}
			n.Command = "FROM node:" + cmdVer + suffix + "   # " + dockerSrc
		} else {
			n.Command = "nvm install " + cmdVer + " && echo " + cmdVer + " > .nvmrc"
		}
	}
	return n
}

func latestOfLine(nd *sources.NodeData, line int) string {
	for _, r := range nd.Releases {
		if v, l := nodeVer(r.Version); l == line {
			return v
		}
	}
	return ""
}

// nextLTS returns the newest even line that is LTS and not EOL, above line.
func nextLTS(nd *sources.NodeData, line int, now time.Time) int {
	best := 0
	for l, s := range nd.Schedule {
		if l <= line || l%2 == 1 || s.LTS == "" {
			continue
		}
		lts, err1 := time.Parse("2006-01-02", s.LTS)
		end, err2 := time.Parse("2006-01-02", s.End)
		if err1 != nil || err2 != nil || now.Before(lts) || now.After(end) {
			continue
		}
		if best == 0 || l < best { // the closest active LTS is the smallest jump
			best = l
		}
	}
	return best
}
