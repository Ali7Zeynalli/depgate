package history

import (
	"sort"

	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/semver"
)

// keepChanges caps the changes stored per scan (a fresh install can move hundreds).
const keepChanges = 300

// DiffVersions tells which package versions changed from old to cur: updated
// (up), moved to an older version (down), added and removed. nil when nothing changed.
func DiffVersions(old, cur []report.Version) *PkgDiff {
	type side struct {
		vers        map[string]bool
		direct, dev bool
	}
	index := func(vs []report.Version) map[string]*side {
		m := map[string]*side{}
		for _, v := range vs {
			s := m[v.Name]
			if s == nil {
				s = &side{vers: map[string]bool{}, dev: true}
				m[v.Name] = s
			}
			s.vers[v.Version] = true
			s.direct = s.direct || v.Direct
			s.dev = s.dev && v.Dev
		}
		return m
	}
	a, b := index(old), index(cur)
	var out []PkgChange
	names := map[string]bool{}
	for n := range a {
		names[n] = true
	}
	for n := range b {
		names[n] = true
	}
	for n := range names {
		o, c := a[n], b[n]
		info := c
		if info == nil {
			info = o
		}
		ch := PkgChange{Name: n, Direct: info.direct, Dev: info.dev}
		var gone, came []string
		if o != nil {
			for v := range o.vers {
				if c == nil || !c.vers[v] {
					gone = append(gone, v)
				}
			}
		}
		if c != nil {
			for v := range c.vers {
				if o == nil || !o.vers[v] {
					came = append(came, v)
				}
			}
		}
		sort.Strings(gone)
		sort.Strings(came)
		if len(gone) == 1 && len(came) == 1 {
			ch.From, ch.To, ch.Kind = gone[0], came[0], "up"
			if older(came[0], gone[0]) {
				ch.Kind = "down"
			}
			out = append(out, ch)
			continue
		}
		for _, v := range gone {
			x := ch
			x.Kind, x.From = "remove", v
			out = append(out, x)
		}
		for _, v := range came {
			x := ch
			x.Kind, x.To = "add", v
			out = append(out, x)
		}
	}
	if len(out) == 0 {
		return nil
	}
	rank := map[string]int{"down": 0, "add": 1, "remove": 2, "up": 3}
	sort.Slice(out, func(i, j int) bool {
		x, y := out[i], out[j]
		if x.Direct != y.Direct {
			return x.Direct
		}
		if rank[x.Kind] != rank[y.Kind] {
			return rank[x.Kind] < rank[y.Kind]
		}
		if x.Name != y.Name {
			return x.Name < y.Name
		}
		return x.From+x.To < y.From+y.To
	})
	d := &PkgDiff{Changes: out}
	if len(out) > keepChanges {
		d.Changes, d.More = out[:keepChanges], len(out)-keepChanges
	}
	return d
}

func older(a, b string) bool {
	x, err1 := semver.Parse(a)
	y, err2 := semver.Parse(b)
	return err1 == nil && err2 == nil && semver.Compare(x, y) < 0
}
