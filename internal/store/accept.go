package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/report"
)

// Acceptance is a risk the user accepted for one finding of one project, until a date.
// The finding key contains the version, so it ends by itself when the version changes.
type Acceptance struct {
	Dir    string    `json:"dir"`
	File   string    `json:"-"` // from a depgate-accept.json
	Key    string    `json:"key"`
	Pkg    string    `json:"pkg,omitempty"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
	Until  time.Time `json:"until"`
}

var (
	ErrNoReason = errors.New("a reason is required")
	ErrMalware  = errors.New("malware cannot be accepted")
)

func (s *Store) acceptPath() string { return filepath.Join(s.Dir, "accepted.json") }

func (s *Store) acceptances() []Acceptance {
	var as []Acceptance
	if b, err := os.ReadFile(s.acceptPath()); err == nil {
		_ = json.Unmarshal(b, &as)
	}
	return as
}

// Acceptances returns the accepted risks of the projects under dir ("" = all).
func (s *Store) Acceptances(dir string) []Acceptance {
	s.amu.Lock()
	defer s.amu.Unlock()
	var out []Acceptance
	for _, a := range s.acceptances() {
		if dir == "" || Within(a.Dir, dir) {
			out = append(out, a)
		}
	}
	return out
}

// Accept records that the user accepts the finding key in dirs until until.
func (s *Store) Accept(dirs []string, key, reason string, until time.Time) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return ErrNoReason
	}
	if strings.HasPrefix(key, "malware:") {
		return ErrMalware
	}
	if len(reason) > 500 {
		reason = reason[:500]
	}
	s.amu.Lock()
	defer s.amu.Unlock()
	as := s.acceptances()
	now := time.Now().UTC()
	for _, d := range dirs {
		d = filepath.Clean(d)
		pkg := ""
		if r := s.rawReport(d); r != nil {
			found := false
			for _, f := range r.Findings {
				if f.Key == key {
					if f.Kind == "malware" {
						return ErrMalware
					}
					found, pkg = true, f.Pkg
				}
			}
			if !found {
				continue
			}
		}
		as = drop(as, d, key)
		as = append(as, Acceptance{Dir: d, Key: key, Pkg: pkg, Reason: reason, At: now, Until: until.UTC()})
	}
	return s.saveAcceptances(as)
}

// Unaccept removes the acceptance of key in dirs.
func (s *Store) Unaccept(dirs []string, key string) error {
	s.amu.Lock()
	defer s.amu.Unlock()
	as := s.acceptances()
	for _, d := range dirs {
		as = drop(as, filepath.Clean(d), key)
	}
	return s.saveAcceptances(as)
}

func drop(as []Acceptance, dir, key string) []Acceptance {
	out := as[:0]
	for _, a := range as {
		if a.Dir != dir || a.Key != key {
			out = append(out, a)
		}
	}
	return out
}

func (s *Store) saveAcceptances(as []Acceptance) error {
	// expired more than a year ago: nobody needs them any more
	keep := []Acceptance{}
	for _, a := range as {
		if time.Since(a.Until) < 365*24*time.Hour {
			keep = append(keep, a)
		}
	}
	b, err := json.MarshalIndent(keep, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.acceptPath(), b)
}

// applyAccepted moves accepted findings into GroupAccepted (and back when an
// acceptance was removed or has ended), then recounts the summary. Idempotent.
// Acceptances come from this computer (accepted.json) and from a
// depgate-accept.json in the project or a parent folder.
func (s *Store) applyAccepted(p *report.Project) {
	if p == nil {
		return
	}
	s.amu.Lock()
	as := s.acceptances()
	s.amu.Unlock()
	ApplyAcceptances(p, append(FileAcceptances(p.Dir), as...))
}

// ApplyAcceptances applies the acceptances made for p.Dir (later entries win).
func ApplyAcceptances(p *report.Project, as []Acceptance) {
	now := time.Now()
	by := map[string]Acceptance{}
	for _, a := range as {
		if a.Dir == filepath.Clean(p.Dir) && now.Before(a.Until) {
			by[a.Key] = a
		}
	}
	changed := false
	for i := range p.Findings {
		f := &p.Findings[i]
		if f.Accepted != nil {
			f.Group, f.Accepted, changed = f.Accepted.Group, nil, true
		}
		if a, ok := by[f.Key]; ok && f.Kind != "malware" {
			f.Accepted = &report.Accepted{Reason: a.Reason, At: a.At, Until: a.Until, Group: f.Group, File: a.File}
			f.Group, changed = report.GroupAccepted, true
		}
	}
	if changed {
		p.Summary = report.Summarize(p.Findings)
	}
}

// LocalAcceptances reads the acceptances saved on this computer without
// creating anything (for one-shot runs such as --ci).
func LocalAcceptances(dataDir string) []Acceptance {
	var as []Acceptance
	if b, err := os.ReadFile(filepath.Join(dataDir, "accepted.json")); err == nil {
		_ = json.Unmarshal(b, &as)
	}
	return as
}
