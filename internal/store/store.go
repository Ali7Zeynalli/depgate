// Package store remembers the user's projects and their last reports on disk.
//
// Layout under the data directory:
//
//	projects.json        list of projects (dir, name, added time)
//	token                UI access token (stable across restarts)
//	reports/<key>.json   last report.Project of each project
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/report"
)

type Entry struct {
	Dir     string    `json:"dir"`
	Name    string    `json:"name"`
	AddedAt time.Time `json:"addedAt"`
	// Group is the folder the user picked when adding this project (a monorepo
	// root or a folder of projects); the UI nests projects under it.
	Group string `json:"group,omitempty"`
}

type Store struct {
	Dir string

	mu       sync.Mutex
	projects []Entry
}

// Open loads (or creates) the store in dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "reports"), 0o700); err != nil {
		return nil, err
	}
	s := &Store{Dir: dir}
	b, err := os.ReadFile(filepath.Join(dir, "projects.json"))
	switch {
	case err == nil:
		var doc struct {
			Projects []Entry `json:"projects"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, errors.New("cannot read projects.json: " + err.Error())
		}
		s.projects = doc.Projects
	case !os.IsNotExist(err):
		return nil, err
	}
	return s, nil
}

// Token returns the persistent UI token, creating it on first use.
// DEPGATE_TOKEN overrides it (useful for containers and bookmarks).
func (s *Store) Token() (string, error) {
	if t := strings.TrimSpace(os.Getenv("DEPGATE_TOKEN")); t != "" {
		return t, nil
	}
	p := filepath.Join(s.Dir, "token")
	if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) >= 16 {
		return strings.TrimSpace(string(b)), nil
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	t := hex.EncodeToString(buf)
	return t, writeAtomic(p, []byte(t+"\n"))
}

// Projects returns a copy of the list, sorted by name.
func (s *Store) Projects() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Entry(nil), s.projects...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
		}
		return out[i].Dir < out[j].Dir
	})
	return out
}

// Add remembers projects; existing dirs are kept. Returns the dirs that were new.
// Adding an existing project again gives it a group if it had none, or moves it
// to a wider group (an outer folder), never to a narrower one.
func (s *Store) Add(es ...Entry) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	have := map[string]int{}
	for i, p := range s.projects {
		have[p.Dir] = i
	}
	var added []string
	changed := false
	for _, e := range es {
		e.Dir = filepath.Clean(e.Dir)
		if e.Group != "" {
			e.Group = filepath.Clean(e.Group)
		}
		if i, ok := have[e.Dir]; ok {
			old := &s.projects[i]
			if e.Group != "" && e.Group != old.Group && (old.Group == "" || Within(old.Group, e.Group)) {
				old.Group = e.Group
				changed = true
			}
			continue
		}
		if e.AddedAt.IsZero() {
			e.AddedAt = time.Now().UTC()
		}
		if e.Name == "" {
			e.Name = filepath.Base(e.Dir)
		}
		have[e.Dir] = len(s.projects)
		s.projects = append(s.projects, e)
		added = append(added, e.Dir)
	}
	if len(added) == 0 && !changed {
		return nil, nil
	}
	return added, s.saveLocked()
}

// Within reports whether dir is parent itself or inside it.
func Within(dir, parent string) bool {
	if dir == parent {
		return true
	}
	if !strings.HasSuffix(parent, string(filepath.Separator)) {
		parent += string(filepath.Separator)
	}
	return strings.HasPrefix(dir, parent)
}

// Rename updates the display name (from package.json after a scan).
func (s *Store) Rename(dir, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.projects {
		if s.projects[i].Dir == dir && name != "" && s.projects[i].Name != name {
			s.projects[i].Name = name
			_ = s.saveLocked()
		}
	}
}

// Remove forgets a project and its saved report.
func (s *Store) Remove(dir string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.projects[:0]
	for _, p := range s.projects {
		if p.Dir != dir {
			out = append(out, p)
		}
	}
	s.projects = out
	_ = os.Remove(s.reportPath(dir))
	return s.saveLocked()
}

// Has reports whether dir is a remembered project.
func (s *Store) Has(dir string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.projects {
		if p.Dir == dir {
			return true
		}
	}
	return false
}

// SaveReport stores the last scan of one project.
func (s *Store) SaveReport(p *report.Project) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return writeAtomic(s.reportPath(p.Dir), b)
}

// Report loads the last scan of dir (nil when never scanned).
func (s *Store) Report(dir string) *report.Project {
	b, err := os.ReadFile(s.reportPath(dir))
	if err != nil {
		return nil
	}
	var p report.Project
	if json.Unmarshal(b, &p) != nil {
		return nil
	}
	return &p
}

func (s *Store) reportPath(dir string) string {
	h := sha256.Sum256([]byte(filepath.Clean(dir)))
	return filepath.Join(s.Dir, "reports", hex.EncodeToString(h[:])[:24]+".json")
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(map[string]any{"projects": s.projects}, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.Dir, "projects.json"), b)
}

func writeAtomic(p string, b []byte) error {
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
