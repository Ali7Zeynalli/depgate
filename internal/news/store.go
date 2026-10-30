package news

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Store keeps the last feed and what the user read, in the data folder.
type Store struct {
	Dir string
	mu  sync.Mutex
}

type state struct {
	Read  map[string]time.Time `json:"read"`  // item id → when it was marked read
	First map[string]time.Time `json:"first"` // item id → when DepGate first saw it (items without a date)
}

func (s *Store) feedPath() string  { return filepath.Join(s.Dir, "news.json") }
func (s *Store) statePath() string { return filepath.Join(s.Dir, "news-state.json") }

func readJSON(p string, v any) {
	b, err := os.ReadFile(p)
	if err == nil {
		_ = json.Unmarshal(b, v)
	}
}

func writeJSON(p string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (s *Store) loadState() state {
	st := state{Read: map[string]time.Time{}, First: map[string]time.Time{}}
	readJSON(s.statePath(), &st)
	if st.Read == nil {
		st.Read = map[string]time.Time{}
	}
	if st.First == nil {
		st.First = map[string]time.Time{}
	}
	return st
}

// Feed returns the last feed (empty when none was built yet).
func (s *Store) Feed() Feed {
	if s == nil || s.Dir == "" {
		return Feed{Items: []Item{}}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f := Feed{Items: []Item{}}
	readJSON(s.feedPath(), &f)
	if f.Items == nil {
		f.Items = []Item{}
	}
	return f
}

// FirstSeen is when each item without a date of its own was first seen.
func (s *Store) FirstSeen() map[string]time.Time {
	if s == nil || s.Dir == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadState().First
}

// Save stores a new feed and remembers when its items were first seen.
func (s *Store) Save(f Feed) error {
	if s == nil || s.Dir == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.loadState()
	live := map[string]bool{}
	for _, it := range f.Items {
		live[it.ID] = true
		if _, ok := st.First[it.ID]; !ok {
			st.First[it.ID] = it.At
		}
	}
	for id := range st.First { // forget what left the feed long ago
		if !live[id] && time.Since(st.First[id]) > 2*Window {
			delete(st.First, id)
		}
	}
	for id, at := range st.Read {
		if !live[id] && time.Since(at) > 2*Window {
			delete(st.Read, id)
		}
	}
	if err := writeJSON(s.feedPath(), f); err != nil {
		return err
	}
	return writeJSON(s.statePath(), st)
}

// Read returns the ids the user marked read.
func (s *Store) Read() map[string]bool {
	out := map[string]bool{}
	if s == nil || s.Dir == "" {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.loadState().Read {
		out[id] = true
	}
	return out
}

// MarkRead marks ids read (unread when unread is true).
func (s *Store) MarkRead(ids []string, unread bool) error {
	if s == nil || s.Dir == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.loadState()
	for _, id := range ids {
		if unread {
			delete(st.Read, id)
		} else {
			st.Read[id] = time.Now().UTC()
		}
	}
	return writeJSON(s.statePath(), st)
}
