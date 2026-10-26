package store

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Settings are the few options changed in the UI.
type Settings struct {
	// RescanHours: scan every project again when its last scan is older than this; 0 = never.
	// nil = not chosen in the UI (the --rescan default applies).
	RescanHours *int `json:"rescanHours,omitempty"`
}

func (s *Store) Settings() Settings {
	var st Settings
	if b, err := os.ReadFile(filepath.Join(s.Dir, "settings.json")); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func (s *Store) SaveSettings(st Settings) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.Dir, "settings.json"), b)
}
