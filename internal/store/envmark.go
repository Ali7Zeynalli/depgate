package store

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/report"
)

// Environment marks: the user says a Docker, Compose or web server file is for
// development or production when DepGate's guess from the name is wrong. They
// are kept in the data folder (never in the project), by absolute file path, so
// a compose file shared by a monorepo's projects is marked once.

func (s *Store) envPath() string { return filepath.Join(s.Dir, "env-marks.json") }

func (s *Store) envMarks() map[string]string {
	m := map[string]string{}
	if b, err := os.ReadFile(s.envPath()); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

// SetEnvMark marks file (absolute) as "dev" or "prod"; "" goes back to the guess.
func (s *Store) SetEnvMark(file, env string) error {
	s.amu.Lock()
	defer s.amu.Unlock()
	m := s.envMarks()
	file = filepath.Clean(file)
	if env == "" {
		delete(m, file)
	} else {
		m[file] = env
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.envPath(), b)
}

var markedWhy = i18n.F("sən işarələmisən", "marked by you")

// applyEnvMarks sets the environment of the issues in files the user marked.
func (s *Store) applyEnvMarks(p *report.Project) {
	if p == nil {
		return
	}
	s.amu.Lock()
	m := s.envMarks()
	s.amu.Unlock()
	if len(m) == 0 {
		return
	}
	abs := func(rel string) string { return filepath.Clean(filepath.Join(p.Dir, filepath.FromSlash(rel))) }
	p.EnvMarks = map[string]string{}
	for _, f := range append(append([]string(nil), p.DockerFiles...), p.ServerFiles...) {
		if e := m[abs(f)]; e != "" {
			p.EnvMarks[f] = e
		}
	}
	for _, is := range [][]report.DockerIssue{p.Docker, p.Server} {
		for i := range is {
			if e := m[abs(is[i].File)]; e != "" {
				w := markedWhy
				is[i].Env, is[i].EnvWhy = e, &w
			}
		}
	}
}
