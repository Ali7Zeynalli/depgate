package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// keepSessions is how many AI work sessions are remembered (all projects).
const keepSessions = 60

// WorkItem is one thing inside a task (a package, a Docker finding…).
type WorkItem struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Done  bool   `json:"done,omitempty"` // gone in DepGate's last check
}

// WorkTask is one checklist entry an agent took on.
type WorkTask struct {
	ID      string     `json:"id"`  // malware | now | code | node | docker | server | setup | plan
	Cat     string     `json:"cat"` // npm | node | docker | server | setup
	Title   string     `json:"title"`
	Items   []WorkItem `json:"items"`
	Status  string     `json:"status"` // todo | doing | done | partial | not_done | skipped
	Note    string     `json:"note,omitempty"`
	Checked *time.Time `json:"checked,omitempty"` // when DepGate last verified it
}

// WorkSession is one agent working through tasks the user chose, on one project.
type WorkSession struct {
	ID      string     `json:"id"`
	Agent   string     `json:"agent"`
	Via     string     `json:"via"`
	Project string     `json:"project"`
	Started time.Time  `json:"started"`
	Updated time.Time  `json:"updated"`
	Tasks   []WorkTask `json:"tasks"`
}

// Open reports whether some task is still to do.
func (w *WorkSession) Open() bool {
	for _, t := range w.Tasks {
		if t.Status == "todo" || t.Status == "doing" {
			return true
		}
	}
	return false
}

// Task returns the task with id (nil if the session has none).
func (w *WorkSession) Task(id string) *WorkTask {
	for i := range w.Tasks {
		if w.Tasks[i].ID == id {
			return &w.Tasks[i]
		}
	}
	return nil
}

func (l *Log) workPath() string { return filepath.Join(l.Dir, "ai-work.json") }

// WorkStamp is when the work sessions last changed (nil: never).
func (l *Log) WorkStamp() *time.Time {
	if l == nil || l.Dir == "" {
		return nil
	}
	st, err := os.Stat(l.workPath())
	if err != nil {
		return nil
	}
	t := st.ModTime().UTC()
	return &t
}

func (l *Log) readWork() []WorkSession {
	var ws []WorkSession
	if b, err := os.ReadFile(l.workPath()); err == nil {
		_ = json.Unmarshal(b, &ws)
	}
	return ws
}

func (l *Log) writeWork(ws []WorkSession) error {
	sort.Slice(ws, func(i, j int) bool { return ws[i].Updated.After(ws[j].Updated) })
	if len(ws) > keepSessions {
		ws = ws[:keepSessions]
	}
	b, err := json.Marshal(ws)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(l.Dir, 0o700); err != nil {
		return err
	}
	tmp := l.workPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, l.workPath())
}

// SaveSession stores w (replacing the session with the same id).
func (l *Log) SaveSession(w WorkSession) error {
	if l == nil || l.Dir == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ws := l.readWork()
	w.Updated = time.Now().UTC()
	found := false
	for i := range ws {
		if ws[i].ID == w.ID {
			ws[i], found = w, true
		}
	}
	if !found {
		ws = append(ws, w)
	}
	return l.writeWork(ws)
}

// Session returns the newest session of agent on project (nil if none).
func (l *Log) Session(agent, project string) *WorkSession {
	if l == nil || l.Dir == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, w := range l.readWork() { // newest first
		if w.Agent == agent && filepath.Clean(w.Project) == filepath.Clean(project) {
			return &w
		}
	}
	return nil
}

// Sessions returns the sessions of projects under dir ("" = all), newest first.
func (l *Log) Sessions(dir string) []WorkSession {
	if l == nil || l.Dir == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []WorkSession{}
	for _, w := range l.readWork() {
		if dir == "" || within(w.Project, dir) {
			out = append(out, w)
		}
	}
	return out
}

// clearWork drops the sessions of projects under dir (caller holds l.mu).
func (l *Log) clearWork(dir string) {
	ws := l.readWork()
	keep := ws[:0]
	for _, w := range ws {
		if !within(w.Project, dir) {
			keep = append(keep, w)
		}
	}
	if len(keep) != len(ws) {
		_ = l.writeWork(keep)
	}
}
