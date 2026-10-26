package app

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/semver"
	"github.com/Ali7Zeynalli/depgate/internal/store"
)

// RescanChoices are the intervals offered in the UI (hours; 0 = off).
var RescanChoices = []int{0, 6, 12, 24, 48}

// RescanHours is how old a scan may get before DepGate scans the project again.
func (m *Manager) RescanHours() int {
	if m.Store != nil {
		if h := m.Store.Settings().RescanHours; h != nil {
			return *h
		}
	}
	return m.Rescan
}

// SetRescanHours saves the interval chosen in the UI.
// SetEnvMark marks a Docker, Compose or web server file of project dir as "dev"
// or "prod" ("" = DepGate's guess). It is stored in the data folder only.
func (m *Manager) SetEnvMark(dir, file, env string) error {
	if m.ro != nil {
		return ErrReadOnly
	}
	if env != "" && env != "dev" && env != "prod" {
		return newErr("mühit dev və ya prod olmalıdır", "the environment must be dev or prod")
	}
	p := m.Store.Report(dir)
	if p == nil {
		return newErr("bu layihə skan olunmayıb", "this project has not been scanned")
	}
	known := false
	for _, f := range append(append([]string(nil), p.DockerFiles...), p.ServerFiles...) {
		known = known || f == file
	}
	if !known {
		return newErr("bu fayl layihənin Docker/server faylları arasında yoxdur", "this file is not one of the project's Docker/server files")
	}
	return m.Store.SetEnvMark(filepath.Join(dir, filepath.FromSlash(file)), env)
}

func (m *Manager) SetRescanHours(h int) error {
	if m.ro != nil {
		return ErrReadOnly
	}
	ok := false
	for _, c := range RescanChoices {
		ok = ok || c == h
	}
	if !ok {
		return newErr("bu interval mümkün deyil", "this interval is not offered")
	}
	st := m.Store.Settings()
	st.RescanHours = &h
	return m.Store.SaveSettings(st)
}

// staleDirs lists the projects whose last scan is older than the interval.
func (m *Manager) staleDirs(now time.Time) []string {
	h := m.RescanHours()
	if h <= 0 {
		return nil
	}
	m.mu.Lock()
	busy := map[string]bool{}
	for d := range m.running {
		busy[d] = true
	}
	for d := range m.queued {
		busy[d] = true
	}
	m.mu.Unlock()
	var out []string
	for _, e := range m.Store.Projects() {
		if busy[e.Dir] {
			continue
		}
		r := m.Store.Report(e.Dir)
		if r == nil || r.ScannedAt.IsZero() || now.Sub(r.ScannedAt) >= time.Duration(h)*time.Hour {
			out = append(out, e.Dir)
		}
	}
	return out
}

// autoLoop scans stale projects again (also after the computer slept) and
// checks 15 s after start and every 6 h whether a newer DepGate is out.
func (m *Manager) autoLoop(ctx context.Context) {
	first := time.NewTimer(15 * time.Second)
	tick := time.NewTicker(5 * time.Minute)
	defer first.Stop()
	defer tick.Stop()
	var lastCheck time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
		case <-tick.C:
		}
		if ds := m.staleDirs(time.Now()); len(ds) > 0 {
			_ = m.ScanBy(ds, "auto")
		}
		if time.Since(lastCheck) > 6*time.Hour {
			lastCheck = time.Now()
			_ = m.checkUpdate(ctx)
		}
	}
}

// ---------- new version ----------

// Update tells that a newer DepGate release exists.
type Update struct {
	Latest string `json:"latest"`
	URL    string `json:"url"`
}

// LatestURL is where the newest release is looked up (a test may point it elsewhere).
var LatestURL = "https://api.github.com/repos/Ali7Zeynalli/depgate/releases/latest"

// CheckUpdate asks GitHub now (the "⋯ → Check for updates" item); nil = up to date.
func (m *Manager) CheckUpdate(ctx context.Context) (*Update, error) {
	if m.ro != nil {
		return nil, ErrReadOnly
	}
	if err := m.checkUpdate(ctx); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.update, nil
}

var errNoCheck = newErr("yeniləmə yoxlanmır (offline və ya DEPGATE_NO_UPDATE_CHECK=1)", "update checks are off (offline or DEPGATE_NO_UPDATE_CHECK=1)")

func (m *Manager) checkUpdate(ctx context.Context) error {
	if m.Opt.Offline || os.Getenv("DEPGATE_NO_UPDATE_CHECK") == "1" {
		return errNoCheck
	}
	cur, err := semver.Parse(m.Opt.Version)
	if err != nil {
		return newErr("bu, rəsmi relizdən yığılmayıb — yoxlamaq mümkün deyil", "this is not a release build — nothing to compare") // a development build
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, LatestURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "depgate/"+m.Opt.Version)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return newErr("GitHub-a çatmaq olmadı", "could not reach GitHub")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return newErr("GitHub cavab vermədi (HTTP %d)", "GitHub did not answer (HTTP %d)", res.StatusCode)
	}
	var rel struct {
		Tag        string `json:"tag_name"`
		URL        string `json:"html_url"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if json.NewDecoder(res.Body).Decode(&rel) != nil || rel.Draft || rel.Prerelease {
		return nil
	}
	latest, err := semver.Parse(rel.Tag)
	if err != nil || semver.Compare(latest, cur) <= 0 {
		m.mu.Lock()
		m.update = nil
		m.mu.Unlock()
		return nil
	}
	if !strings.HasPrefix(rel.URL, "https://github.com/") {
		rel.URL = "https://github.com/Ali7Zeynalli/depgate/releases/latest"
	}
	m.mu.Lock()
	m.update = &Update{Latest: strings.TrimPrefix(rel.Tag, "v"), URL: rel.URL}
	m.mu.Unlock()
	return nil
}

// Accept records that the user accepts a finding's risk in dirs for days days.
func (m *Manager) Accept(dirs []string, key, reason string, days int) error {
	if m.ro != nil {
		return ErrReadOnly
	}
	if days < 1 || days > 366 {
		return newErr("müddət 1–366 gün olmalıdır", "the period must be 1–366 days")
	}
	for _, d := range dirs {
		if !m.Store.Has(d) {
			return ErrOutside
		}
	}
	err := m.Store.Accept(dirs, key, reason, time.Now().Add(time.Duration(days)*24*time.Hour))
	switch err {
	case store.ErrNoReason:
		return newErr("səbəb yaz", "write a reason")
	case store.ErrMalware:
		return newErr("zərərli paketin riskini qəbul etmək olmaz — onu sil", "the risk of a malicious package cannot be accepted — remove it")
	}
	return err
}

// Unaccept removes an accepted risk.
func (m *Manager) Unaccept(dirs []string, key string) error {
	if m.ro != nil {
		return ErrReadOnly
	}
	return m.Store.Unaccept(dirs, key)
}
