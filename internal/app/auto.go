package app

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
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
// checks once a day whether a newer DepGate is out.
func (m *Manager) autoLoop(ctx context.Context) {
	first := time.NewTimer(time.Minute)
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
		if time.Since(lastCheck) > 24*time.Hour {
			lastCheck = time.Now()
			m.checkUpdate(ctx)
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

func (m *Manager) checkUpdate(ctx context.Context) {
	if m.Opt.Offline || os.Getenv("DEPGATE_NO_UPDATE_CHECK") == "1" {
		return
	}
	cur, err := semver.Parse(m.Opt.Version)
	if err != nil {
		return // a development build
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, LatestURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "depgate/"+m.Opt.Version)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return
	}
	var rel struct {
		Tag        string `json:"tag_name"`
		URL        string `json:"html_url"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if json.NewDecoder(res.Body).Decode(&rel) != nil || rel.Draft || rel.Prerelease {
		return
	}
	latest, err := semver.Parse(rel.Tag)
	if err != nil || semver.Compare(latest, cur) <= 0 {
		return
	}
	if !strings.HasPrefix(rel.URL, "https://github.com/") {
		rel.URL = "https://github.com/Ali7Zeynalli/depgate/releases/latest"
	}
	m.mu.Lock()
	m.update = &Update{Latest: strings.TrimPrefix(rel.Tag, "v"), URL: rel.URL}
	m.mu.Unlock()
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
