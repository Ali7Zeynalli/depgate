package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/scan"
	"github.com/Ali7Zeynalli/depgate/internal/store"
)

func TestStaleDirsAndRescanSetting(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	root := t.TempDir()
	fresh, old, never := filepath.Join(root, "fresh"), filepath.Join(root, "old"), filepath.Join(root, "never")
	_, _ = st.Add(store.Entry{Dir: fresh}, store.Entry{Dir: old}, store.Entry{Dir: never})
	now := time.Now()
	_ = st.SaveReport(&report.Project{Dir: fresh, ScannedAt: now.Add(-time.Hour)})
	_ = st.SaveReport(&report.Project{Dir: old, ScannedAt: now.Add(-13 * time.Hour)})
	m := &Manager{Store: st, Rescan: 12}
	if got := m.staleDirs(now); len(got) != 2 || got[0] != never && got[1] != never {
		t.Fatalf("stale %v", got)
	}
	if err := m.SetRescanHours(7); err == nil {
		t.Fatal("7 is not offered")
	}
	if err := m.SetRescanHours(0); err != nil || m.RescanHours() != 0 || m.staleDirs(now) != nil {
		t.Fatal("off")
	}
	if err := m.SetRescanHours(48); err != nil || m.RescanHours() != 48 || len(m.staleDirs(now)) != 1 {
		t.Fatal("48h")
	}
}

func TestUpdateCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v0.10.0","html_url":"https://github.com/Ali7Zeynalli/depgate/releases/tag/v0.10.0"}`))
	}))
	defer srv.Close()
	old := LatestURL
	LatestURL = srv.URL
	defer func() { LatestURL = old }()
	for _, c := range []struct {
		ver  string
		want bool
	}{{"0.9.0", true}, {"0.10.0", false}, {"0.11.1", false}, {"dev", false}} {
		m := &Manager{Opt: scan.Options{Version: c.ver}}
		m.checkUpdate(context.Background())
		if (m.update != nil) != c.want || c.want && m.update.Latest != "0.10.0" {
			t.Fatalf("%s: %+v", c.ver, m.update)
		}
	}
	m := &Manager{Opt: scan.Options{Version: "0.9.0", Offline: true}}
	m.checkUpdate(context.Background())
	if m.update != nil {
		t.Fatal("offline must not check")
	}
}
