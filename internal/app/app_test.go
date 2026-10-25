package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/decide"
	"github.com/Ali7Zeynalli/depgate/internal/scan"
	"github.com/Ali7Zeynalli/depgate/internal/semver"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
	"github.com/Ali7Zeynalli/depgate/internal/sources/sourcestest"
	"github.com/Ali7Zeynalli/depgate/internal/store"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func setup(t *testing.T) (*Manager, string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir()
	write(t, filepath.Join(root, "shop/package.json"), `{"name":"shop","dependencies":{"left-pad":"1.3.0"}}`)
	write(t, filepath.Join(root, "shop/package-lock.json"), `{"lockfileVersion":3,"packages":{"":{"dependencies":{"left-pad":"1.3.0"}},"node_modules/left-pad":{"version":"1.3.0"}}}`)
	write(t, filepath.Join(root, "mono/package.json"), `{"name":"mono","private":true}`)
	write(t, filepath.Join(root, "mono/apps/web/package.json"), `{"name":"web","dependencies":{"left-pad":"^1.3.0"}}`)
	write(t, filepath.Join(root, "mono/apps/api/package.json"), `{"name":"api","dependencies":{"left-pad":"^1.3.0"}}`)
	write(t, filepath.Join(root, "notes/readme.txt"), "x")
	if err := os.MkdirAll(filepath.Join(root, ".hidden"), 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	f := sourcestest.New(now)
	f.Match = func(v *sources.Vuln, name, ver string) bool {
		sv, err := semver.Parse(ver)
		return err == nil && decide.Affects(v, name, sv)
	}
	f.Vuln("GHSA-lp", "left-pad", "HIGH", "0", "1.3.1", "left-pad bug")
	f.Versions["left-pad"] = sourcestest.Old("1.3.0", "1.3.1")
	m := &Manager{Store: st, Fetcher: func() sources.Fetcher { return f }, Opt: scan.Options{Version: "test", Now: now}, Roots: []string{root}, Depth: 3}
	m.Start(context.Background())
	return m, root
}

func waitIdle(t *testing.T, m *Manager) State {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st := m.State(); !st.Busy {
			return st
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("scan did not finish")
	return State{}
}

func TestBrowse(t *testing.T) {
	m, root := setup(t)
	l, err := m.Browse("")
	if err != nil {
		t.Fatal(err)
	}
	if l.Path != root || len(l.Entries) != 3 || l.Entries[1].Name != "shop" || !l.Entries[1].IsProject || !l.Entries[1].Lockfile {
		t.Fatalf("listing %+v", l)
	}
	if l.Entries[0].Name != "mono" || !l.Entries[0].IsProject || l.Entries[2].Name != "notes" || l.Entries[2].IsProject {
		t.Fatalf("order %+v", l.Entries)
	}
	sub, err := m.Browse(filepath.Join(root, "mono/apps"))
	if err != nil || len(sub.Crumbs) != 3 || sub.Parent != filepath.Join(root, "mono") {
		t.Fatalf("sub %+v %v", sub, err)
	}
	if _, err := m.Browse("/etc"); err != ErrOutside {
		t.Fatalf("outside: %v", err)
	}
	if _, err := m.Browse(filepath.Join(root, "../")); err != ErrOutside {
		t.Fatalf("parent escape: %v", err)
	}
}

func TestAddScanRemember(t *testing.T) {
	m, root := setup(t)
	dirs, err := m.Add(filepath.Join(root, "mono"))
	if err != nil || len(dirs) != 2 {
		t.Fatalf("add mono: %v %v", dirs, err)
	}
	if _, err := m.Add(filepath.Join(root, "shop")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Add(filepath.Join(root, "notes")); err == nil {
		t.Fatal("folder without package.json accepted")
	}
	st := waitIdle(t, m)
	if len(st.Projects) != 3 {
		t.Fatalf("projects %+v", st.Projects)
	}
	for _, p := range st.Projects {
		if p.Report == nil {
			t.Fatalf("%s not scanned", p.Dir)
		}
	}
	var shop *ProjectState
	for i := range st.Projects {
		if st.Projects[i].Name == "shop" {
			shop = &st.Projects[i]
		}
	}
	if shop == nil || shop.Report.Summary.NowEasy != 1 {
		t.Fatalf("shop %+v", shop)
	}
	// browse marks added projects
	l, _ := m.Browse("")
	if !l.Entries[0].Added || !l.Entries[1].Added || l.Entries[2].Added {
		t.Fatalf("added marks wrong: %+v", l.Entries)
	}
	// remembered across restarts
	st2, _ := store.Open(m.Store.Dir)
	if len(st2.Projects()) != 3 || st2.Report(shop.Dir) == nil {
		t.Fatal("not persisted")
	}
	// rescan all + remove
	if err := m.Scan(nil); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, m)
	if err := m.Remove(shop.Dir); err != nil {
		t.Fatal(err)
	}
	if len(m.State().Projects) != 2 || m.Store.Report(shop.Dir) != nil {
		t.Fatal("remove failed")
	}
}

func TestTokenStable(t *testing.T) {
	d := t.TempDir()
	s1, _ := store.Open(d)
	a, _ := s1.Token()
	s2, _ := store.Open(d)
	b, _ := s2.Token()
	if a == "" || a != b {
		t.Fatalf("token not stable: %q %q", a, b)
	}
	t.Setenv("DEPGATE_TOKEN", "from-env-0123456789")
	c, _ := s2.Token()
	if c != "from-env-0123456789" {
		t.Fatal(c)
	}
}

func TestAssignGroups(t *testing.T) {
	ps := []ProjectState{
		{Dir: "/h/acme/apps/web", Name: "@acme/web"},
		{Dir: "/h/blog", Name: "blog"},
		{Dir: "/h/acme", Name: "acme"},
		{Dir: "/h/acme/apps/admin", Name: "@acme/admin"},
		{Dir: "/h/work/a", Name: "a"},
		{Dir: "/h/work/b", Name: "b"},
		{Dir: "/h/work/b/sub", Name: "old-without-group"},
	}
	explicit := map[string]string{
		"/h/acme/apps/web":   "/h/acme",
		"/h/acme/apps/admin": "/h/acme/apps", // picked a narrower folder later
		"/h/work/a":          "/h/work",
		"/h/work/b":          "/h/work",
	}
	assignGroups(ps, explicit)
	want := []struct{ dir, group string }{
		{"/h/acme", "/h/acme"},
		{"/h/acme/apps/admin", "/h/acme"},
		{"/h/acme/apps/web", "/h/acme"},
		{"/h/blog", "/h/blog"},
		{"/h/work/a", "/h/work"},
		{"/h/work/b", "/h/work"},
		{"/h/work/b/sub", "/h/work"},
	}
	for i, w := range want {
		if ps[i].Dir != w.dir || ps[i].Group != w.group {
			t.Fatalf("%d: got %s in %s, want %s in %s", i, ps[i].Dir, ps[i].Group, w.dir, w.group)
		}
	}
}

func TestReAddSetsGroup(t *testing.T) {
	s, _ := store.Open(t.TempDir())
	_, _ = s.Add(store.Entry{Dir: "/h/k/apps/a"})
	_, _ = s.Add(store.Entry{Dir: "/h/k/apps/a", Group: "/h/k"})
	if g := s.Projects()[0].Group; g != "/h/k" {
		t.Fatalf("group %q", g)
	}
	_, _ = s.Add(store.Entry{Dir: "/h/k/apps/a", Group: "/h/k/apps"}) // narrower: keep the wider one
	if g := s.Projects()[0].Group; g != "/h/k" {
		t.Fatalf("narrowed to %q", g)
	}
}
