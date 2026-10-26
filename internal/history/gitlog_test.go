package history

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func gitT(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func lockJSON(next, extra string) string {
	s := `{"name":"web","lockfileVersion":3,"packages":{"":{"name":"web","dependencies":{"next":"^14.2.3"}},"node_modules/next":{"version":"` + next + `"}`
	if extra != "" {
		s += `,"node_modules/` + extra + `":{"version":"1.0.0"}`
	}
	return s + `}}`
}

func TestReadGitLog(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "apps", "web")
	_ = os.MkdirAll(dir, 0o755)
	w := func(name, s string) { _ = os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644) }
	commit := func(msg string) { gitT(t, root, "add", "-A"); gitT(t, root, "commit", "-q", "-m", msg) }
	gitT(t, root, "init", "-q", "-b", "main")
	w("package.json", `{"name":"web","dependencies":{"next":"^14.2.3"}}`)
	w("package-lock.json", lockJSON("14.2.3", ""))
	commit("init")
	w("README.md", "x")
	commit("docs only")
	w("package-lock.json", lockJSON("14.2.25", "left-pad"))
	commit("chore: bump next")
	w("package.json", `{"name":"web","version":"1.0.1","dependencies":{"next":"^14.2.3"}}`)
	commit("version bump")
	w("package-lock.json", lockJSON("14.2.10", "left-pad")) // not committed: a downgrade

	g := ReadGitLog(dir, "package-lock.json", time.Now().Add(-time.Hour), 100)
	if g.Note != "" || len(g.Changes) != 4 {
		t.Fatalf("%+v", g)
	}
	u, bump, man, first := g.Changes[0], g.Changes[2], g.Changes[1], g.Changes[3]
	if !u.Uncommitted || u.Pkgs == nil || u.Pkgs.Changes[0].Kind != "down" {
		t.Fatalf("uncommitted %+v", u)
	}
	if !man.Manifest || man.Subject != "version bump" {
		t.Fatalf("manifest %+v", man)
	}
	if bump.Subject != "chore: bump next" || bump.Pkgs == nil || len(bump.Pkgs.Changes) != 2 || len(bump.Hash) != 40 {
		t.Fatalf("bump %+v", bump)
	}
	got := map[string]string{}
	for _, c := range bump.Pkgs.Changes {
		got[c.Name] = c.Kind + " " + c.From + ">" + c.To
	}
	if got["next"] != "up 14.2.3>14.2.25" || !strings.HasPrefix(got["left-pad"], "add") {
		t.Fatalf("bump changes %v", got)
	}
	if !first.First || first.Subject != "init" {
		t.Fatalf("first %+v", first)
	}
	if g := ReadGitLog(t.TempDir(), "package-lock.json", time.Time{}, 10); g.Note != "no-git" {
		t.Fatalf("no git %+v", g)
	}
}
