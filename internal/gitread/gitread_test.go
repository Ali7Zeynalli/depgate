package gitread

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// repo makes a repository with n commits that each change apps/web/lock.json.
func repo(t *testing.T, n int) (string, []string) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	_ = os.MkdirAll(filepath.Join(dir, "apps", "web"), 0o755)
	var contents []string
	for i := 0; i < n; i++ {
		// big, mostly equal content so git stores deltas
		c := strings.Repeat("line that stays the same\n", 400) + fmt.Sprintf("version %d\n", i)
		contents = append(contents, c)
		_ = os.WriteFile(filepath.Join(dir, "apps", "web", "lock.json"), []byte(c), 0o644)
		git(t, dir, "add", "-A")
		git(t, dir, "commit", "-q", "-m", fmt.Sprintf("commit %d\n\nbody", i))
	}
	return dir, contents
}

func check(t *testing.T, dir string, contents []string) {
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	h, err := r.Head()
	if err != nil {
		t.Fatal(err)
	}
	if h != git(t, dir, "rev-parse", "HEAD") {
		t.Fatalf("head %s", h)
	}
	for i := len(contents) - 1; i >= 0; i-- {
		c, err := r.Commit(h)
		if err != nil {
			t.Fatal(err)
		}
		if c.Subject != fmt.Sprintf("commit %d", i) || c.At.IsZero() {
			t.Fatalf("commit %+v", c)
		}
		b, err := r.Blob(c.Tree, "apps/web/lock.json")
		if err != nil || b == "" {
			t.Fatalf("blob %q %v", b, err)
		}
		_, data, err := r.Object(b)
		if err != nil || string(data) != contents[i] || BlobHash(data) != b {
			t.Fatalf("content %d: %v", i, err)
		}
		if x, _ := r.Blob(c.Tree, "apps/missing.json"); x != "" {
			t.Fatal("missing file found")
		}
		if len(c.Parents) == 0 {
			break
		}
		h = c.Parents[0]
	}
}

func TestLooseObjects(t *testing.T) {
	dir, cs := repo(t, 4)
	check(t, dir, cs)
}

func TestPackedObjectsWithDeltas(t *testing.T) {
	dir, cs := repo(t, 12)
	git(t, dir, "gc", "-q", "--aggressive")
	if ps, _ := filepath.Glob(filepath.Join(dir, ".git", "objects", "pack", "*.pack")); len(ps) == 0 {
		t.Fatal("no pack")
	}
	check(t, dir, cs)
	// refs packed too
	if _, err := os.Stat(filepath.Join(dir, ".git", "refs", "heads", "main")); err == nil {
		t.Log("loose ref still present")
	}
}

func TestWorktree(t *testing.T) {
	dir, cs := repo(t, 3)
	wt := filepath.Join(t.TempDir(), "wt")
	git(t, dir, "worktree", "add", "-q", wt)
	check(t, wt, cs)
}
