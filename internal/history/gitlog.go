package history

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/gitread"
	"github.com/Ali7Zeynalli/depgate/internal/lockfile"
	"github.com/Ali7Zeynalli/depgate/internal/report"
)

// GitChange is one commit that changed the project's package versions (or its
// package.json), or the lockfile's uncommitted changes.
type GitChange struct {
	Hash        string    `json:"hash,omitempty"`
	At          time.Time `json:"at"`
	Subject     string    `json:"subject,omitempty"`
	Pkgs        *PkgDiff  `json:"pkgs,omitempty"`
	Manifest    bool      `json:"manifest,omitempty"`    // package.json changed, versions did not
	First       bool      `json:"first,omitempty"`       // the commit that added the lockfile
	Uncommitted bool      `json:"uncommitted,omitempty"` // the working tree differs from HEAD
}

// GitLog is what git says about a project's dependencies, newest first.
type GitLog struct {
	Changes []GitChange `json:"changes"`
	Head    string      `json:"head,omitempty"`
	Note    string      `json:"note,omitempty"` // why it is empty or ends early: no-git | no-lockfile | shallow | error
}

// ReadGitLog reads the commits of the last days (first-parent line from HEAD,
// at most maxCommits) that changed the project's lockfile or package.json.
// lockRel is the lockfile path relative to dir (may start with ../ in a workspace).
func ReadGitLog(dir, lockRel string, since time.Time, maxCommits int) GitLog {
	out := GitLog{Changes: []GitChange{}}
	root := repoRoot(dir)
	if root == "" {
		out.Note = "no-git"
		return out
	}
	if lockRel == "" {
		out.Note = "no-lockfile"
		return out
	}
	r, err := gitread.Open(root)
	if err != nil {
		out.Note = "error"
		return out
	}
	defer r.Close()
	lockAbs := filepath.Clean(filepath.Join(dir, lockRel))
	rel := func(p string) string { s, _ := filepath.Rel(root, p); return filepath.ToSlash(s) }
	lockPath, manPath := rel(lockAbs), rel(filepath.Join(dir, "package.json"))
	if strings.HasPrefix(lockPath, "../") {
		out.Note = "error"
		return out
	}
	member, _ := filepath.Rel(filepath.Dir(lockAbs), dir)
	member = filepath.ToSlash(member)
	if member == "." {
		member = ""
	}
	parsed := map[string][]report.Version{}
	read := func(h string) []byte {
		if h == "" {
			return nil
		}
		_, b, err := r.Object(h)
		if err != nil {
			return nil
		}
		return b
	}
	vers := func(lockBlob, manBlob string, lockData, manData []byte) []report.Version {
		key := lockBlob + "|" + manBlob
		if v, ok := parsed[key]; ok {
			return v
		}
		if lockData == nil {
			lockData = read(lockBlob)
		}
		if manData == nil {
			manData = read(manBlob)
		}
		var v []report.Version
		if len(lockData) > 0 {
			var man lockfile.Manifest
			_ = json.Unmarshal(manData, &man)
			if pk, err := lockfile.ParseData(lockfile.KindOf(lockPath, lockData), lockData, &man, member); err == nil {
				v = make([]report.Version, 0, len(pk))
				for _, x := range pk {
					v = append(v, report.Version{Name: x.Name, Version: x.Version, Direct: x.Direct, Dev: x.Dev})
				}
			}
		}
		parsed[key] = v
		return v
	}
	head, err := r.Head()
	if err != nil {
		out.Note = "error"
		return out
	}
	out.Head = head
	c, err := r.Commit(head)
	if err != nil {
		out.Note = "error"
		return out
	}
	// uncommitted: the lockfile on disk against HEAD
	headLock, _ := r.Blob(c.Tree, lockPath)
	headMan, _ := r.Blob(c.Tree, manPath)
	if b, err := os.ReadFile(lockAbs); err == nil && gitread.BlobHash(b) != headLock {
		m, _ := os.ReadFile(filepath.Join(dir, "package.json"))
		at := time.Now().UTC()
		if st, err := os.Stat(lockAbs); err == nil {
			at = st.ModTime().UTC()
		}
		if d := DiffVersions(vers(headLock, headMan, nil, nil), vers(gitread.BlobHash(b), gitread.BlobHash(m), b, m)); d != nil {
			out.Changes = append(out.Changes, GitChange{At: at, Pkgs: d, Uncommitted: true})
		}
	}
	for n := 0; n < maxCommits; n++ {
		if c.At.Before(since) {
			break
		}
		lb, mb := headLock, headMan
		var p *gitread.Commit
		plb, pmb := "", ""
		if len(c.Parents) > 0 {
			p, err = r.Commit(c.Parents[0])
			if err != nil {
				if errors.Is(err, gitread.ErrNotFound) {
					out.Note = "shallow"
				} else {
					out.Note = "error"
				}
				break
			}
			plb, _ = r.Blob(p.Tree, lockPath)
			pmb, _ = r.Blob(p.Tree, manPath)
		}
		if lb != plb || mb != pmb {
			ch := GitChange{Hash: c.Hash, At: c.At, Subject: clip(c.Subject, 140), First: plb == "" && lb != ""}
			if lb != plb {
				ch.Pkgs = DiffVersions(vers(plb, pmb, nil, nil), vers(lb, mb, nil, nil))
			}
			ch.Manifest = ch.Pkgs == nil
			if ch.Pkgs != nil || mb != pmb {
				out.Changes = append(out.Changes, ch)
			}
		}
		if p == nil {
			break
		}
		c, headLock, headMan = p, plb, pmb
	}
	return out
}

func repoRoot(dir string) string {
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		if filepath.Dir(d) == d {
			return ""
		}
	}
}

// GitSignature changes when a new commit, a checkout or an edit of the
// lockfile or package.json could change ReadGitLog's answer; cheap to compute.
func GitSignature(dir, lockRel string) string {
	var b strings.Builder
	stamp := func(p string) {
		if st, err := os.Stat(p); err == nil {
			b.WriteString(st.ModTime().UTC().Format(time.RFC3339Nano))
			b.WriteString(";")
		} else {
			b.WriteString("-;")
		}
	}
	if lockRel != "" {
		stamp(filepath.Join(dir, lockRel))
	}
	stamp(filepath.Join(dir, "package.json"))
	root := repoRoot(dir)
	if root == "" {
		return b.String()
	}
	gd := filepath.Join(root, ".git")
	if st, err := os.Stat(gd); err == nil && !st.IsDir() {
		// a worktree: look again at most every minute
		b.WriteString(time.Now().UTC().Truncate(time.Minute).String())
		return b.String()
	}
	head, _ := os.ReadFile(filepath.Join(gd, "HEAD"))
	b.Write(head)
	if ref, ok := strings.CutPrefix(strings.TrimSpace(string(head)), "ref: "); ok {
		stamp(filepath.Join(gd, filepath.FromSlash(ref)))
	}
	stamp(filepath.Join(gd, "packed-refs"))
	return b.String()
}
