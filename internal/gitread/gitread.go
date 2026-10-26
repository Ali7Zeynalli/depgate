// Package gitread reads commits, trees and blobs straight from a repository's
// .git folder — loose objects and pack files with deltas — using only the
// standard library. It never writes and never runs git. SHA-1 repositories only.
package gitread

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrNotFound means the object is not in the repository (a shallow clone, say).
var ErrNotFound = errors.New("git object not found")

// maxObject guards against huge blobs (a lockfile is far smaller).
const maxObject = 64 << 20

// Repo is an open repository.
type Repo struct {
	gitDir, common string
	packs          []*pack
	mu             sync.Mutex
	cache          map[string]object // decoded objects, for delta bases and repeated trees
	cacheBytes     int
}

type object struct {
	typ  string
	data []byte
}

// Open opens the repository whose working tree is root (the folder holding .git).
func Open(root string) (*Repo, error) {
	gd := filepath.Join(root, ".git")
	st, err := os.Stat(gd)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() { // worktree or submodule: "gitdir: <path>"
		b, err := os.ReadFile(gd)
		if err != nil {
			return nil, err
		}
		line := strings.TrimSpace(string(b))
		if !strings.HasPrefix(line, "gitdir:") {
			return nil, errors.New("unknown .git file")
		}
		gd = strings.TrimSpace(strings.TrimPrefix(line, "gitdir:"))
		if !filepath.IsAbs(gd) {
			gd = filepath.Join(root, gd)
		}
	}
	r := &Repo{gitDir: gd, common: gd, cache: map[string]object{}}
	if b, err := os.ReadFile(filepath.Join(gd, "commondir")); err == nil {
		c := strings.TrimSpace(string(b))
		if !filepath.IsAbs(c) {
			c = filepath.Join(gd, c)
		}
		r.common = filepath.Clean(c)
	}
	if b, err := os.ReadFile(filepath.Join(r.common, "config")); err == nil && strings.Contains(string(b), "objectformat = sha256") {
		return nil, errors.New("SHA-256 repositories are not supported")
	}
	idxs, _ := filepath.Glob(filepath.Join(r.common, "objects", "pack", "*.idx"))
	sort.Strings(idxs)
	for _, idx := range idxs {
		if p, err := openPack(idx); err == nil {
			r.packs = append(r.packs, p)
		}
	}
	return r, nil
}

// Close releases the pack files.
func (r *Repo) Close() {
	for _, p := range r.packs {
		_ = p.f.Close()
	}
}

// Head returns the commit HEAD points at.
func (r *Repo) Head() (string, error) {
	b, err := os.ReadFile(filepath.Join(r.gitDir, "HEAD"))
	if err != nil {
		return "", err
	}
	h := strings.TrimSpace(string(b))
	for i := 0; i < 5 && strings.HasPrefix(h, "ref:"); i++ {
		h, err = r.ref(strings.TrimSpace(strings.TrimPrefix(h, "ref:")))
		if err != nil {
			return "", err
		}
	}
	if !isHash(h) {
		return "", fmt.Errorf("HEAD: %q", h)
	}
	return h, nil
}

func (r *Repo) ref(name string) (string, error) {
	for _, d := range []string{r.gitDir, r.common} {
		if b, err := os.ReadFile(filepath.Join(d, filepath.FromSlash(name))); err == nil {
			return strings.TrimSpace(string(b)), nil
		}
	}
	f, err := os.Open(filepath.Join(r.common, "packed-refs"))
	if err != nil {
		return "", fmt.Errorf("ref %s not found", name)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) == 2 && fs[1] == name {
			return fs[0], nil
		}
	}
	return "", fmt.Errorf("ref %s not found", name)
}

func isHash(s string) bool {
	if len(s) != 40 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// Object returns the type and content of the object with hash h.
func (r *Repo) Object(h string) (string, []byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	o, err := r.object(h, 0)
	return o.typ, o.data, err
}

func (r *Repo) object(h string, depth int) (object, error) {
	if o, ok := r.cache[h]; ok {
		return o, nil
	}
	if depth > 60 {
		return object{}, errors.New("delta chain too deep")
	}
	o, err := r.loose(h)
	if errors.Is(err, os.ErrNotExist) {
		o, err = r.packed(h, depth)
	}
	if err != nil {
		return object{}, err
	}
	r.remember(h, o)
	return o, nil
}

func (r *Repo) remember(h string, o object) {
	if r.cacheBytes > 48<<20 { // keep memory bounded
		r.cache, r.cacheBytes = map[string]object{}, 0
	}
	r.cache[h] = o
	r.cacheBytes += len(o.data)
}

func (r *Repo) loose(h string) (object, error) {
	if !isHash(h) {
		return object{}, ErrNotFound
	}
	f, err := os.Open(filepath.Join(r.common, "objects", h[:2], h[2:]))
	if err != nil {
		return object{}, err
	}
	defer f.Close()
	zr, err := zlib.NewReader(f)
	if err != nil {
		return object{}, err
	}
	defer zr.Close()
	b, err := io.ReadAll(io.LimitReader(zr, maxObject+64))
	if err != nil {
		return object{}, err
	}
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return object{}, errors.New("bad loose object")
	}
	typ, _, _ := strings.Cut(string(b[:i]), " ")
	return object{typ, b[i+1:]}, nil
}

// ---------- pack files ----------

type pack struct {
	f       *os.File
	fanout  [256]uint32
	hashes  []byte // n*20
	offsets []byte // n*4
	large   []byte // 8 bytes each
}

func openPack(idx string) (*pack, error) {
	b, err := os.ReadFile(idx)
	if err != nil {
		return nil, err
	}
	if len(b) < 8+256*4 || !bytes.Equal(b[:4], []byte{0xff, 't', 'O', 'c'}) || binary.BigEndian.Uint32(b[4:8]) != 2 {
		return nil, errors.New("only pack index v2 is supported")
	}
	p := &pack{}
	for i := 0; i < 256; i++ {
		p.fanout[i] = binary.BigEndian.Uint32(b[8+i*4:])
	}
	n := int(p.fanout[255])
	at := 8 + 256*4
	need := at + n*20 + n*4 + n*4
	if len(b) < need {
		return nil, errors.New("short pack index")
	}
	p.hashes = b[at : at+n*20]
	at += n*20 + n*4 // skip CRCs
	p.offsets = b[at : at+n*4]
	at += n * 4
	p.large = b[at:]
	p.f, err = os.Open(strings.TrimSuffix(idx, ".idx") + ".pack")
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *pack) find(h []byte) (int64, bool) {
	lo := 0
	if h[0] > 0 {
		lo = int(p.fanout[h[0]-1])
	}
	hi := int(p.fanout[h[0]])
	for lo < hi {
		m := (lo + hi) / 2
		c := bytes.Compare(p.hashes[m*20:m*20+20], h)
		switch {
		case c == 0:
			off := binary.BigEndian.Uint32(p.offsets[m*4:])
			if off&0x80000000 != 0 {
				i := int(off &^ 0x80000000)
				if (i+1)*8 > len(p.large) {
					return 0, false
				}
				return int64(binary.BigEndian.Uint64(p.large[i*8:])), true
			}
			return int64(off), true
		case c < 0:
			lo = m + 1
		default:
			hi = m
		}
	}
	return 0, false
}

func (r *Repo) packed(h string, depth int) (object, error) {
	hb, err := hex.DecodeString(h)
	if err != nil || len(hb) != 20 {
		return object{}, ErrNotFound
	}
	for _, p := range r.packs {
		if off, ok := p.find(hb); ok {
			return r.readAt(p, off, depth)
		}
	}
	return object{}, ErrNotFound
}

var packTypes = map[byte]string{1: "commit", 2: "tree", 3: "blob", 4: "tag"}

func (r *Repo) readAt(p *pack, off int64, depth int) (object, error) {
	if depth > 60 {
		return object{}, errors.New("delta chain too deep")
	}
	// delta bases are shared by many objects: decode each one once
	key := fmt.Sprintf("%p@%d", p, off)
	if o, ok := r.cache[key]; ok {
		return o, nil
	}
	o, err := r.readAtRaw(p, off, depth)
	if err == nil {
		r.remember(key, o)
	}
	return o, err
}

func (r *Repo) readAtRaw(p *pack, off int64, depth int) (object, error) {
	br := bufio.NewReader(io.NewSectionReader(p.f, off, 1<<62))
	c, err := br.ReadByte()
	if err != nil {
		return object{}, err
	}
	typ := (c >> 4) & 7
	size := uint64(c & 15)
	shift := uint(4)
	for c&0x80 != 0 {
		if c, err = br.ReadByte(); err != nil {
			return object{}, err
		}
		size |= uint64(c&0x7f) << shift
		shift += 7
	}
	if size > maxObject {
		return object{}, errors.New("object too large")
	}
	var base object
	switch typ {
	case 6: // OFS_DELTA: negative offset to the base in the same pack
		c, err := br.ReadByte()
		if err != nil {
			return object{}, err
		}
		rel := int64(c & 0x7f)
		for c&0x80 != 0 {
			if c, err = br.ReadByte(); err != nil {
				return object{}, err
			}
			rel = ((rel + 1) << 7) | int64(c&0x7f)
		}
		if base, err = r.readAt(p, off-rel, depth+1); err != nil {
			return object{}, err
		}
	case 7: // REF_DELTA: the base by hash
		hb := make([]byte, 20)
		if _, err := io.ReadFull(br, hb); err != nil {
			return object{}, err
		}
		if base, err = r.object(hex.EncodeToString(hb), depth+1); err != nil {
			return object{}, err
		}
	}
	zr, err := zlib.NewReader(br)
	if err != nil {
		return object{}, err
	}
	defer zr.Close()
	data := make([]byte, size)
	if _, err := io.ReadFull(zr, data); err != nil {
		return object{}, err
	}
	if typ == 6 || typ == 7 {
		out, err := applyDelta(base.data, data)
		if err != nil {
			return object{}, err
		}
		return object{base.typ, out}, nil
	}
	t, ok := packTypes[typ]
	if !ok {
		return object{}, fmt.Errorf("unknown pack object type %d", typ)
	}
	return object{t, data}, nil
}

func deltaSize(d []byte, i *int) (uint64, error) {
	var n uint64
	var shift uint
	for {
		if *i >= len(d) {
			return 0, errors.New("bad delta")
		}
		c := d[*i]
		*i++
		n |= uint64(c&0x7f) << shift
		shift += 7
		if c&0x80 == 0 {
			return n, nil
		}
	}
}

func applyDelta(base, d []byte) ([]byte, error) {
	i := 0
	bs, err := deltaSize(d, &i)
	if err != nil {
		return nil, err
	}
	if bs != uint64(len(base)) {
		return nil, errors.New("delta base size mismatch")
	}
	rs, err := deltaSize(d, &i)
	if err != nil || rs > maxObject {
		return nil, errors.New("bad delta result size")
	}
	out := make([]byte, 0, rs)
	for i < len(d) {
		op := d[i]
		i++
		if op&0x80 != 0 { // copy from base
			var off, n uint32
			for k := uint(0); k < 4; k++ {
				if op&(1<<k) != 0 {
					if i >= len(d) {
						return nil, errors.New("bad delta copy")
					}
					off |= uint32(d[i]) << (8 * k)
					i++
				}
			}
			for k := uint(0); k < 3; k++ {
				if op&(0x10<<k) != 0 {
					if i >= len(d) {
						return nil, errors.New("bad delta copy")
					}
					n |= uint32(d[i]) << (8 * k)
					i++
				}
			}
			if n == 0 {
				n = 0x10000
			}
			if uint64(off)+uint64(n) > uint64(len(base)) {
				return nil, errors.New("delta copy out of range")
			}
			out = append(out, base[off:off+n]...)
		} else if op != 0 { // insert
			n := int(op)
			if i+n > len(d) {
				return nil, errors.New("bad delta insert")
			}
			out = append(out, d[i:i+n]...)
			i += n
		} else {
			return nil, errors.New("bad delta op")
		}
	}
	if uint64(len(out)) != rs {
		return nil, errors.New("delta result size mismatch")
	}
	return out, nil
}

// ---------- commits and trees ----------

// Commit is the part of a commit DepGate needs.
type Commit struct {
	Hash    string
	Tree    string
	Parents []string
	At      time.Time // author time
	Subject string    // first line of the message
}

// Commit reads commit h.
func (r *Repo) Commit(h string) (*Commit, error) {
	typ, b, err := r.Object(h)
	if err != nil {
		return nil, err
	}
	if typ != "commit" {
		return nil, fmt.Errorf("%s is a %s, not a commit", h, typ)
	}
	c := &Commit{Hash: h}
	head, msg, _ := bytes.Cut(b, []byte("\n\n"))
	for _, l := range strings.Split(string(head), "\n") {
		k, v, _ := strings.Cut(l, " ")
		switch k {
		case "tree":
			c.Tree = v
		case "parent":
			c.Parents = append(c.Parents, v)
		case "author", "committer":
			// the author time: when the change was made (a rebase keeps it)
			fs := strings.Fields(v)
			if len(fs) >= 2 && (k == "author" || c.At.IsZero()) {
				if sec, err := strconv.ParseInt(fs[len(fs)-2], 10, 64); err == nil {
					c.At = time.Unix(sec, 0).UTC()
				}
			}
		}
	}
	subj, _, _ := strings.Cut(strings.TrimSpace(string(msg)), "\n")
	c.Subject = strings.TrimSpace(subj)
	return c, nil
}

// Blob returns the hash of the file at path (slash-separated, from the repo root)
// in tree; "" when it is not there.
func (r *Repo) Blob(tree, path string) (string, error) {
	h := tree
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, name := range parts {
		typ, b, err := r.Object(h)
		if err != nil {
			return "", err
		}
		if typ != "tree" {
			return "", nil
		}
		next, isTree := "", false
		for len(b) > 0 {
			sp := bytes.IndexByte(b, ' ')
			nul := bytes.IndexByte(b, 0)
			if sp < 0 || nul < sp || nul+21 > len(b) {
				return "", errors.New("bad tree")
			}
			mode, n := string(b[:sp]), string(b[sp+1:nul])
			if n == name {
				next, isTree = hex.EncodeToString(b[nul+1:nul+21]), mode == "40000"
				break
			}
			b = b[nul+21:]
		}
		if next == "" || (i < len(parts)-1) != isTree {
			return "", nil
		}
		h = next
	}
	return h, nil
}

// BlobHash is the hash git gives content as a blob (to compare with the working tree).
func BlobHash(data []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(data))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
