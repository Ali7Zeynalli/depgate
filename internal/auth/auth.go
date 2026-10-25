// Package auth protects the local UI with a user-chosen password.
//
// The password is stored as PBKDF2-SHA256 (600 000 iterations, 16-byte salt)
// in <data>/auth.json. Sessions are stateless signed cookies (HMAC-SHA256 with a
// random key kept in the same file); changing or resetting the password rotates
// the key, which logs out every session. Only the standard library is used.
package auth

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Iterations is the PBKDF2 work factor (OWASP 2023+ for SHA-256); tests lower it.
var Iterations = 600_000

const (
	MinLength = 8
	// LongSession is "remember me"; ShortSession is a browser session.
	LongSession  = 30 * 24 * time.Hour
	ShortSession = 12 * time.Hour
)

var (
	ErrNoPassword  = errors.New("no password set")
	ErrHasPassword = errors.New("password already set")
	ErrWrong       = errors.New("wrong password")
	ErrTooShort    = errors.New("password too short")
	ErrLocked      = errors.New("too many attempts, wait a moment")
)

type file struct {
	Hash  string    `json:"hash"` // base64
	Salt  string    `json:"salt"` // base64
	Iter  int       `json:"iter"`
	Key   string    `json:"key"` // base64 session signing key
	SetAt time.Time `json:"setAt"`
}

// Auth is safe for concurrent use.
type Auth struct {
	path string
	env  string // DEPGATE_PASSWORD: fixed password, never written to disk

	mu   sync.Mutex
	f    *file
	fail map[string]*attempts
	now  func() time.Time
}

type attempts struct {
	n     int
	until time.Time
}

// Open loads <dir>/auth.json. envPassword (may be "") overrides the stored password.
func Open(dir, envPassword string) (*Auth, error) {
	a := &Auth{path: filepath.Join(dir, "auth.json"), env: envPassword, fail: map[string]*attempts{}, now: time.Now}
	b, err := os.ReadFile(a.path)
	switch {
	case err == nil:
		var f file
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, errors.New("auth.json: " + err.Error())
		}
		a.f = &f
	case !os.IsNotExist(err):
		return nil, err
	}
	if envPassword != "" {
		if len(envPassword) < MinLength {
			return nil, errors.New("DEPGATE_PASSWORD must be at least 8 characters")
		}
		// keep a stable signing key across restarts, but derive the hash from the env value
		key := randB64(32)
		if a.f != nil && a.f.Key != "" {
			key = a.f.Key
		}
		salt := randB64(16)
		h, err := derive(envPassword, salt, Iterations)
		if err != nil {
			return nil, err
		}
		a.f = &file{Hash: h, Salt: salt, Iter: Iterations, Key: key, SetAt: time.Now().UTC()}
		_ = a.saveLocked() // persists only the key/hash of the env password; harmless if it fails
	}
	return a, nil
}

// Reset deletes the stored password (CLI --reset-password).
func Reset(dir string) error {
	err := os.Remove(filepath.Join(dir, "auth.json"))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// refreshLocked drops the in-memory password when --reset-password removed
// auth.json while the server is running.
func (a *Auth) refreshLocked() {
	if a.env != "" || a.f == nil {
		return
	}
	if _, err := os.Stat(a.path); os.IsNotExist(err) {
		a.f = nil
	}
}

// Configured reports whether a password exists.
func (a *Auth) Configured() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshLocked()
	return a.f != nil && a.f.Hash != ""
}

// FromEnv reports whether the password comes from DEPGATE_PASSWORD (cannot be changed in the UI).
func (a *Auth) FromEnv() bool { return a.env != "" }

// Setup sets the first password; it fails when one exists already.
func (a *Auth) Setup(pw string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshLocked()
	if a.f != nil && a.f.Hash != "" {
		return ErrHasPassword
	}
	return a.setLocked(pw)
}

// Change replaces the password after checking the current one; all sessions end.
func (a *Auth) Change(client, current, next string) error {
	if err := a.Check(client, current); err != nil {
		return err
	}
	if a.env != "" {
		return errors.New("password is set by DEPGATE_PASSWORD")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.setLocked(next)
}

func (a *Auth) setLocked(pw string) error {
	if len([]rune(pw)) < MinLength {
		return ErrTooShort
	}
	salt := randB64(16)
	h, err := derive(pw, salt, Iterations)
	if err != nil {
		return err
	}
	a.f = &file{Hash: h, Salt: salt, Iter: Iterations, Key: randB64(32), SetAt: time.Now().UTC()}
	return a.saveLocked()
}

// Check verifies pw with a per-client backoff after repeated failures.
func (a *Auth) Check(client, pw string) error {
	a.mu.Lock()
	a.refreshLocked()
	f := a.f
	at := a.fail[client]
	now := a.now()
	if at != nil && now.Before(at.until) {
		a.mu.Unlock()
		return ErrLocked
	}
	a.mu.Unlock()
	if f == nil || f.Hash == "" {
		return ErrNoPassword
	}
	got, err := derive(pw, f.Salt, f.Iter)
	if err != nil {
		return err
	}
	ok := subtle.ConstantTimeCompare([]byte(got), []byte(f.Hash)) == 1
	a.mu.Lock()
	defer a.mu.Unlock()
	if ok {
		delete(a.fail, client)
		return nil
	}
	if at == nil {
		at = &attempts{}
		a.fail[client] = at
	}
	at.n++
	if at.n >= 5 { // 5 free tries, then 2s, 4s, 8s … capped at 5 minutes
		d := time.Duration(1<<min(at.n-4, 8)) * time.Second
		at.until = now.Add(min(d, 5*time.Minute))
	}
	return ErrWrong
}

// Issue returns a signed session value valid for ttl.
func (a *Auth) Issue(ttl time.Duration) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return "", ErrNoPassword
	}
	exp := strconv.FormatInt(a.now().Add(ttl).Unix(), 10)
	return exp + "." + a.sign(exp), nil
}

// Valid checks a session value from the cookie.
func (a *Auth) Valid(v string) bool {
	exp, mac, ok := strings.Cut(v, ".")
	if !ok {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshLocked()
	if a.f == nil {
		return false
	}
	if !hmac.Equal([]byte(mac), []byte(a.sign(exp))) {
		return false
	}
	t, err := strconv.ParseInt(exp, 10, 64)
	return err == nil && a.now().Unix() < t
}

func (a *Auth) sign(s string) string {
	key, _ := base64.RawStdEncoding.DecodeString(a.f.Key)
	m := hmac.New(sha256.New, key)
	m.Write([]byte("depgate-session:" + s))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (a *Auth) saveLocked() error {
	b, err := json.MarshalIndent(a.f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
		return err
	}
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.path)
}

func derive(pw, saltB64 string, iter int) (string, error) {
	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		return "", err
	}
	k, err := pbkdf2.Key(sha256.New, pw, salt, iter, 32)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(k), nil
}

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawStdEncoding.EncodeToString(b)
}
