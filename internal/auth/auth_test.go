package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func init() { Iterations = 1000 } // fast tests; the real work factor is 600 000

func TestSetupLoginChangeReset(t *testing.T) {
	d := t.TempDir()
	a, err := Open(d, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Configured() {
		t.Fatal("fresh store must not have a password")
	}
	if err := a.Setup("short"); err != ErrTooShort {
		t.Fatalf("short password: %v", err)
	}
	if err := a.Setup("correct horse"); err != nil {
		t.Fatal(err)
	}
	if err := a.Setup("another one!"); err != ErrHasPassword {
		t.Fatalf("second setup: %v", err)
	}
	if err := a.Check("c", "correct horse"); err != nil {
		t.Fatal(err)
	}
	if err := a.Check("c", "wrong one"); err != ErrWrong {
		t.Fatal(err)
	}
	// persisted and never in plain text
	b, _ := os.ReadFile(filepath.Join(d, "auth.json"))
	if len(b) == 0 || containsStr(string(b), "correct horse") {
		t.Fatalf("auth.json: %s", b)
	}
	st, _ := os.Stat(filepath.Join(d, "auth.json"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	a2, _ := Open(d, "")
	if err := a2.Check("c", "correct horse"); err != nil {
		t.Fatal("reload:", err)
	}
	// sessions
	s, _ := a2.Issue(time.Hour)
	if !a2.Valid(s) || a2.Valid(s+"x") || a2.Valid("123.abc") {
		t.Fatal("session validation")
	}
	// change rotates the key -> old session invalid
	if err := a2.Change("c", "correct horse", "battery staple"); err != nil {
		t.Fatal(err)
	}
	if a2.Valid(s) {
		t.Fatal("old session still valid after password change")
	}
	if err := a2.Check("c", "battery staple"); err != nil {
		t.Fatal(err)
	}
	if err := Reset(d); err != nil {
		t.Fatal(err)
	}
	a3, _ := Open(d, "")
	if a3.Configured() {
		t.Fatal("reset did not remove the password")
	}
}

func TestExpiryAndBackoff(t *testing.T) {
	a, _ := Open(t.TempDir(), "")
	_ = a.Setup("correct horse")
	now := time.Now()
	a.now = func() time.Time { return now }
	s, _ := a.Issue(time.Minute)
	now = now.Add(2 * time.Minute)
	if a.Valid(s) {
		t.Fatal("expired session accepted")
	}
	for i := 0; i < 5; i++ {
		_ = a.Check("ip1", "nope-nope")
	}
	if err := a.Check("ip1", "correct horse"); err != ErrLocked {
		t.Fatalf("expected lock, got %v", err)
	}
	if err := a.Check("ip2", "correct horse"); err != nil {
		t.Fatalf("other client blocked: %v", err)
	}
	now = now.Add(10 * time.Second)
	if err := a.Check("ip1", "correct horse"); err != nil {
		t.Fatalf("lock did not expire: %v", err)
	}
}

func TestEnvPassword(t *testing.T) {
	d := t.TempDir()
	if _, err := Open(d, "short"); err == nil {
		t.Fatal("short env password accepted")
	}
	a, err := Open(d, "from the environment")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Configured() || !a.FromEnv() {
		t.Fatal("env password not active")
	}
	if err := a.Check("c", "from the environment"); err != nil {
		t.Fatal(err)
	}
	if err := a.Change("c", "from the environment", "something else"); err == nil {
		t.Fatal("env password changed from the UI")
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestResetWhileRunning(t *testing.T) {
	d := t.TempDir()
	a, _ := Open(d, "")
	_ = a.Setup("correct horse")
	s, _ := a.Issue(time.Hour)
	if err := Reset(d); err != nil {
		t.Fatal(err)
	}
	if a.Configured() || a.Valid(s) {
		t.Fatal("running server still uses the removed password")
	}
	if err := a.Setup("battery staple"); err != nil {
		t.Fatalf("new setup after reset: %v", err)
	}
}
