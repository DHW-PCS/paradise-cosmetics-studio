package identity_test

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/legacy/password"
	"blessing-skin-go/internal/testsupport"
)

func TestOriginalAccountRotationRememberAndLogout(t *testing.T) {
	store, s := testsupport.Database(t, "site-")
	guest, err := s.Guest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Session(t.Context(), "old-PHP-cookie"); !errors.Is(err, identity.ErrSession) {
		t.Fatal("accepted legacy credential")
	}
	login, err := s.Login(t.Context(), "USER@EXAMPLE.INVALID", "original-password", true, guest.Token)
	if err != nil {
		t.Fatal(err)
	}
	if login.Token == guest.Token || login.CSRF == guest.CSRF || login.User.UID != 1 {
		t.Fatal("login did not rotate or preserve UID")
	}
	if _, err = s.Session(t.Context(), guest.Token); !errors.Is(err, identity.ErrSession) {
		t.Fatal("old anonymous session survived login")
	}
	other, err := s.Login(t.Context(), "playerone", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	recalled, err := s.Recall(t.Context(), login.Remember)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Logout(t.Context(), recalled.Token); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Session(t.Context(), login.Token); !errors.Is(err, identity.ErrSession) {
		t.Fatal("remember family survived logout")
	}
	if _, err = s.Recall(t.Context(), login.Remember); !errors.Is(err, identity.ErrSession) {
		t.Fatal("remember token survived logout")
	}
	if _, err = s.Session(t.Context(), other.Token); err != nil {
		t.Fatal("logout expanded to another browser")
	}
	var score int
	if err = store.DB.QueryRow("SELECT score FROM " + store.Table("users") + " WHERE uid=1").Scan(&score); err != nil || score != 71 {
		t.Fatal("login changed business score")
	}
}

func TestPasswordSnapshotCannotIssueAfterRevocation(t *testing.T) {
	store, s := testsupport.Database(t, "")
	err := s.WithPassword(t.Context(), "user@example.invalid", "original-password", identity.EmailOrPlayer, func(proof *identity.PasswordProof) error {
		if err := store.Transaction(t.Context(), func(tx *sql.Tx) error {
			var uid int
			if err := tx.QueryRow("SELECT uid FROM users WHERE uid=1 FOR UPDATE").Scan(&uid); err != nil {
				return err
			}
			return s.RevokeUID(t.Context(), tx, 1)
		}); err != nil {
			return err
		}
		return store.Transaction(t.Context(), func(tx *sql.Tx) error { _, err := s.RecheckPassword(t.Context(), tx, proof); return err })
	})
	if !errors.Is(err, identity.ErrStale) {
		t.Fatalf("stale password snapshot accepted: %v", err)
	}
}

func TestSessionExpiryAndDatabaseErrors(t *testing.T) {
	store, s := testsupport.Database(t, "")
	clock := time.Now()
	s.Now = func() time.Time { return clock }
	login, err := s.Login(t.Context(), "user@example.invalid", "original-password", true, "")
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(s.SessionLifetime)
	if _, err = s.Session(t.Context(), login.Token); !errors.Is(err, identity.ErrSession) {
		t.Fatal("expired session accepted")
	}
	if _, err = s.Recall(t.Context(), login.Remember); err != nil {
		t.Fatal(err)
	}
	if _, err = store.DB.Exec("DROP TABLE go_auth_versions"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Recall(t.Context(), login.Remember); err == nil || errors.Is(err, identity.ErrSession) {
		t.Fatal("database fault misreported as invalid credentials")
	}
}

func BenchmarkOriginalPassword(b *testing.B) {
	h, _ := password.New("BCRYPT", "")
	hash, err := h.Hash("synthetic-password")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		if ok, err := h.Verify("synthetic-password", hash); !ok || err != nil {
			b.Fatal("verifier failed")
		}
	}
}

func TestSessionPreservesIdleExpiry(t *testing.T) {
	_, s := testsupport.Database(t, "")
	clock := time.Now()
	s.Now = func() time.Time { return clock }
	login, err := s.Login(t.Context(), "user@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(s.SessionLifetime / 2)
	if _, err = s.Session(t.Context(), login.Token); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(s.SessionLifetime / 2)
	if _, err = s.Session(t.Context(), login.Token); err != nil {
		t.Fatal("active session expired at fixed issuance deadline")
	}
	clock = clock.Add(s.SessionLifetime)
	if _, err = s.Session(t.Context(), login.Token); !errors.Is(err, identity.ErrSession) {
		t.Fatal("idle session remained valid")
	}
}
