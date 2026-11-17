// Slice-B focused checks for the Actor boundary and the first-party API
// cookie (real database via testsupport).
package identity_test

import (
	"database/sql"
	"errors"
	"testing"

	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/testsupport"
)

func mustLogin(t *testing.T, s *identity.Service, email string) *identity.BrowserSession {
	t.Helper()
	b, err := s.Login(t.Context(), email, "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBrowserActorRecheckMatchesSessionCheck(t *testing.T) {
	store, s := testsupport.Database(t, "actor-")
	b := mustLogin(t, s, "user@example.invalid")
	actor, err := s.NewBrowserActor(b)
	if err != nil {
		t.Fatal(err)
	}
	if actor.UID() != 1 || actor.Domain() != identity.DomainBrowser {
		t.Fatalf("actor identity = %d/%q", actor.UID(), actor.Domain())
	}
	err = store.Transaction(t.Context(), func(tx *sql.Tx) error {
		if err = actor.PrepareTx(t.Context(), tx); err != nil {
			return err
		}
		if err = s.LockUsersTx(t.Context(), tx, []int64{2, 1}); err != nil {
			return err
		}
		u, err := actor.RecheckTx(t.Context(), tx, identity.ScopeRequirement{})
		if err != nil {
			return err
		}
		if u.UID != 1 {
			t.Fatalf("rechecked uid=%d", u.UID)
		}
		// Browser actors ignore scope requirements entirely; the
		// real session check above remains authoritative.
		u, err = actor.RecheckTx(t.Context(), tx, identity.ScopeRequirement{AllOf: []string{"Nope.Read"}, AnyOf: []string{"Also.Nope"}})
		if err != nil {
			return err
		}
		if u.UID != 1 {
			t.Fatalf("rechecked uid=%d with ignored requirement", u.UID)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Revocation between entry validation and recheck must fail.
	if err = store.Transaction(t.Context(), func(tx *sql.Tx) error {
		return s.RevokeUID(t.Context(), tx, 1)
	}); err != nil {
		t.Fatal(err)
	}
	err = store.Transaction(t.Context(), func(tx *sql.Tx) error {
		_, err := actor.RecheckTx(t.Context(), tx, identity.ScopeRequirement{})
		return err
	})
	if !errors.Is(err, identity.ErrSession) {
		t.Fatalf("stale actor rechecked: %v", err)
	}
	if _, err = s.NewBrowserActor(&identity.BrowserSession{}); !errors.Is(err, identity.ErrSession) {
		t.Fatalf("anonymous actor accepted: %v", err)
	}
}

func TestLockUsersTxSortsParticipants(t *testing.T) {
	store, s := testsupport.Database(t, "actor-lock-")
	for _, entry := range []struct {
		name string
		lock func(*sql.Tx, []int64) error
	}{
		{"helper", func(tx *sql.Tx, uids []int64) error {
			return identity.LockUsersTx(t.Context(), tx, store, uids)
		}},
		{"service", func(tx *sql.Tx, uids []int64) error {
			return s.LockUsersTx(t.Context(), tx, uids)
		}},
	} {
		t.Run(entry.name, func(t *testing.T) {
			err := store.Transaction(t.Context(), func(tx *sql.Tx) error {
				// Unsorted, duplicate, and zero UIDs retain the existing rules.
				return entry.lock(tx, []int64{2, 0, 1, 2})
			})
			if err != nil {
				t.Fatal(err)
			}
			err = store.Transaction(t.Context(), func(tx *sql.Tx) error {
				return entry.lock(tx, []int64{1, 99})
			})
			if !errors.Is(err, identity.ErrStale) {
				t.Fatalf("missing participant accepted: %v", err)
			}
		})
	}
}

func TestAPICookieIssueRotateCSRFAndLogout(t *testing.T) {
	store, s := testsupport.Database(t, "actor-api-")
	// The synthetic fixture does not carry the slice-B API digest column;
	// IssueAPI operates on it, so install it here (production wiring
	// stays with oauthserver.MigrateAPIDigest).
	if _, err := store.DB.Exec("ALTER TABLE " + store.Table("go_web_sessions") + " ADD COLUMN api_digest BINARY(32) NULL, ADD UNIQUE INDEX api_digest_unique(api_digest)"); err != nil {
		t.Fatal(err)
	}
	b := mustLogin(t, s, "user@example.invalid")
	first, err := s.IssueAPI(t.Context(), b.Token)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := s.ValidateAPI(t.Context(), first, b.CSRF)
	if err != nil || checked.User.UID != 1 {
		t.Fatalf("api validate: %v", err)
	}
	if _, err = s.ValidateAPI(t.Context(), first, "wrong-csrf"); !errors.Is(err, identity.ErrSession) {
		t.Fatalf("api csr mismatched accepted: %v", err)
	}
	// Rotation invalidates the previous secret immediately.
	second, err := s.IssueAPI(t.Context(), b.Token)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("rotation kept the secret")
	}
	if _, err = s.ValidateAPI(t.Context(), first, b.CSRF); !errors.Is(err, identity.ErrSession) {
		t.Fatalf("rotated secret accepted: %v", err)
	}
	if _, err = s.ValidateAPI(t.Context(), second, b.CSRF); err != nil {
		t.Fatalf("rotated secret rejected: %v", err)
	}
	// The secret is never a browser session or an OAuth bearer: session
	// lookup and actor construction must refuse it.
	if _, err = s.Session(t.Context(), second); !errors.Is(err, identity.ErrSession) {
		t.Fatalf("api secret accepted as session: %v", err)
	}
	// Logout removes the session row and with it the API digest.
	if err = s.Logout(t.Context(), b.Token); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ValidateAPI(t.Context(), second, b.CSRF); !errors.Is(err, identity.ErrSession) {
		t.Fatalf("api secret survived logout: %v", err)
	}
	// Another user's API cookie never resolves for this session.
	other := mustLogin(t, s, "admin@example.invalid")
	otherSecret, err := s.IssueAPI(t.Context(), other.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ValidateAPI(t.Context(), otherSecret, other.CSRF); err != nil {
		t.Fatalf("other user api cookie rejected: %v", err)
	}
}

func apiCookieActorFixture(t *testing.T) (*identity.Service, *identity.BrowserSession, identity.Actor) {
	t.Helper()
	store, s := testsupport.Database(t, "actor-api-recheck-")
	if _, err := store.DB.Exec("ALTER TABLE " + store.Table("go_web_sessions") + " ADD COLUMN api_digest BINARY(32) NULL, ADD UNIQUE INDEX api_digest_unique(api_digest)"); err != nil {
		t.Fatal(err)
	}
	b := mustLogin(t, s, "admin@example.invalid")
	secret, err := s.IssueAPI(t.Context(), b.Token)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := s.ValidateAPI(t.Context(), secret, b.CSRF)
	if err != nil {
		t.Fatal(err)
	}
	if validated.Token != "" {
		t.Fatal("API-cookie validation supplied a web token")
	}
	actor, err := s.NewAPICookieActor(validated)
	if err != nil {
		t.Fatal(err)
	}
	return s, b, actor
}

func TestAPICookieActorRecheckUsesBorrowedTxAndCurrentUser(t *testing.T) {
	s, b, actor := apiCookieActorFixture(t)
	if actor.UID() != b.User.UID || actor.Domain() != identity.DomainAPICookie {
		t.Fatalf("API-cookie actor identity = %d/%q", actor.UID(), actor.Domain())
	}
	if _, err := s.NewAPICookieActor(b); !errors.Is(err, identity.ErrSession) {
		t.Fatal("web session accepted as an API-cookie proof")
	}
	if _, err := s.NewAPICookieActor(nil); !errors.Is(err, identity.ErrSession) {
		t.Fatal("nil API-cookie proof accepted")
	}
	tx, err := s.Store.DB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// Pin an old snapshot before a separate transaction commits demotion.
	var permission int
	var verified bool
	var originalNickname string
	if err = tx.QueryRowContext(t.Context(), "SELECT permission,verified,nickname FROM "+s.Store.Table("users")+" WHERE uid=?", actor.UID()).Scan(&permission, &verified, &originalNickname); err != nil {
		t.Fatal(err)
	}
	if permission != 2 || !verified {
		t.Fatal("fixture did not start with a verified admin")
	}
	if err = s.Store.Transaction(t.Context(), func(other *sql.Tx) error {
		_, err := other.ExecContext(t.Context(), "UPDATE "+s.Store.Table("users")+" SET permission=0,verified=0 WHERE uid=?", actor.UID())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err = actor.PrepareTx(t.Context(), tx); err != nil {
		t.Fatal(err)
	}
	if err = identity.LockUsersTx(t.Context(), tx, s.Store, []int64{actor.UID()}); err != nil {
		t.Fatal(err)
	}
	current, err := actor.RecheckTx(t.Context(), tx, identity.ScopeRequirement{AllOf: []string{"Nope.Read"}, AnyOf: []string{"Also.Nope"}})
	if err != nil {
		t.Fatal(err)
	}
	if current.UID != actor.UID() || current.Permission != 0 || current.Verified {
		t.Fatal("API-cookie recheck did not return the current user")
	}
	if _, err = tx.ExecContext(t.Context(), "UPDATE "+s.Store.Table("users")+" SET nickname=? WHERE uid=?", "Uncommitted API-cookie change", actor.UID()); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var nickname string
	if err = s.Store.DB.QueryRowContext(t.Context(), "SELECT nickname FROM "+s.Store.Table("users")+" WHERE uid=?", actor.UID()).Scan(&nickname); err != nil {
		t.Fatal(err)
	}
	if nickname != originalNickname {
		t.Fatal("API-cookie recheck committed the owner's transaction")
	}
}

func TestAPICookieActorRecheckRejectsInvalidatedProof(t *testing.T) {
	for _, reason := range []string{"rotate", "revoke", "logout", "expiry", "csrf", "banned"} {
		t.Run(reason, func(t *testing.T) {
			s, b, actor := apiCookieActorFixture(t)
			var err error
			switch reason {
			case "rotate":
				_, err = s.IssueAPI(t.Context(), b.Token)
			case "revoke":
				err = s.Store.Transaction(t.Context(), func(tx *sql.Tx) error {
					if err := identity.LockUsersTx(t.Context(), tx, s.Store, []int64{actor.UID()}); err != nil {
						return err
					}
					return s.RevokeUID(t.Context(), tx, actor.UID())
				})
			case "logout":
				err = s.Logout(t.Context(), b.Token)
			case "expiry":
				_, err = s.Store.DB.ExecContext(t.Context(), "UPDATE "+s.Store.Table("go_web_sessions")+" SET expires_at=? WHERE digest=?", s.Now().Unix(), identity.Digest(b.Token))
			case "csrf":
				_, err = s.Store.DB.ExecContext(t.Context(), "UPDATE "+s.Store.Table("go_web_sessions")+" SET csrf=? WHERE digest=?", "changed-csrf", identity.Digest(b.Token))
			case "banned":
				_, err = s.Store.DB.ExecContext(t.Context(), "UPDATE "+s.Store.Table("users")+" SET permission=-1 WHERE uid=?", actor.UID())
			}
			if err != nil {
				t.Fatal(err)
			}
			var current *identity.User
			err = s.Store.Transaction(t.Context(), func(tx *sql.Tx) error {
				if err := actor.PrepareTx(t.Context(), tx); err != nil {
					return err
				}
				if err := identity.LockUsersTx(t.Context(), tx, s.Store, []int64{actor.UID()}); err != nil {
					return err
				}
				var err error
				current, err = actor.RecheckTx(t.Context(), tx, identity.ScopeRequirement{})
				return err
			})
			if !errors.Is(err, identity.ErrSession) || current != nil {
				t.Fatalf("invalidated API-cookie proof accepted: %v", err)
			}
		})
	}
}
