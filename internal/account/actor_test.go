// Focused checks for the account Actor entries (M4-03). Every test
// needs a real database (M2_TEST_DSN); without a DSN the fixture
// skips and nothing is claimed as passed.
package account_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"blessing-skin-go/internal/account"
	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
)

var (
	errFakeRevoked = errors.New("account test: credential revoked")
	errFakeScope   = errors.New("account test: scope not granted")
)

type fakeActor struct {
	store    *database.Store
	uid      int64
	scopes   []string
	revoked  bool
	prepared bool
}

func (a *fakeActor) UID() int64     { return a.uid }
func (a *fakeActor) Domain() string { return identity.DomainOAuth }
func (a *fakeActor) PrepareTx(context.Context, *sql.Tx) error {
	a.prepared = true
	return nil
}
func (a *fakeActor) RecheckTx(ctx context.Context, tx *sql.Tx, req identity.ScopeRequirement) (*identity.User, error) {
	if a.revoked {
		return nil, errFakeRevoked
	}
	for _, want := range req.AllOf {
		if !containsScope(a.scopes, want) {
			return nil, errFakeScope
		}
	}
	if len(req.AnyOf) > 0 {
		any := false
		for _, want := range req.AnyOf {
			if containsScope(a.scopes, want) {
				any = true
				break
			}
		}
		if !any {
			return nil, errFakeScope
		}
	}
	var user identity.User
	err := tx.QueryRowContext(ctx, "SELECT uid,email,nickname,permission,verified,COALESCE(locale,''),is_dark_mode FROM "+a.store.Table("users")+" WHERE uid=?", a.uid).
		Scan(&user.UID, &user.Email, &user.Nickname, &user.Permission, &user.Verified, &user.Locale, &user.DarkMode)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errFakeRevoked
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func containsScope(scopes []string, want string) bool {
	for _, scope := range scopes {
		if scope == want || scope == "*" {
			return true
		}
	}
	return false
}

func actorFor(s *account.Service, uid int64, scopes ...string) *fakeActor {
	return &fakeActor{store: s.Store, uid: uid, scopes: scopes}
}

func TestCurrentActorScopeAndCurrentRead(t *testing.T) {
	s, _, _ := fixture(t)
	user, err := s.CurrentActor(t.Context(), actorFor(s, 1, "User.Read"))
	if err != nil || user.UID != 1 || user.Email != "user@example.invalid" || user.Score != 71 {
		t.Fatalf("current = %+v err=%v", user, err)
	}
	// Current read: a separate-transaction change is observed, not a
	// snapshot from actor construction.
	if _, err := s.Store.DB.Exec("UPDATE " + s.Store.Table("users") + " SET nickname='Renamed' WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	user, err = s.CurrentActor(t.Context(), actorFor(s, 1, "User.Read"))
	if err != nil || user.Nickname != "Renamed" {
		t.Fatalf("current after rename = %+v err=%v", user, err)
	}
	if _, err := s.CurrentActor(t.Context(), actorFor(s, 1, "Player.Read")); !errors.Is(err, errFakeScope) {
		t.Fatalf("wrong scope err=%v", err)
	}
	revoked := actorFor(s, 1, "User.Read")
	revoked.revoked = true
	if _, err := s.CurrentActor(t.Context(), revoked); !errors.Is(err, errFakeRevoked) {
		t.Fatalf("revoked err=%v", err)
	}
	if _, err := s.CurrentActor(t.Context(), nil); !errors.Is(err, identity.ErrSession) {
		t.Fatalf("nil actor err=%v", err)
	}
}

func TestAdminChangeActorActionsPermissionAndRollback(t *testing.T) {
	s, _, _ := fixture(t)
	admin := func() *fakeActor { return actorFor(s, 2, "UsersManagement.ReadWrite") }
	if err := s.AdminChangeActor(t.Context(), admin(), 1, "score", "123"); err != nil {
		t.Fatal(err)
	}
	if err := s.AdminChangeActor(t.Context(), admin(), 1, "nickname", "AdminSet"); err != nil {
		t.Fatal(err)
	}
	if err := s.AdminChangeActor(t.Context(), admin(), 1, "verification", ""); err != nil {
		t.Fatal(err)
	}
	var score int64
	var nickname string
	var verified bool
	if err := s.Store.DB.QueryRow("SELECT score,nickname,verified FROM "+s.Store.Table("users")+" WHERE uid=1").Scan(&score, &nickname, &verified); err != nil {
		t.Fatal(err)
	}
	if score != 123 || nickname != "AdminSet" || verified {
		t.Fatalf("after changes score=%d nickname=%q verified=%v", score, nickname, verified)
	}
	// Non-admin actor is forbidden even with the write scope.
	if err := s.AdminChangeActor(t.Context(), actorFor(s, 1, "UsersManagement.ReadWrite"), 2, "score", "1"); !errors.Is(err, account.ErrForbidden) {
		t.Fatalf("non-admin err=%v", err)
	}
	// Wrong scope is a scope error, never a permission pass.
	if err := s.AdminChangeActor(t.Context(), actorFor(s, 2, "UsersManagement.Read"), 1, "score", "1"); !errors.Is(err, errFakeScope) {
		t.Fatalf("read scope write err=%v", err)
	}
	// Demotion in a separate transaction is observed at recheck.
	if _, err := s.Store.DB.Exec("UPDATE " + s.Store.Table("users") + " SET permission=0 WHERE uid=2"); err != nil {
		t.Fatal(err)
	}
	if err := s.AdminChangeActor(t.Context(), admin(), 1, "score", "999"); !errors.Is(err, account.ErrForbidden) {
		t.Fatalf("demoted admin err=%v", err)
	}
	if _, err := s.Store.DB.Exec("UPDATE " + s.Store.Table("users") + " SET permission=2 WHERE uid=2"); err != nil {
		t.Fatal(err)
	}
	// Rollback: a duplicate email fails and leaves the row unchanged.
	if err := s.AdminChangeActor(t.Context(), admin(), 1, "email", "admin@example.invalid"); !errors.Is(err, account.ErrEmailUsed) {
		t.Fatalf("duplicate email err=%v", err)
	}
	var email string
	if err := s.Store.DB.QueryRow("SELECT email FROM " + s.Store.Table("users") + " WHERE uid=1").Scan(&email); err != nil {
		t.Fatal(err)
	}
	if email != "user@example.invalid" {
		t.Fatalf("email after rollback = %q", email)
	}
	// Permission and password actions share the same kernel.
	if err := s.AdminChangeActor(t.Context(), admin(), 1, "permission", "1"); err != nil {
		t.Fatal(err)
	}
	if err := s.AdminChangeActor(t.Context(), admin(), 1, "permission", "0"); err != nil {
		t.Fatal(err)
	}
	if err := s.AdminChangeActor(t.Context(), admin(), 1, "password", "new-password"); err != nil {
		t.Fatal(err)
	}
	// Delete is last: the target row disappears.
	if err := s.AdminChangeActor(t.Context(), admin(), 1, "delete", ""); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.Store.DB.QueryRow("SELECT COUNT(*) FROM " + s.Store.Table("users") + " WHERE uid=1").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("deleted user still present")
	}
}
