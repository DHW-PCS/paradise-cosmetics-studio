// Focused checks for the admin users Actor entry (M4-03). Every test
// needs a real database (M2_TEST_DSN); without a DSN the fixture
// skips and nothing is claimed as passed.
package users_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/database"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/site"
	"paradise-cosmetics-studio/internal/testsupport"
	"paradise-cosmetics-studio/internal/users"
)

var (
	errFakeRevoked = errors.New("users test: credential revoked")
	errFakeScope   = errors.New("users test: scope not granted")
)

type fakeActor struct {
	store   *database.Store
	uid     int64
	scopes  []string
	revoked bool
}

func (a *fakeActor) UID() int64     { return a.uid }
func (a *fakeActor) Domain() string { return identity.DomainOAuth }
func (a *fakeActor) PrepareTx(context.Context, *sql.Tx) error {
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

func fixture(t *testing.T) (*users.Service, *database.Store) {
	t.Helper()
	store, _ := testsupport.Database(t, "users-actor-")
	view := &site.Service{Store: store, Location: time.UTC}
	return users.New(store, view, time.Now), store
}

func actorFor(store *database.Store, uid int64, scopes ...string) *fakeActor {
	return &fakeActor{store: store, uid: uid, scopes: scopes}
}

func TestListActorAnyOfPermissionAndDemotion(t *testing.T) {
	s, store := fixture(t)
	for _, scopes := range [][]string{{"UsersManagement.Read"}, {"UsersManagement.ReadWrite"}} {
		page, err := s.ListActor(t.Context(), actorFor(store, 2, scopes...), 1, "", "http://localhost/admin/users")
		if err != nil {
			t.Fatalf("any-of %v: %v", scopes, err)
		}
		if page.Total != 2 {
			t.Fatalf("any-of %v total=%d", scopes, page.Total)
		}
	}
	if _, err := s.ListActor(t.Context(), actorFor(store, 2, "Player.Read"), 1, "", "http://localhost/admin/users"); !errors.Is(err, errFakeScope) {
		t.Fatalf("wrong scope err=%v", err)
	}
	// A scoped non-admin is still forbidden by the current permission.
	if _, err := s.ListActor(t.Context(), actorFor(store, 1, "UsersManagement.ReadWrite"), 1, "", "http://localhost/admin/users"); !errors.Is(err, users.ErrNoPermission) {
		t.Fatalf("non-admin err=%v", err)
	}
	// Demotion in a separate transaction is observed at recheck.
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET permission=0 WHERE uid=2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListActor(t.Context(), actorFor(store, 2, "UsersManagement.Read"), 1, "", "http://localhost/admin/users"); !errors.Is(err, users.ErrNoPermission) {
		t.Fatalf("demoted err=%v", err)
	}
	revoked := actorFor(store, 2, "UsersManagement.Read")
	revoked.revoked = true
	if _, err := s.ListActor(t.Context(), revoked, 1, "", "http://localhost/admin/users"); !errors.Is(err, errFakeRevoked) {
		t.Fatalf("revoked err=%v", err)
	}
}
