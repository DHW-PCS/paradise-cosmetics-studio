// Focused checks for the closet Actor entries (M4-03).
//
// The fake actor below is a test double for the frozen Actor boundary:
// it interprets ScopeRequirement AllOf/AnyOf against its granted scopes
// and returns the current users row from the borrowed transaction, so
// revocation and permission downgrade are observed at recheck time.
// Production alias interpretation lives in the Actor base and is not
// repeated here. Every test needs a real database (M2_TEST_DSN); without
// a DSN the fixture skips and nothing is claimed as passed.
package closet

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/textures"
	"blessing-skin-go/internal/users"
)

var (
	errFakeRevoked = errors.New("closet test: credential revoked")
	errFakeScope   = errors.New("closet test: scope not granted")
)

type fakeActor struct {
	store    *database.Store
	uid      int64
	scopes   []string
	revoked  bool
	prepared bool
	rechecks int
}

func (a *fakeActor) UID() int64     { return a.uid }
func (a *fakeActor) Domain() string { return identity.DomainOAuth }

func (a *fakeActor) PrepareTx(context.Context, *sql.Tx) error {
	a.prepared = true
	return nil
}

func (a *fakeActor) RecheckTx(ctx context.Context, tx *sql.Tx, req identity.ScopeRequirement) (*identity.User, error) {
	a.rechecks++
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
	err := tx.QueryRowContext(ctx, "SELECT uid,email,nickname,permission,verified,COALESCE(locale,''),is_dark_mode FROM "+a.store.Table("users")+" WHERE uid=? FOR UPDATE", a.uid).
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

func actorFor(store *database.Store, uid int64, scopes ...string) *fakeActor {
	return &fakeActor{store: store, uid: uid, scopes: scopes}
}

func closetCount(t *testing.T, env fixtureEnv, uid, tid int64) int64 {
	t.Helper()
	var count int64
	if err := env.store.DB.QueryRow("SELECT COUNT(*) FROM "+env.store.Table("user_closet")+" WHERE user_uid=? AND texture_tid=?", uid, tid).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestListActorReadAnyOf(t *testing.T) {
	env := fixture(t, nil)
	owner := login(t, env.id, "user@example.invalid")
	tid := uploadTexture(t, env, owner, "ActorList", "steve", true, 41)
	// Upload already adds the uploader's closet pivot and charges its fee.
	for _, scopes := range [][]string{{"Closet.Read"}, {"Closet.ReadWrite"}} {
		page, err := env.service.ListActor(t.Context(), actorFor(env.store, 1, scopes...), "skin", "", 1, 6, "http://localhost/closet")
		if err != nil {
			t.Fatalf("read any-of %v rejected: %v", scopes, err)
		}
		items, _ := page.Data.([]Item)
		if page.Total != 1 || len(items) != 1 || items[0].TID != tid {
			t.Fatalf("read any-of %v page = %+v items=%v", scopes, page, items)
		}
	}
	if _, err := env.service.ListActor(t.Context(), actorFor(env.store, 1, "Player.Read"), "skin", "", 1, 6, "http://localhost/closet"); !errors.Is(err, errFakeScope) {
		t.Fatalf("unrelated scope list err = %v, want scope error", err)
	}
	if _, err := env.service.ListActor(t.Context(), actorFor(env.store, 1), "skin", "", 1, 6, "http://localhost/closet"); !errors.Is(err, errFakeScope) {
		t.Fatalf("empty scope list err = %v, want scope error", err)
	}
}

func TestAddActorCrossUserPrivateTexture(t *testing.T) {
	env := fixture(t, nil)
	owner := login(t, env.id, "user@example.invalid")
	// UID 2 is the seeded admin in the shared fixture; use a plain
	// non-admin actor for the cross-user check by downgrading a copy of
	// the permission state through the current row: the actor recheck
	// reads the live permission, so a non-admin private attempt must be
	// rejected even though the scope is granted.
	tid := uploadTexture(t, env, owner, "PrivateSkin", "steve", false, 42)
	if err := env.service.Remove(t.Context(), owner, tid); err != nil {
		t.Fatal(err)
	}
	// Owner (uploader) may add their own private texture.
	if err := env.service.AddActor(t.Context(), actorFor(env.store, 1, "Closet.ReadWrite"), tid, "Mine"); err != nil {
		t.Fatalf("owner add private texture: %v", err)
	}
	// A different non-admin user must not add it. UID 2 is seeded as an
	// admin in testsupport, so temporarily drop its permission to model
	// a plain user; the recheck must observe the downgrade.
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET permission=0 WHERE uid=2"); err != nil {
		t.Fatal(err)
	}
	before := scoreOf(t, env.store, 2)
	if err := env.service.AddActor(t.Context(), actorFor(env.store, 2, "Closet.ReadWrite"), tid, "Theirs"); !errors.Is(err, ErrPrivate) {
		t.Fatalf("cross-user private add err = %v, want ErrPrivate", err)
	}
	if got := closetCount(t, env, 2, tid); got != 0 {
		t.Fatalf("private texture left a closet pivot for uid 2: %d", got)
	}
	after := scoreOf(t, env.store, 2)
	if after != before {
		t.Fatalf("rejected private add moved score: %d -> %d", before, after)
	}
}

func TestAddActorBillingRollback(t *testing.T) {
	env := fixture(t, nil)
	owner := login(t, env.id, "user@example.invalid")
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET score=1000 WHERE uid IN (1,2)"); err != nil {
		t.Fatal(err)
	}
	tid := uploadTexture(t, env, owner, "RollbackSkin", "steve", true, 43)
	if _, err := env.store.DB.Exec("CREATE TRIGGER reject_actor_refund BEFORE UPDATE ON " + env.store.Table("users") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic closet billing fault'"); err != nil {
		t.Fatal(err)
	}
	before := scoreOf(t, env.store, 2)
	uploaderBefore := scoreOf(t, env.store, 1)
	if err := env.service.AddActor(t.Context(), actorFor(env.store, 2, "Closet.ReadWrite"), tid, "Pick"); err == nil || !strings.Contains(err.Error(), "synthetic closet billing fault") {
		t.Fatalf("add did not reach the injected billing fault: %v", err)
	}
	if got := closetCount(t, env, 2, tid); got != 0 {
		t.Fatalf("failed add left a closet pivot: %d", got)
	}
	var likes int64
	env.store.DB.QueryRow("SELECT likes FROM "+env.store.Table("textures")+" WHERE tid=?", tid).Scan(&likes)
	if likes != 1 {
		t.Fatalf("failed add changed likes: %d", likes)
	}
	if got := scoreOf(t, env.store, 2); got != before {
		t.Fatalf("failed add moved score: %d -> %d", before, got)
	}
	if got := scoreOf(t, env.store, 1); got != uploaderBefore {
		t.Fatalf("failed add moved uploader score: %d -> %d", uploaderBefore, got)
	}
	// The texture itself must survive a rolled-back closet add.
	var textures int64
	env.store.DB.QueryRow("SELECT COUNT(*) FROM "+env.store.Table("textures")+" WHERE tid=?", tid).Scan(&textures)
	if textures != 1 {
		t.Fatalf("failed add removed the texture: %d", textures)
	}
}

func TestActorRevocationAndDowngrade(t *testing.T) {
	env := fixture(t, nil)
	owner := login(t, env.id, "user@example.invalid")
	tid := uploadTexture(t, env, owner, "RevokeSkin", "steve", true, 44)
	if err := env.service.Remove(t.Context(), owner, tid); err != nil {
		t.Fatal(err)
	}

	// Revoked credential: recheck fails and no write happens.
	revoked := actorFor(env.store, 1, "Closet.ReadWrite")
	revoked.revoked = true
	if err := env.service.AddActor(t.Context(), revoked, tid, "Pick"); !errors.Is(err, errFakeRevoked) {
		t.Fatalf("revoked add err = %v, want revoked error", err)
	}
	if got := closetCount(t, env, 1, tid); got != 0 {
		t.Fatalf("revoked add left a closet pivot: %d", got)
	}

	// Downgraded admin: permission is read from the current row at
	// recheck, so dropping the admin permission must deny admin writes
	// even with the management scope still granted.
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET permission=0 WHERE uid=2"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.service.AdminAddActor(t.Context(), actorFor(env.store, 2, "ClosetManagement.ReadWrite"), 1, tid); !errors.Is(err, ErrNoPermission) {
		t.Fatalf("downgraded admin add err = %v, want ErrNoPermission", err)
	}
	if got := closetCount(t, env, 1, tid); got != 0 {
		t.Fatalf("downgraded admin add left a closet pivot: %d", got)
	}
}

func TestAdminListActorTarget(t *testing.T) {
	env := fixture(t, nil)
	owner := login(t, env.id, "user@example.invalid")
	other := login(t, env.id, "admin@example.invalid")
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET score=1000 WHERE uid=2"); err != nil {
		t.Fatal(err)
	}
	tidA := uploadTexture(t, env, owner, "TargetSkin", "steve", true, 45)
	tidCape := uploadTexture(t, env, owner, "TargetCape", "cape", true, 49)
	tidB := uploadTexture(t, env, other, "OtherSkin", "steve", true, 46)
	if got := closetCount(t, env, 2, tidB); got != 1 {
		t.Fatalf("other user's upload pivot = %d, want 1", got)
	}
	// Admin (UID 2, seeded admin) reading target UID 1 sees the frozen
	// bare belongsToMany collection: every item of the target, no
	// category/q filter and no paginator, with either management read
	// scope.
	for _, scopes := range [][]string{{"ClosetManagement.Read"}, {"ClosetManagement.ReadWrite"}} {
		items, err := env.service.AdminListActor(t.Context(), actorFor(env.store, 2, scopes...), 1)
		if err != nil {
			t.Fatalf("admin target list %v: %v", scopes, err)
		}
		if len(items) != 2 || items[0].TID != tidCape || items[1].TID != tidA || items[1].Pivot.UserUID != 1 {
			t.Fatalf("admin target list %v = %+v", scopes, items)
		}
	}
	// The normal closet read scope does not authorize the admin list.
	if _, err := env.service.AdminListActor(t.Context(), actorFor(env.store, 2, "Closet.Read"), 1); !errors.Is(err, errFakeScope) {
		t.Fatalf("admin list with closet scope err = %v, want scope error", err)
	}
	// A non-admin actor cannot list another user's closet as an admin.
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET permission=0 WHERE uid=2"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.service.AdminListActor(t.Context(), actorFor(env.store, 2, "ClosetManagement.Read"), 1); !errors.Is(err, ErrNoPermission) {
		t.Fatalf("non-admin target list err = %v, want ErrNoPermission", err)
	}
}

func TestAdminAddActorReturnsFullModels(t *testing.T) {
	env := fixture(t, nil)
	owner := login(t, env.id, "user@example.invalid")
	admin := login(t, env.id, "admin@example.invalid")
	tid := uploadTexture(t, env, owner, "FullModelSkin", "steve", true, 50)
	result, err := env.service.AdminAddActor(t.Context(), actorFor(env.store, 2, "ClosetManagement.ReadWrite"), 1, tid)
	if err != nil {
		t.Fatal(err)
	}
	user, ok := result["user"].(*users.User)
	if !ok || user.Email != "user@example.invalid" || user.Nickname != "User" || user.UID != 1 {
		t.Fatalf("admin add user = %#v (%T), want full users.User", result["user"], result["user"])
	}
	texture, ok := result["texture"].(*textures.Texture)
	if !ok || texture.Name != "FullModelSkin" || texture.Type != "steve" || texture.TID != tid {
		t.Fatalf("admin add texture = %#v (%T), want full textures.Texture", result["texture"], result["texture"])
	}
	// The browser wrapper shares the kernel and returns the same shape.
	browserResult, err := env.service.AdminAdd(t.Context(), admin, 1, tid)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := browserResult["user"].(*users.User); !ok {
		t.Fatalf("browser admin add user = %#v (%T)", browserResult["user"], browserResult["user"])
	}
}

func TestAdminAddRemoveMissingTarget(t *testing.T) {
	env := fixture(t, nil)
	owner := login(t, env.id, "user@example.invalid")
	admin := login(t, env.id, "admin@example.invalid")
	tid := uploadTexture(t, env, owner, "MissingTargetSkin", "steve", true, 47)
	// Frozen contract: a deterministically missing admin target is
	// ErrTargetNotFound (route-model binding 404), not the LockUsersTx
	// stale error for a missing participant and not ErrNoPermission.
	if _, err := env.service.AdminAddActor(t.Context(), actorFor(env.store, 2, "ClosetManagement.ReadWrite"), 9999, tid); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("AdminAddActor missing target err = %v, want ErrTargetNotFound", err)
	}
	if _, err := env.service.AdminRemoveActor(t.Context(), actorFor(env.store, 2, "ClosetManagement.ReadWrite"), 9999, tid); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("AdminRemoveActor missing target err = %v, want ErrTargetNotFound", err)
	}
	// The browser wrappers share the kernel and keep the same contract.
	if _, err := env.service.AdminAdd(t.Context(), admin, 9999, tid); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("browser AdminAdd missing target err = %v, want ErrTargetNotFound", err)
	}
	if _, err := env.service.AdminRemove(t.Context(), admin, 9999, tid); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("browser AdminRemove missing target err = %v, want ErrTargetNotFound", err)
	}
	var count int64
	env.store.DB.QueryRow("SELECT COUNT(*) FROM "+env.store.Table("user_closet")+" WHERE texture_tid=?", tid).Scan(&count)
	if count != 1 || closetCount(t, env, 1, tid) != 1 || closetCount(t, env, 9999, tid) != 0 {
		t.Fatalf("missing-target writes changed the upload's sole uploader pivot: count=%d", count)
	}
}

func TestAdminListActorMissingTarget(t *testing.T) {
	env := fixture(t, nil)
	owner := login(t, env.id, "user@example.invalid")
	uploadTexture(t, env, owner, "ListMissingTarget", "steve", true, 48)
	// Deterministic missing target: explicit ErrTargetNotFound for a
	// 404 mapping, distinct from a participant conflict after discovery
	// or an identity stale error from credential recheck.
	_, err := env.service.AdminListActor(t.Context(), actorFor(env.store, 2, "ClosetManagement.Read"), 9999)
	if !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("AdminListActor missing target err = %v, want ErrTargetNotFound", err)
	}
	if errors.Is(err, identity.ErrStale) {
		t.Fatalf("AdminListActor missing target leaked ErrStale: %v", err)
	}
	if errors.Is(err, ErrNoPermission) {
		t.Fatalf("AdminListActor missing target conflated with ErrNoPermission: %v", err)
	}
}

func TestRunActorTxMissingParticipantIsConflict(t *testing.T) {
	env := fixture(t, nil)
	actor := actorFor(env.store, 1, "Closet.Read")
	// The participant set has already been discovered. A now-missing
	// row is a business conflict, not a credential recheck failure or
	// a deterministic missing admin target.
	err := env.store.Transaction(t.Context(), func(tx *sql.Tx) error {
		_, err := env.service.runActorTx(t.Context(), tx, actor, []int64{1, 9999}, closetReadRequirement())
		return err
	})
	if !errors.Is(err, ErrConflict) || errors.Is(err, identity.ErrStale) {
		t.Fatalf("missing participant err = %v, want only ErrConflict", err)
	}
}
