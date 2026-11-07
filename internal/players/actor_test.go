// Focused Actor checks for M4-03 players. These run against a real
// database via testsupport (skipped when M2_TEST_DSN is unset, which
// is not a pass). The fake Actor mimics the OAuth adapter contract:
// PrepareTx locks the "client", RecheckTx enforces AllOf/AnyOf against
// its granted set and the current auth version, and returns the
// current user row from the borrowed transaction.
package players

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
)

var (
	errFakeScope = errors.New("fake actor: scope not granted")
	errFakeToken = errors.New("fake actor: credential revoked")
)

type fakeActor struct {
	store      *database.Store
	uid        int64
	version    int64
	granted    []string
	revoked    bool
	prepared   bool
	lastReq    identity.ScopeRequirement
	rechecks   int
	prepareErr error
	recheckErr error
}

func newFakeActor(store *database.Store, uid int64, granted ...string) *fakeActor {
	return &fakeActor{store: store, uid: uid, version: 1, granted: granted}
}

func (f *fakeActor) UID() int64 { return f.uid }
func (f *fakeActor) Domain() string {
	return identity.DomainOAuth
}
func (f *fakeActor) PrepareTx(ctx context.Context, tx *sql.Tx) error {
	f.prepared = true
	if f.prepareErr != nil {
		return f.prepareErr
	}
	if f.revoked {
		return errFakeToken
	}
	return nil
}
func (f *fakeActor) RecheckTx(ctx context.Context, tx *sql.Tx, req identity.ScopeRequirement) (*identity.User, error) {
	f.rechecks++
	f.lastReq = req
	if f.recheckErr != nil {
		return nil, f.recheckErr
	}
	if f.revoked {
		return nil, errFakeToken
	}
	for _, want := range req.AllOf {
		if !slices.Contains(f.granted, want) && !slices.Contains(f.granted, "*") {
			return nil, errFakeScope
		}
	}
	if len(req.AnyOf) > 0 {
		ok := false
		for _, want := range req.AnyOf {
			if slices.Contains(f.granted, want) || slices.Contains(f.granted, "*") {
				ok = true
				break
			}
		}
		if !ok {
			return nil, errFakeScope
		}
	}
	var current int64
	if err := tx.QueryRowContext(ctx, "SELECT version FROM "+f.store.Table("go_auth_versions")+" WHERE user_uid=? FOR UPDATE", f.uid).Scan(&current); err != nil {
		return nil, err
	}
	if current != f.version {
		return nil, errFakeToken
	}
	var user identity.User
	err := tx.QueryRowContext(ctx, "SELECT uid,email,nickname,permission,verified,COALESCE(locale,''),is_dark_mode FROM "+f.store.Table("users")+" WHERE uid=? FOR UPDATE", f.uid).
		Scan(&user.UID, &user.Email, &user.Nickname, &user.Permission, &user.Verified, &user.Locale, &user.DarkMode)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func requireReq(t *testing.T, got identity.ScopeRequirement, allOf, anyOf []string) {
	t.Helper()
	if !slices.Equal(got.AllOf, allOf) || !slices.Equal(got.AnyOf, anyOf) {
		t.Fatalf("scope requirement = AllOf %v AnyOf %v, want AllOf %v AnyOf %v", got.AllOf, got.AnyOf, allOf, anyOf)
	}
}

func TestActorScopeRequirementsPerEntry(t *testing.T) {
	service, _, store := fixture(t, nil)
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=5000 WHERE uid IN (1,2)"); err != nil {
		t.Fatal(err)
	}
	own := insertPlayer(t, store, 1, "ActorOwnPlayer")

	user := newFakeActor(store, 1, "Player.Read", "Player.ReadWrite", "PlayersManagement.Read", "PlayersManagement.ReadWrite")
	if _, err := service.ListActor(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	requireReq(t, user.lastReq, nil, []string{"Player.Read", "Player.ReadWrite"})

	if _, err := service.AddActor(context.Background(), user, "ActorAdded"); err != nil {
		t.Fatal(err)
	}
	requireReq(t, user.lastReq, []string{"Player.ReadWrite"}, nil)

	if _, _, err := service.RenameActor(context.Background(), user, own, "ActorRenamed", Normal); err != nil {
		t.Fatal(err)
	}
	requireReq(t, user.lastReq, []string{"Player.ReadWrite"}, nil)

	if _, err := service.SetTexturesActor(context.Background(), user, own, nil, nil); err != nil {
		t.Fatal(err)
	}
	requireReq(t, user.lastReq, []string{"Player.ReadWrite"}, nil)

	if _, err := service.ClearTexturesActor(context.Background(), user, own, false, false); err != nil {
		t.Fatal(err)
	}
	requireReq(t, user.lastReq, []string{"Player.ReadWrite"}, nil)

	admin := newFakeActor(store, 2, "PlayersManagement.Read", "PlayersManagement.ReadWrite")
	if _, _, err := service.RenameActor(context.Background(), admin, own, "ActorAdminRename", Admin); err != nil {
		t.Fatal(err)
	}
	requireReq(t, admin.lastReq, []string{"PlayersManagement.ReadWrite"}, nil)

	if _, err := service.TransferActor(context.Background(), admin, own, 2); err != nil {
		t.Fatal(err)
	}
	requireReq(t, admin.lastReq, []string{"PlayersManagement.ReadWrite"}, nil)

	if err := service.AdminSetTextureActor(context.Background(), admin, own, 0, "skin"); err != nil {
		t.Fatal(err)
	}
	requireReq(t, admin.lastReq, []string{"PlayersManagement.ReadWrite"}, nil)

	if _, err := service.AdminListActor(context.Background(), admin, 1, "", "http://localhost/skin/admin/players/list"); err != nil {
		t.Fatal(err)
	}
	requireReq(t, admin.lastReq, nil, []string{"PlayersManagement.Read", "PlayersManagement.ReadWrite"})

	// Delete (normal then admin) needs a fresh own player after transfer.
	own2 := insertPlayer(t, store, 2, "ActorDeleteMe")
	if _, err := service.DeleteActor(context.Background(), admin, own2, Admin); err != nil {
		t.Fatal(err)
	}
	requireReq(t, admin.lastReq, []string{"PlayersManagement.ReadWrite"}, nil)
}

func TestActorReadAnyOfAndScopeDenial(t *testing.T) {
	service, _, store := fixture(t, nil)
	// Player.Read alone satisfies the normal read; Player.ReadWrite alone
	// also satisfies it (AnyOf). Neither fails before any business read.
	for _, granted := range [][]string{{"Player.Read"}, {"Player.ReadWrite"}} {
		actor := newFakeActor(store, 1, granted...)
		list, err := service.ListActor(context.Background(), actor)
		if err != nil {
			t.Fatalf("granted %v: %v", granted, err)
		}
		if len(list) != 1 || list[0].Name != "PlayerOne" {
			t.Fatalf("granted %v list %#v", granted, list)
		}
	}
	denied := newFakeActor(store, 1, "Closet.Read")
	if _, err := service.ListActor(context.Background(), denied); !errors.Is(err, errFakeScope) {
		t.Fatalf("unscoped list error = %v", err)
	}
	// A read scope alone must not satisfy a write.
	readOnly := newFakeActor(store, 1, "Player.Read")
	if _, err := service.AddActor(context.Background(), readOnly, "ShouldNotAdd"); !errors.Is(err, errFakeScope) {
		t.Fatalf("read-only add error = %v", err)
	}
	var count int
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("players") + " WHERE name='ShouldNotAdd'").Scan(&count)
	if count != 0 {
		t.Fatal("scope-denied add created a player")
	}
	// Admin read AnyOf, both forms.
	for _, granted := range [][]string{{"PlayersManagement.Read"}, {"PlayersManagement.ReadWrite"}} {
		actor := newFakeActor(store, 2, granted...)
		if _, err := service.AdminListActor(context.Background(), actor, 1, "", "http://localhost/skin/admin/players/list"); err != nil {
			t.Fatalf("admin granted %v: %v", granted, err)
		}
	}
	// Scope grants do not replace the current permission check.
	nonAdmin := newFakeActor(store, 1, "PlayersManagement.ReadWrite")
	if _, err := service.AdminListActor(context.Background(), nonAdmin, 1, "", "http://localhost/skin/admin/players/list"); !errors.Is(err, ErrNoPermission) {
		t.Fatalf("non-admin admin list error = %v", err)
	}
}

func TestActorAddBillingUUIDLazyAndRollback(t *testing.T) {
	service, _, store := fixture(t, nil)
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=500 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	actor := newFakeActor(store, 1, "Player.ReadWrite")
	player, err := service.AddActor(context.Background(), actor, "ActorBilled")
	if err != nil {
		t.Fatal(err)
	}
	if player.PID == 0 || scoreOf(t, store, 1) != 400 {
		t.Fatalf("billed add %#v score %d", player, scoreOf(t, store, 1))
	}
	var uuidRows, bindings int
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("uuid")).Scan(&uuidRows)
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("go_uuid_bindings")).Scan(&bindings)
	if uuidRows != 0 || bindings != 0 {
		t.Fatalf("add allocated uuid state uuid=%d bindings=%d", uuidRows, bindings)
	}
	// A charge fault rolls the insert back with no score change.
	if _, err := store.DB.Exec("CREATE TRIGGER reject_charge_actor BEFORE UPDATE ON " + store.Table("users") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic charge fault'"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AddActor(context.Background(), actor, "ActorChargeFail"); err == nil {
		t.Fatal("charge failure ignored")
	}
	var players int
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("players") + " WHERE name='ActorChargeFail'").Scan(&players)
	if players != 0 || scoreOf(t, store, 1) != 400 {
		t.Fatalf("failed add players=%d score=%d", players, scoreOf(t, store, 1))
	}
}

func TestActorCrossUserDenied(t *testing.T) {
	service, _, store := fixture(t, nil)
	other := insertPlayer(t, store, 2, "ActorOtherPlayer")
	user := newFakeActor(store, 1, "Player.ReadWrite")
	if _, _, err := service.RenameActor(context.Background(), user, other, "ActorStolen", Normal); !errors.Is(err, ErrNoPermission) {
		t.Fatalf("cross-user rename = %v", err)
	}
	if _, err := service.DeleteActor(context.Background(), user, other, Normal); !errors.Is(err, ErrNoPermission) {
		t.Fatalf("cross-user delete = %v", err)
	}
	if _, err := service.SetTexturesActor(context.Background(), user, other, nil, nil); !errors.Is(err, ErrNoPermission) {
		t.Fatalf("cross-user set textures = %v", err)
	}
	if _, err := service.ClearTexturesActor(context.Background(), user, other, true, false); !errors.Is(err, ErrNoPermission) {
		t.Fatalf("cross-user clear textures = %v", err)
	}
	// Normal list never leaks the other account's players.
	list, err := service.ListActor(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range list {
		if p.UID != 1 {
			t.Fatalf("list leaked uid %d", p.UID)
		}
	}
	var name string
	store.DB.QueryRow("SELECT name FROM "+store.Table("players")+" WHERE pid=?", other).Scan(&name)
	if name != "ActorOtherPlayer" {
		t.Fatalf("cross-user attempt changed name to %q", name)
	}
}

func TestActorAdminDemotionAndRevocation(t *testing.T) {
	service, id, store := fixture(t, nil)
	admin := newFakeActor(store, 2, "PlayersManagement.ReadWrite")
	if _, err := service.AdminListActor(context.Background(), admin, 1, "", "http://localhost/skin/admin/players/list"); err != nil {
		t.Fatal(err)
	}
	// Demotion is read from the current row in RecheckTx, so the next
	// operation fails even though the granted scope is unchanged.
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET permission=0 WHERE uid=2"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AdminListActor(context.Background(), admin, 1, "", "http://localhost/skin/admin/players/list"); !errors.Is(err, ErrNoPermission) {
		t.Fatalf("demoted admin list = %v", err)
	}
	pid := insertPlayer(t, store, 1, "ActorDemoteTarget")
	if _, err := service.TransferActor(context.Background(), admin, pid, 2); !errors.Is(err, ErrNoPermission) {
		t.Fatalf("demoted transfer = %v", err)
	}
	// Revocation bumps the auth version; the stale actor fails RecheckTx
	// and performs no billing/write.
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET permission=2,score=1000 WHERE uid=2"); err != nil {
		t.Fatal(err)
	}
	if err := store.Transaction(context.Background(), func(tx *sql.Tx) error { return id.RevokeUID(context.Background(), tx, 2) }); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AdminListActor(context.Background(), admin, 1, "", "http://localhost/skin/admin/players/list"); !errors.Is(err, errFakeToken) {
		t.Fatalf("revoked admin list = %v", err)
	}
	// A client revoked before the business transaction fails in PrepareTx.
	revoked := newFakeActor(store, 2, "PlayersManagement.ReadWrite")
	revoked.revoked = true
	if _, err := service.AdminListActor(context.Background(), revoked, 1, "", "http://localhost/skin/admin/players/list"); !errors.Is(err, errFakeToken) {
		t.Fatalf("prepare-revoked admin list = %v", err)
	}
	if revoked.rechecks != 0 {
		t.Fatalf("revoked actor reached RecheckTx %d times", revoked.rechecks)
	}
}

func TestActorAdminListIsFullPlayersPagination(t *testing.T) {
	service, _, store := fixture(t, nil)
	insertPlayer(t, store, 1, "ActorFullOne")
	insertPlayer(t, store, 2, "ActorFullTwo")
	admin := newFakeActor(store, 2, "PlayersManagement.Read")
	page, err := service.AdminListActor(context.Background(), admin, 1, "", "http://localhost/skin/admin/players/list")
	if err != nil {
		t.Fatal(err)
	}
	// Fixture seed (uid 1) + the two inserted rows, across both accounts.
	if page.Total != 3 {
		t.Fatalf("admin list total = %d, want 3 (all accounts)", page.Total)
	}
	rows, ok := page.Data.([]Player)
	if !ok || len(rows) != 3 {
		t.Fatalf("admin list data %#v", page.Data)
	}
	seen := map[int64]bool{}
	for _, row := range rows {
		seen[row.UID] = true
	}
	if !seen[1] || !seen[2] {
		t.Fatalf("admin list uids %#v", rows)
	}
	// Nil / UID-0 actors are never business actors.
	if _, err := service.ListActor(context.Background(), nil); !errors.Is(err, ErrNoPermission) {
		t.Fatalf("nil actor list = %v", err)
	}
	zero := newFakeActor(store, 0, "Player.ReadWrite")
	if _, err := service.AddActor(context.Background(), zero, "ZeroActor"); !errors.Is(err, ErrNoPermission) {
		t.Fatalf("uid-0 actor add = %v", err)
	}
}
