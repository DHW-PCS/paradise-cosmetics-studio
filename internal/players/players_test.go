package players

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/database"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/site"
	"paradise-cosmetics-studio/internal/testsupport"
)

func fixture(t *testing.T, overrides map[string]string) (*Service, *identity.Service, *database.Store) {
	t.Helper()
	store, id := testsupport.Database(t, "players-")
	options := map[string]string{
		"player_name_rule":       "official",
		"player_name_length_min": "3",
		"player_name_length_max": "16",
		"score_per_player":       "100",
		"return_score":           "true",
		"ygg_uuid_algorithm":     "v4",
		"require_verification":   "false",
		"user_initial_score":     "1000",
	}
	for key, value := range overrides {
		options[key] = value
	}
	view := &site.Service{Store: store, Identity: id, Location: time.FixedZone("site", 8*3600), OptionSnapshot: options}
	service := New(store, id, view, func() time.Time { return time.Date(2026, 10, 30, 12, 0, 0, 0, time.FixedZone("site", 8*3600)) })
	return service, id, store
}

func login(t *testing.T, id *identity.Service, email string) *identity.BrowserSession {
	t.Helper()
	b, err := id.Login(context.Background(), email, "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func insertPlayer(t *testing.T, store *database.Store, uid int64, name string) int64 {
	t.Helper()
	result, err := store.DB.Exec("INSERT INTO "+store.Table("players")+" (uid,name,tid_skin,tid_cape,last_modified) VALUES (?,?,0,0,'2026-01-01 00:00:00')", uid, name)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

func scoreOf(t *testing.T, store *database.Store, uid int64) int64 {
	t.Helper()
	var score int64
	if err := store.DB.QueryRow("SELECT score FROM "+store.Table("users")+" WHERE uid=?", uid).Scan(&score); err != nil {
		t.Fatal(err)
	}
	return score
}

func TestAddChargesAndLeavesUUIDLazy(t *testing.T) {
	service, id, store := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=500 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	player, err := service.Add(context.Background(), b, "FreshPlayer")
	if err != nil {
		t.Fatal(err)
	}
	if player.Name != "FreshPlayer" || scoreOf(t, store, 1) != 400 {
		t.Fatalf("add result %#v score %d", player, scoreOf(t, store, 1))
	}
	var uuidRows, bindings int
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("uuid")).Scan(&uuidRows)
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("go_uuid_bindings")).Scan(&bindings)
	if uuidRows != 0 || bindings != 0 {
		t.Fatalf("add allocated uuid state: uuid=%d binding=%d", uuidRows, bindings)
	}
	var tidSkin int64
	store.DB.QueryRow("SELECT tid_skin FROM "+store.Table("players")+" WHERE pid=?", player.PID).Scan(&tidSkin)
	if tidSkin != 0 {
		t.Fatalf("tid_skin default = %d, want 0", tidSkin)
	}
}

func TestAddInsufficientAndConcurrentBalance(t *testing.T) {
	service, id, store := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=100 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			name := "Parallel" + string(rune('A'+index)) + "abc"
			_, results[index] = service.Add(context.Background(), b, name)
		}(i)
	}
	wg.Wait()
	success := 0
	for _, err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrLackScore) {
			t.Fatalf("unexpected add error %v", err)
		}
	}
	if success != 1 {
		t.Fatalf("successful adds = %d, want 1 (%v)", success, results)
	}
	if score := scoreOf(t, store, 1); score != 0 {
		t.Fatalf("score after race = %d, want 0", score)
	}
	var players int
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("players") + " WHERE uid=1").Scan(&players)
	if players != 2 {
		t.Fatalf("players after race = %d, want 2 (initial + one add)", players)
	}
}

func TestAddNameCollationAndDuplicate(t *testing.T) {
	service, id, store := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=1000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Add(context.Background(), b, "Playerone"); !errors.Is(err, ErrPlayerUsed) {
		t.Fatalf("case-insensitive duplicate error = %v", err)
	}
	if _, err := service.Add(context.Background(), b, "ab"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("short name error = %v", err)
	}
	if _, err := service.Add(context.Background(), b, "bad name"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("invalid rule error = %v", err)
	}
	if score := scoreOf(t, store, 1); score != 1000 {
		t.Fatalf("failed adds charged: %d", score)
	}
}

func TestRenameV4KeepsUUIDAndVersion(t *testing.T) {
	service, id, store := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	pid := insertPlayer(t, store, 1, "RenameOne")
	binding, err := service.EnsureUUID(context.Background(), pid)
	if err != nil || binding == nil {
		t.Fatalf("ensure uuid: %v %#v", err, binding)
	}
	player, old, err := service.Rename(context.Background(), b, pid, "RenameTwo", Normal)
	if err != nil {
		t.Fatal(err)
	}
	if old != "RenameOne" || player.Name != "RenameTwo" {
		t.Fatalf("rename result %#v old=%q", player, old)
	}
	after, err := service.Binding(context.Background(), pid)
	if err != nil || after == nil {
		t.Fatalf("binding after rename: %v %#v", err, after)
	}
	if after.UUID != binding.UUID || after.Version != binding.Version {
		t.Fatalf("v4 rename changed binding: before %#v after %#v", binding, after)
	}
	var name string
	if err = store.DB.QueryRow("SELECT name FROM "+store.Table("uuid")+" WHERE id=?", binding.UUIDRowID).Scan(&name); err != nil || name != "RenameTwo" {
		t.Fatalf("uuid row name = %q err=%v", name, err)
	}
	var oldRows int
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("uuid") + " WHERE name='RenameOne'").Scan(&oldRows)
	if oldRows != 0 {
		t.Fatalf("v4 rename left old mapping rows: %d", oldRows)
	}
}

func TestRenameV4ResidualTargetConflict(t *testing.T) {
	service, id, store := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	pid := insertPlayer(t, store, 1, "ConflictOne")
	if _, err := service.EnsureUUID(context.Background(), pid); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec("INSERT INTO " + store.Table("uuid") + " (name,uuid) VALUES ('ConflictTwo','0123456789abcdef0123456789abcdef')"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Rename(context.Background(), b, pid, "ConflictTwo", Normal); !errors.Is(err, ErrUUIDConflict) {
		t.Fatalf("residual conflict error = %v", err)
	}
	var name string
	store.DB.QueryRow("SELECT name FROM "+store.Table("players")+" WHERE pid=?", pid).Scan(&name)
	if name != "ConflictOne" {
		t.Fatalf("failed rename changed name to %q", name)
	}
	var residual int
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("uuid") + " WHERE name='ConflictTwo'").Scan(&residual)
	if residual != 1 {
		t.Fatalf("residual mapping deleted: %d", residual)
	}
}

func TestRenameV3ChangesUUID(t *testing.T) {
	service, id, store := fixture(t, map[string]string{"ygg_uuid_algorithm": "v3"})
	b := login(t, id, "user@example.invalid")
	pid := insertPlayer(t, store, 1, "VthreeOne")
	binding, err := service.EnsureUUID(context.Background(), pid)
	if err != nil || binding == nil {
		t.Fatalf("ensure uuid: %v", err)
	}
	if binding.UUID != UUID3("VthreeOne") {
		t.Fatalf("v3 uuid = %q", binding.UUID)
	}
	if _, _, err = service.Rename(context.Background(), b, pid, "VthreeTwo", Normal); err != nil {
		t.Fatal(err)
	}
	after, err := service.Binding(context.Background(), pid)
	if err != nil || after == nil {
		t.Fatal(err)
	}
	if after.UUID != UUID3("VthreeTwo") || after.Version != binding.Version+1 {
		t.Fatalf("v3 binding %#v, want uuid %q version %d", after, UUID3("VthreeTwo"), binding.Version+1)
	}
	var oldRows int
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("uuid") + " WHERE name='VthreeOne'").Scan(&oldRows)
	if oldRows != 1 {
		t.Fatalf("v3 rename should keep old residual mapping, got %d", oldRows)
	}
}

func TestRenameV3AdoptsMatchingResidual(t *testing.T) {
	service, id, store := fixture(t, map[string]string{"ygg_uuid_algorithm": "v3"})
	b := login(t, id, "user@example.invalid")
	pid := insertPlayer(t, store, 1, "AdoptOne")
	if _, err := service.EnsureUUID(context.Background(), pid); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec("INSERT INTO "+store.Table("uuid")+" (name,uuid) VALUES ('AdoptTwo',?)", UUID3("AdoptTwo")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Rename(context.Background(), b, pid, "AdoptTwo", Normal); err != nil {
		t.Fatal(err)
	}
	var rows int
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("uuid") + " WHERE name='AdoptTwo'").Scan(&rows)
	if rows != 1 {
		t.Fatalf("matching residual duplicated: %d", rows)
	}
	after, _ := service.Binding(context.Background(), pid)
	if after == nil || after.UUID != UUID3("AdoptTwo") {
		t.Fatalf("binding after adopt: %#v", after)
	}
}

func TestRenameAmbiguousMappingAborts(t *testing.T) {
	service, id, store := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	pid := insertPlayer(t, store, 1, "AmbigOne")
	if _, err := store.DB.Exec("INSERT INTO " + store.Table("uuid") + " (name,uuid) VALUES ('AmbigOne','0123456789abcdef0123456789abcdef'),('AmbigOne','fedcba9876543210fedcba9876543210')"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Rename(context.Background(), b, pid, "AmbigTwo", Normal); !errors.Is(err, ErrUUIDAmbiguous) {
		t.Fatalf("ambiguous rename error = %v", err)
	}
}

func TestRenameV4MalformedLegacyWithoutBinding(t *testing.T) {
	service, id, store := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	pid := insertPlayer(t, store, 1, "LegacyOne")
	if _, err := store.DB.Exec("INSERT INTO " + store.Table("uuid") + " (name,uuid) VALUES ('LegacyOne','NOT-A-UUID')"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Rename(context.Background(), b, pid, "LegacyTwo", Normal); err != nil {
		t.Fatalf("v4 malformed legacy rename failed: %v", err)
	}
	var name string
	store.DB.QueryRow("SELECT name FROM " + store.Table("uuid") + " WHERE uuid='NOT-A-UUID'").Scan(&name)
	if name != "LegacyTwo" {
		t.Fatalf("uuid row not renamed: %q", name)
	}
	if binding, _ := service.Binding(context.Background(), pid); binding != nil {
		t.Fatalf("malformed value should not be bound: %#v", binding)
	}
}

func TestRenameBindingWithMissingUUIDTableAborts(t *testing.T) {
	service, id, store := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	pid := insertPlayer(t, store, 1, "MissingOne")
	if _, err := service.EnsureUUID(context.Background(), pid); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec("DROP TABLE " + store.Table("uuid")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Rename(context.Background(), b, pid, "MissingTwo", Normal); !errors.Is(err, ErrUUIDUnavailable) {
		t.Fatalf("missing uuid table rename error = %v", err)
	}
}

func TestDeleteRefundAdminNoRefundAndPermissions(t *testing.T) {
	service, id, store := fixture(t, nil)
	user := login(t, id, "user@example.invalid")
	admin := login(t, id, "admin@example.invalid")
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=1000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	own, err := service.Add(context.Background(), user, "OwnPlayer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.EnsureUUID(context.Background(), own.PID); err != nil {
		t.Fatal(err)
	}
	// A normal user cannot rename or delete somebody else's player.
	other := insertPlayer(t, store, 2, "AdminPlayer")
	if _, _, err = service.Rename(context.Background(), user, other, "StolenName", Normal); !errors.Is(err, ErrNoPermission) {
		t.Fatalf("cross-user rename error = %v", err)
	}
	if _, err = service.Delete(context.Background(), user, other, Normal); !errors.Is(err, ErrNoPermission) {
		t.Fatalf("cross-user delete error = %v", err)
	}
	// Admin deletion does not refund the owner.
	ownerScore := scoreOf(t, store, 2)
	if _, err = service.Delete(context.Background(), admin, other, Admin); err != nil {
		t.Fatal(err)
	}
	if score := scoreOf(t, store, 2); score != ownerScore {
		t.Fatalf("admin delete refunded: %d -> %d", ownerScore, score)
	}
	// Owner deletion refunds and keeps the uuid mapping row.
	if name, err := service.Delete(context.Background(), user, own.PID, Normal); err != nil || name != "OwnPlayer" {
		t.Fatalf("owner delete name=%q err=%v", name, err)
	}
	if score := scoreOf(t, store, 1); score != 1000 {
		t.Fatalf("owner delete refund score = %d, want 1000", score)
	}
	var uuidRows int
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("uuid") + " WHERE name='OwnPlayer'").Scan(&uuidRows)
	if uuidRows != 1 {
		t.Fatalf("delete removed uuid mapping rows: %d", uuidRows)
	}
}

func TestTransferBumpsVersionAndNickname(t *testing.T) {
	service, id, store := fixture(t, nil)
	admin := login(t, id, "admin@example.invalid")
	pid := insertPlayer(t, store, 1, "TransferOne")
	binding, err := service.EnsureUUID(context.Background(), pid)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Transfer(context.Background(), admin, pid, 2)
	if err != nil {
		t.Fatal(err)
	}
	if result.PlayerName != "TransferOne" || result.OwnerNickname != "Admin" {
		t.Fatalf("transfer result %#v", result)
	}
	var uid int64
	store.DB.QueryRow("SELECT uid FROM "+store.Table("players")+" WHERE pid=?", pid).Scan(&uid)
	if uid != 2 {
		t.Fatalf("uid after transfer = %d", uid)
	}
	after, _ := service.Binding(context.Background(), pid)
	if after == nil || after.UUID != binding.UUID || after.Version != binding.Version+1 {
		t.Fatalf("transfer binding %#v before %#v", after, binding)
	}
	// Same-owner transfer only touches last_modified.
	if _, err = service.Transfer(context.Background(), admin, pid, 2); err != nil {
		t.Fatal(err)
	}
	same, _ := service.Binding(context.Background(), pid)
	if same == nil || same.Version != after.Version {
		t.Fatalf("same-owner transfer bumped version: %#v", same)
	}
	if _, err = service.Transfer(context.Background(), admin, pid, 99); !errors.Is(err, ErrTargetMissing) {
		t.Fatalf("missing target error = %v", err)
	}
}

func TestClearTexturesKeepsBindingVersion(t *testing.T) {
	service, _, store := fixture(t, nil)
	pid := insertPlayer(t, store, 1, "ClearOne")
	if _, err := store.DB.Exec("UPDATE "+store.Table("players")+" SET tid_skin=5,tid_cape=6 WHERE pid=?", pid); err != nil {
		t.Fatal(err)
	}
	binding, err := service.EnsureUUID(context.Background(), pid)
	if err != nil {
		t.Fatal(err)
	}
	var count int64
	if err = store.Transaction(context.Background(), func(tx *sql.Tx) error {
		var inner error
		count, inner = service.ClearTexturesTx(context.Background(), tx, 1, []int64{5})
		return inner
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("cleared players = %d", count)
	}
	var skin, cape int64
	store.DB.QueryRow("SELECT tid_skin,tid_cape FROM "+store.Table("players")+" WHERE pid=?", pid).Scan(&skin, &cape)
	if skin != 0 || cape != 6 {
		t.Fatalf("textures after clear skin=%d cape=%d", skin, cape)
	}
	after, _ := service.Binding(context.Background(), pid)
	if after == nil || after.Version != binding.Version {
		t.Fatalf("clear changed binding version: %#v", after)
	}
}

func TestAddRollbackOnChargeFailure(t *testing.T) {
	service, id, store := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=1000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec("CREATE TRIGGER reject_charge BEFORE UPDATE ON " + store.Table("users") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic charge fault'"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Add(context.Background(), b, "ChargeFail"); err == nil {
		t.Fatal("charge failure ignored")
	}
	var players int
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("players") + " WHERE name='ChargeFail'").Scan(&players)
	if players != 0 {
		t.Fatalf("failed add left player rows: %d", players)
	}
	if score := scoreOf(t, store, 1); score != 1000 {
		t.Fatalf("failed add changed score: %d", score)
	}
}

func TestAdminListDSLAndPagination(t *testing.T) {
	service, _, store := fixture(t, nil)
	for _, name := range []string{"ListAlpha", "ListBeta"} {
		insertPlayer(t, store, 1, name)
	}
	page, err := service.AdminList(context.Background(), 1, "List", "http://localhost/skin/admin/players/list")
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || page.LastPage != 1 || page.From == nil || *page.From != 1 || page.To == nil || *page.To != 2 {
		t.Fatalf("paginator %#v", page)
	}
	if rows, ok := page.Data.([]Player); !ok || len(rows) != 2 {
		t.Fatalf("data %#v", page.Data)
	}
	sorted, err := service.AdminList(context.Background(), 1, "sort:-pid", "http://localhost/skin/admin/players/list")
	if err != nil {
		t.Fatal(err)
	}
	rows := sorted.Data.([]Player)
	if len(rows) != 3 || rows[0].PID <= rows[1].PID {
		t.Fatalf("sort not applied: %#v", rows)
	}
	subset, err := service.AdminList(context.Background(), 1, "fields:pid,name", "http://localhost/skin/admin/players/list")
	if err != nil {
		t.Fatal(err)
	}
	selected := subset.Data.([]map[string]any)
	if len(selected) != 3 || len(selected[0]) != 2 || selected[0]["pid"] == nil || selected[0]["name"] == nil {
		t.Fatalf("fields projection %#v", selected)
	}
	invalid, err := service.AdminList(context.Background(), -3, "unknown:1", "http://localhost/skin/admin/players/list")
	if err != nil {
		t.Fatal(err)
	}
	if invalid.CurrentPage != 1 || invalid.Total != 3 {
		t.Fatalf("invalid query/page handling %#v", invalid)
	}
}

func TestAdminListPaginationWindow(t *testing.T) {
	service, _, store := fixture(t, nil)
	for i := 0; i < 13; i++ {
		insertPlayer(t, store, 1, "PageItem"+strings.Repeat("X", i%3)+string(rune('A'+i)))
	}
	page, err := service.AdminList(context.Background(), 2, "", "http://localhost/skin/admin/players/list")
	if err != nil {
		t.Fatal(err)
	}
	if page.LastPage != 2 || page.PerPage != 10 || page.CurrentPage != 2 {
		t.Fatalf("window paginator %#v", page)
	}
	if rows := page.Data.([]Player); len(rows) != 4 {
		t.Fatalf("second page rows = %d", len(rows))
	}
	if page.PrevPageURL == nil || page.NextPageURL != nil {
		t.Fatalf("page urls prev=%v next=%v", page.PrevPageURL, page.NextPageURL)
	}
}

func TestRenameRollbackOnBindingFailure(t *testing.T) {
	service, id, store := fixture(t, map[string]string{"ygg_uuid_algorithm": "v3"})
	b := login(t, id, "user@example.invalid")
	pid := insertPlayer(t, store, 1, "RollbackOne")
	before, err := service.EnsureUUID(context.Background(), pid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.DB.Exec("CREATE TRIGGER reject_binding BEFORE UPDATE ON " + store.Table("go_uuid_bindings") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic binding fault'"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = service.Rename(context.Background(), b, pid, "RollbackTwo", Normal); err == nil {
		t.Fatal("binding failure ignored")
	}
	var name string
	store.DB.QueryRow("SELECT name FROM "+store.Table("players")+" WHERE pid=?", pid).Scan(&name)
	if name != "RollbackOne" {
		t.Fatalf("failed rename changed player name to %q", name)
	}
	after, _ := service.Binding(context.Background(), pid)
	if after == nil || after.UUID != before.UUID || after.Version != before.Version {
		t.Fatalf("failed rename changed binding: %#v", after)
	}
}

func TestTransferRollbackOnPlayerWriteFailure(t *testing.T) {
	service, id, store := fixture(t, nil)
	admin := login(t, id, "admin@example.invalid")
	pid := insertPlayer(t, store, 1, "TransferFail")
	before, err := service.EnsureUUID(context.Background(), pid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.DB.Exec("CREATE TRIGGER reject_player BEFORE UPDATE ON " + store.Table("players") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic player fault'"); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Transfer(context.Background(), admin, pid, 2); err == nil {
		t.Fatal("player write failure ignored")
	}
	var uid int64
	store.DB.QueryRow("SELECT uid FROM "+store.Table("players")+" WHERE pid=?", pid).Scan(&uid)
	if uid != 1 {
		t.Fatalf("failed transfer changed owner to %d", uid)
	}
	after, _ := service.Binding(context.Background(), pid)
	if after == nil || after.Version != before.Version {
		t.Fatalf("failed transfer bumped version: %#v", after)
	}
}

func TestDeleteRollbackOnRefundFailure(t *testing.T) {
	service, id, store := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	pid := insertPlayer(t, store, 1, "DeleteFail")
	if _, err := service.EnsureUUID(context.Background(), pid); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec("CREATE TRIGGER reject_refund BEFORE UPDATE ON " + store.Table("users") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic refund fault'"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Delete(context.Background(), b, pid, Normal); err == nil {
		t.Fatal("refund failure ignored")
	}
	var players, bindings int
	store.DB.QueryRow("SELECT COUNT(*) FROM "+store.Table("players")+" WHERE pid=?", pid).Scan(&players)
	store.DB.QueryRow("SELECT COUNT(*) FROM "+store.Table("go_uuid_bindings")+" WHERE pid=?", pid).Scan(&bindings)
	if players != 1 || bindings != 1 {
		t.Fatalf("failed delete left players=%d bindings=%d", players, bindings)
	}
}

func TestFreePlayerDeletionAndNegativeScore(t *testing.T) {
	service, id, store := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=-50 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Add(context.Background(), b, "NoScorePlayer"); !errors.Is(err, ErrLackScore) {
		t.Fatalf("negative score add error = %v", err)
	}
	var pid int64
	if err := store.DB.QueryRow("SELECT pid FROM " + store.Table("players") + " WHERE name='PlayerOne'").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Delete(context.Background(), b, pid, Normal); err != nil {
		t.Fatalf("negative score delete = %v", err)
	}
	if score := scoreOf(t, store, 1); score != 50 {
		t.Fatalf("refund from negative score = %d, want 50", score)
	}
	// A free registration player still refunds score_per_player on owner delete.
	var freePID int64
	if err := store.Transaction(context.Background(), func(tx *sql.Tx) error {
		if err := database.LockNamespaces(context.Background(), tx, store, "player-name", "uuid"); err != nil {
			return err
		}
		player, err := service.AddTx(context.Background(), tx, 1, "FreePlayer", true)
		freePID = player.PID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Delete(context.Background(), b, freePID, Normal); err != nil {
		t.Fatal(err)
	}
	if score := scoreOf(t, store, 1); score != 150 {
		t.Fatalf("free player refund = %d, want 150", score)
	}
}

func TestRenameDeleteConcurrencyStaysConsistent(t *testing.T) {
	service, id, store := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	pid := insertPlayer(t, store, 1, "RaceOriginal")
	if _, err := service.EnsureUUID(context.Background(), pid); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	var renameErr, deleteErr error
	go func() {
		defer wg.Done()
		_, _, renameErr = service.Rename(context.Background(), b, pid, "RaceRenamed", Normal)
	}()
	go func() {
		defer wg.Done()
		_, deleteErr = service.Delete(context.Background(), b, pid, Normal)
	}()
	wg.Wait()
	for _, err := range []error{renameErr, deleteErr} {
		if err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, identity.ErrSession) && !errors.Is(err, ErrConflict) {
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}
	var name string
	err := store.DB.QueryRow("SELECT name FROM "+store.Table("players")+" WHERE pid=?", pid).Scan(&name)
	var bindings int
	store.DB.QueryRow("SELECT COUNT(*) FROM "+store.Table("go_uuid_bindings")+" WHERE pid=?", pid).Scan(&bindings)
	if errors.Is(err, sql.ErrNoRows) {
		if bindings != 0 {
			t.Fatalf("deleted player kept binding: %d", bindings)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if name != "RaceOriginal" && name != "RaceRenamed" {
		t.Fatalf("unexpected final name %q", name)
	}
	if bindings != 1 {
		t.Fatalf("surviving player binding count = %d", bindings)
	}
}
