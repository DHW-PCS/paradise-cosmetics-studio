package yggdrasil

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/legacy/testdb"
)

var testKey = []byte("m1-isolated-ygg-key-32bytes-long-001")

func newStore(t *testing.T, db *sql.DB) *Store {
	t.Helper()
	store := &Store{DB: db, Key: testKey, ValidTTL: 300, RefreshTTL: 600, Limit: 5, Now: time.Now}
	if err := store.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}
	return store
}

func seedYggUser(t *testing.T, db *sql.DB, email, name string) (int64, string) {
	t.Helper()
	result, err := db.Exec(`INSERT INTO users(email,nickname,password,permission,verified)
		VALUES(?,?,?,0,1)`, email, "Nick", "$2y$04$unused")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	profile := UUID5(name)
	if _, err := db.Exec("INSERT INTO players(uid,name) VALUES(?,?)", uid, name); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO uuid(name,uuid) VALUES(?,?)", name, profile); err != nil {
		t.Fatal(err)
	}
	return uid, profile
}

// TestRevokedUnknownTokenCannotBeImported covers R04: a successful revoke of a
// token that was never imported must survive a later snapshot import.
func TestRevokedUnknownTokenCannotBeImported(t *testing.T) {
	db := testdb.Open(t)
	store := newStore(t, db)
	ctx := context.Background()
	uid, profile := seedYggUser(t, db, "unknown@example.invalid", "UnknownPlayer")

	token, err := Mint(uid, "unknown@example.invalid", profile, "opaque-client", testKey, time.Now(), 300, 600)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, token.AccessToken); err != nil {
		t.Fatalf("revoke unknown token: %v", err)
	}
	if err := store.Import(ctx, token); err == nil {
		t.Fatal("revoked token was imported from a snapshot")
	}
	if _, err := store.Validate(ctx, token.AccessToken, ""); err == nil {
		t.Fatal("revoked token validated after import attempt")
	}
	if _, err := store.Refresh(ctx, token.AccessToken, "", "", ""); err == nil {
		t.Fatal("revoked token refreshed after import attempt")
	}
}

// TestRevokedImportedTokenStaysRevoked keeps the original imported-row path.
func TestRevokedImportedTokenStaysRevoked(t *testing.T) {
	db := testdb.Open(t)
	store := newStore(t, db)
	ctx := context.Background()
	uid, profile := seedYggUser(t, db, "imported@example.invalid", "ImportedPlayer")

	token, err := Mint(uid, "imported@example.invalid", profile, "", testKey, time.Now(), 300, 600)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Import(ctx, token); err != nil {
		t.Fatalf("import: %v", err)
	}
	if _, err := store.Validate(ctx, token.AccessToken, ""); err != nil {
		t.Fatalf("imported token rejected: %v", err)
	}
	if err := store.Revoke(ctx, token.AccessToken); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, token.AccessToken); err != nil {
		t.Fatalf("repeated revoke must be idempotent: %v", err)
	}
	if _, err := store.Validate(ctx, token.AccessToken, ""); err == nil {
		t.Fatal("revoked token validated")
	}
}

// TestTombstoneFailureDoesNotReportSuccess injects an insert failure.
func TestTombstoneFailureDoesNotReportSuccess(t *testing.T) {
	db := testdb.Open(t)
	store := newStore(t, db)
	ctx := context.Background()
	uid, profile := seedYggUser(t, db, "fault@example.invalid", "FaultPlayer")

	token, err := Mint(uid, "fault@example.invalid", profile, "", testKey, time.Now(), 300, 600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER m1_fail_tombstone BEFORE INSERT ON go_yggdrasil_revocations
		FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'm1 failure'`); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, token.AccessToken); err == nil {
		t.Fatal("revoke reported success while the tombstone insert failed")
	}
	// The token was never imported and must not appear from the failed revoke.
	if err := store.Import(ctx, token); err != nil {
		t.Fatalf("import after a rolled-back revoke: %v", err)
	}
}

// TestMissingTombstoneTableFailsClosed keeps the fail-closed contract: if the
// additive tombstone table is absent (for example an unadapted rollback build),
// every path that must consult it refuses instead of silently accepting revoked
// tokens.
func TestMissingTombstoneTableFailsClosed(t *testing.T) {
	db := testdb.Open(t)
	store := newStore(t, db)
	ctx := context.Background()
	uid, profile := seedYggUser(t, db, "missing@example.invalid", "MissingPlayer")

	token, err := Mint(uid, "missing@example.invalid", profile, "", testKey, time.Now(), 300, 600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DROP TABLE go_yggdrasil_revocations"); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, token.AccessToken); err == nil {
		t.Fatal("revoke reported success without the tombstone table")
	}
	if err := store.Import(ctx, token); err == nil {
		t.Fatal("import succeeded without the tombstone table")
	}
	if _, err := store.Validate(ctx, token.AccessToken, ""); err == nil {
		t.Fatal("validate succeeded without the tombstone table")
	}
}

// TestSetupIsIdempotentAndKeepsRows keeps Setup usable on a populated database:
// the additive tables are created or kept, never recreated, so a revoked token
// stays revoked and an advanced watermark is not reset.
func TestSetupIsIdempotentAndKeepsRows(t *testing.T) {
	db := testdb.Open(t)
	store := newStore(t, db)
	ctx := context.Background()
	uid, profile := seedYggUser(t, db, "setup@example.invalid", "SetupPlayer")

	token, err := Mint(uid, "setup@example.invalid", profile, "", testKey, time.Now(), 300, 600)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, token.AccessToken); err != nil {
		t.Fatal(err)
	}
	if err := store.Setup(ctx); err != nil {
		t.Fatalf("repeated setup: %v", err)
	}
	var tombstones int
	if err := db.QueryRow("SELECT COUNT(*) FROM go_yggdrasil_revocations").Scan(&tombstones); err != nil {
		t.Fatal(err)
	}
	if tombstones != 1 {
		t.Fatalf("tombstone rows after repeated setup = %d, want 1", tombstones)
	}
	if _, err := store.Validate(ctx, token.AccessToken, ""); err == nil {
		t.Fatal("revoked token validated after repeated setup")
	}
}
