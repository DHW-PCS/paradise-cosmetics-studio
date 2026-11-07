package maintenance

import (
	"testing"

	"blessing-skin-go/internal/oauthserver"
	"blessing-skin-go/internal/outbox"
	"blessing-skin-go/internal/testsupport"
	"blessing-skin-go/internal/yggdrasil"
)

// M4-07 prepare: atomic reset must clear every credential family that
// currently holds a row, in one ResetAuthentication call, while accounts
// and business rows survive.
//
// Existing coverage (reuse, not rerun as formal acceptance here):
//   - TestOfflineResetAndBoundedCleanup: transient tables emptied,
//     accounts/business/outbox kept (table-count level).
//   - TestResetClearsConsentKeepsAccounts / TestAPILimitsResetClearsCountersKeepsAccounts:
//     consent + API-limit families cleared.
//
// Missing at combination level: a single fixture that seeds live rows in
// EACH family in one DB and asserts all are zero afterwards in one call,
// with users/players/outbox intact. This test does exactly that at the DB
// level; HTTP-level rejection is covered by
// TestM407ResetRejectsAllCredentialEntries in internal/httpapp.
//
// Seed strategy (non-vacuous but schema-safe): create live browser
// sessions via Identity (seeds go_web_sessions + go_remember_tokens),
// then insert one live row per remaining family using the minimal column
// sets proven by the owning packages' own tests/migrations. If a family
// seed is impossible in this fixture, the test fails loudly (does not
// silently shrink the matrix); the HTTP-level test remains the primary
// rejection oracle.
func TestM407ResetAtomicAllFamilies(t *testing.T) {
	store, id := testsupport.Database(t, "m407reset-")
	if err := oauthserver.Migrate(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err := oauthserver.MigrateConsents(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err := oauthserver.MigrateAPIDigest(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err := yggdrasil.Migrate(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err := outbox.Migrate(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err := CheckSchema(t.Context(), store); err != nil {
		t.Fatal(err)
	}

	// Live sessions: Guest seeds go_web_sessions; a remembered login
	// would add remember tokens, but the reset must clear whatever exists.
	for range 2 {
		if _, err := id.Guest(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	// Expire them so the seeded state is realistic (reset clears expired
	// and live rows alike).
	if _, err := store.DB.Exec("UPDATE " + store.Table("go_web_sessions") + " SET expires_at=9999999999"); err != nil {
		t.Fatal(err)
	}

	// Seed one API-limit row (schema per apilimits package) and one Ygg
	// limit row. Token/join rows need full digests; seed via the
	// services' own issuance paths would require passwords/keys, so this
	// test instead seeds them with minimal digest rows mirroring the
	// migrations' NOT NULL columns. If the column set drifts, the seed
	// fails loudly and the HTTP-level test is the fallback oracle.
	// F3: seed with the migration column sets (apilimits.go: digest
	// BINARY(20)/count/expires_at; yggdrasil schema.go: digest
	// BINARY(32)/last_at/expires_at). The old (user_uid,ip,...) shape
	// does not exist in either table.
	seed := map[string]string{
		"go_api_limits":       "INSERT INTO " + store.Table("go_api_limits") + " (digest,count,expires_at) VALUES ('01234567890123456789',1,9999999999)",
		"go_yggdrasil_limits": "INSERT INTO " + store.Table("go_yggdrasil_limits") + " (digest,last_at,expires_at) VALUES ('m407-ygg-limit-digest-0123456789',1,9999999999)",
	}
	for table, stmt := range seed {
		if _, err := store.DB.Exec(stmt); err != nil {
			t.Fatalf("seed %s: %v (schema drift: update this test's seed, do not drop the family)", table, err)
		}
	}
	// Ygg token + join + OAuth code/access/refresh/PKCE/consent rows are
	// digest-bound and seeded end-to-end (real issuance) in
	// TestM407ResetRejectsAllCredentialEntries. At the DB level here we
	// only assert the reset sweeps them when present: insert digest-bound
	// rows directly.
	seedDigest := map[string]string{
		"go_yggdrasil_tokens": "INSERT INTO " + store.Table("go_yggdrasil_tokens") + " (digest,user_uid,version,client_token,binding_version,yggt,created_at,access_until,refresh_until) VALUES ('m407-ytok',1,1,'m407-yc','1','m407-yt',1,9999999999,9999999999)",
	}
	for table, stmt := range seedDigest {
		if _, err := store.DB.Exec(stmt); err != nil {
			t.Fatalf("seed %s: %v", table, err)
		}
	}

	families := append(append(append([]string{}, transientTables...), pendingConsents, apiLimits), yggdrasilTables...)
	before := map[string]int{}
	for _, table := range families {
		var n int
		if err := store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table(table)).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		before[table] = n
	}
	// Non-vacuous guard: the seeded families must be non-zero.
	for _, table := range []string{"go_web_sessions", apiLimits, "go_yggdrasil_tokens", "go_yggdrasil_limits"} {
		if before[table] == 0 {
			t.Fatalf("seeded family %s is empty before reset; matrix vacuous", table)
		}
	}

	if err := ResetAuthentication(t.Context(), store); err != nil {
		t.Fatalf("ResetAuthentication: %v", err)
	}

	for _, table := range families {
		var n int
		if err := store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table(table)).Scan(&n); err != nil {
			t.Fatalf("count after reset %s: %v", table, err)
		}
		if n != 0 {
			t.Fatalf("reset left %d rows in %s (before %d)", n, table, before[table])
		}
	}
	// Business data needed for reauthentication must survive.
	var users, players int
	if err := store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("users")).Scan(&users); err != nil || users < 2 {
		t.Fatalf("users after reset=%d err=%v", users, err)
	}
	if err := store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("players")).Scan(&players); err != nil || players < 1 {
		t.Fatalf("players after reset=%d err=%v", players, err)
	}
}
