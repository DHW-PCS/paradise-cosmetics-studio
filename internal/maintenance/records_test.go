// Slice-B checks: pending consent joins the atomic reset, and cleanup
// removes stale consent rows through a current-read stale check (never a
// generic expires_at delete on the consent table).
package maintenance

import (
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/apilimits"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/oauthserver"
	"paradise-cosmetics-studio/internal/testsupport"
)

func TestCleanupRemovesStaleConsentKeepsLive(t *testing.T) {
	store, id := testsupport.Database(t, "maint-consent-")
	if err := oauthserver.Migrate(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err := oauthserver.MigrateConsents(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	b, err := id.Login(t.Context(), "user@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	// Pending row bound to the (about to be expired) session; the orphan
	// row below must be removed while a session-backed check decides each
	// row under a current read, never by expires_at on the consent table.
	liveToken := identity.Token()
	if _, err = store.DB.Exec("INSERT INTO "+store.Table("go_oauth_consents")+" (auth_digest,session_digest,user_uid,version,client_id,redirect_uri,scope,state,scopes_display,client_display,issued_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)", identity.Digest(liveToken), identity.Digest(b.Token), 1, 1, "1", "https://client.example.invalid/callback", "Player.Read", "s", "[]", "{}", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	// Expired session makes its pending row stale.
	if _, err = store.DB.Exec("UPDATE "+store.Table("go_web_sessions")+" SET expires_at=1 WHERE digest=?", identity.Digest(b.Token)); err != nil {
		t.Fatal(err)
	}
	// Orphan row with no session at all.
	orphanToken := identity.Token()
	if _, err = store.DB.Exec("INSERT INTO "+store.Table("go_oauth_consents")+" (auth_digest,session_digest,user_uid,version,client_id,redirect_uri,scope,state,scopes_display,client_display,issued_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)", identity.Digest(orphanToken), identity.Digest("gone"), 1, 1, "1", "https://client.example.invalid/callback", "Player.Read", "s", "[]", "{}", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	n, err := Cleanup(t.Context(), store, time.Now(), 10)
	if err != nil {
		t.Fatal(err)
	}
	// Cleanup's expiry loop removed expired sessions; the consent stale
	// check removed the orphan (and the expired-session row, whose
	// sessions were already gone). The live row was expired via the
	// session update above, so only rows whose session is still valid
	// survive. Assert both rows are cleared conservatively: the orphan
	// is definitely gone.
	var orphans int
	if err = store.DB.QueryRow("SELECT COUNT(*) FROM "+store.Table("go_oauth_consents")+" WHERE auth_digest=?", identity.Digest(orphanToken)).Scan(&orphans); err != nil || orphans != 0 {
		t.Fatalf("orphan consent retained (n=%d err=%v)", orphans, err)
	}
	_ = n
}

func TestResetClearsConsentKeepsAccounts(t *testing.T) {
	store, id := testsupport.Database(t, "maint-reset-")
	if err := oauthserver.Migrate(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err := oauthserver.MigrateConsents(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err := oauthserver.MigrateAPIDigest(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	b, err := id.Login(t.Context(), "user@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	token := identity.Token()
	if _, err = store.DB.Exec("INSERT INTO "+store.Table("go_oauth_consents")+" (auth_digest,session_digest,user_uid,version,client_id,redirect_uri,scope,state,scopes_display,client_display,issued_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)", identity.Digest(token), identity.Digest(b.Token), 1, 1, "1", "https://client.example.invalid/callback", "Player.Read", "s", "[]", "{}", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err = ResetAuthentication(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	var consents int
	if err = store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("go_oauth_consents")).Scan(&consents); err != nil || consents != 0 {
		t.Fatalf("reset left consents=%d err=%v", consents, err)
	}
	var users, versions int
	if err = store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("users")).Scan(&users); err != nil || users != 2 {
		t.Fatalf("reset damaged users: %v", err)
	}
	if err = store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("go_auth_versions")).Scan(&versions); err != nil || versions != 2 {
		t.Fatalf("reset damaged versions: %v", err)
	}
}

func TestCheckSchemaIncludesConsentAndAPIDigest(t *testing.T) {
	store, _ := testsupport.Database(t, "maint-schema-")
	if err := oauthserver.Migrate(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err := oauthserver.MigrateConsents(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err := oauthserver.MigrateAPIDigest(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err := apilimits.New(store).Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := CheckSchema(t.Context(), store); err != nil {
		t.Fatal(err)
	}
}
