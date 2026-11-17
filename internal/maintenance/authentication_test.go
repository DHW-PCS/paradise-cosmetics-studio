package maintenance

import (
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/oauthserver"
	"paradise-cosmetics-studio/internal/outbox"
	"paradise-cosmetics-studio/internal/testsupport"
)

func TestOfflineResetAndBoundedCleanup(t *testing.T) {
	store, id := testsupport.Database(t, "reset-")
	if err := oauthserver.Migrate(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err := oauthserver.MigrateConsents(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err := oauthserver.MigrateAPIDigest(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err := outbox.Migrate(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err := CheckSchema(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	queue := &outbox.Store{Database: store, Now: time.Now}
	if err := store.Transaction(t.Context(), func(tx *sql.Tx) error {
		return queue.Enqueue(t.Context(), tx, "business-kept", "mail", json.RawMessage(`{"synthetic":true}`))
	}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := id.Guest(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.DB.Exec("UPDATE " + store.Table("go_web_sessions") + " SET expires_at=1"); err != nil {
		t.Fatal(err)
	}
	n, err := Cleanup(t.Context(), store, time.Now(), 2)
	if err != nil || n != 2 {
		t.Fatalf("batch=%d err=%v", n, err)
	}
	if err = ResetAuthentication(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	for _, table := range transientTables {
		var count int
		if err = store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table(table)).Scan(&count); err != nil || count != 0 {
			t.Fatalf("reset %s failed", table)
		}
	}
	for table, want := range map[string]int{"users": 2, "oauth_clients": 3, "players": 1, "go_outbox": 1, "go_auth_versions": 2} {
		var n int
		if err = store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table(table)).Scan(&n); err != nil || n != want {
			t.Fatalf("reset damaged %s", table)
		}
	}
}

func TestCleanupBatchMeasurement(t *testing.T) {
	store, _ := testsupport.Database(t, "capacity_")
	if err := oauthserver.Migrate(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	err := store.Transaction(t.Context(), func(tx *sql.Tx) error {
		statement, err := tx.PrepareContext(t.Context(), "INSERT INTO "+store.Table("go_web_sessions")+" (digest,csrf,expires_at) VALUES (?,?,1)")
		if err != nil {
			return err
		}
		defer statement.Close()
		for range 1000 {
			if _, err = statement.ExecContext(t.Context(), identity.Digest(identity.Token()), identity.Token()); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := store.DB.Query("ANALYZE TABLE " + store.Table("go_web_sessions"))
	if err != nil {
		t.Fatal(err)
	}
	rows.Close()
	var allocated, indexed int64
	err = store.DB.QueryRow("SELECT DATA_LENGTH,INDEX_LENGTH FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", store.Prefix+"go_web_sessions").Scan(&allocated, &indexed)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	n, err := Cleanup(t.Context(), store, time.Now(), 500)
	elapsed := time.Since(start)
	if err != nil || n != 500 {
		t.Fatalf("cleanup batch n=%d err=%v", n, err)
	}
	t.Logf("synthetic_sessions=1000 data_bytes=%d index_bytes=%d delete_rows=%d elapsed=%s", allocated, indexed, n, elapsed)
}

func TestAccountTemporaryResetRollbackAndCleanup(t *testing.T) {
	store, id := testsupport.Database(t, "account-reset-")
	if err := oauthserver.Migrate(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	b, err := id.Guest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.DB.Exec("INSERT INTO "+store.Table("go_captchas")+" VALUES (?,?,?)", identity.Digest(b.Token), identity.Digest("answer"), b.Expires.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err = store.DB.Exec("INSERT INTO "+store.Table("go_mail_challenges")+" (digest,user_uid,version,purpose,target_email,issued_at) VALUES (?,1,1,'verify','other@example.invalid',1)", identity.Digest("challenge")); err != nil {
		t.Fatal(err)
	}
	if _, err = store.DB.Exec("CREATE TRIGGER reject_reset BEFORE DELETE ON " + store.Table("go_captchas") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic reset fault'"); err != nil {
		t.Fatal(err)
	}
	if err = ResetAuthentication(t.Context(), store); err == nil {
		t.Fatal("reset failure ignored")
	}
	if _, err = id.Session(t.Context(), b.Token); err != nil {
		t.Fatal("failed reset was partially committed", err)
	}
	if _, err = store.DB.Exec("DROP TRIGGER reject_reset"); err != nil {
		t.Fatal(err)
	}
	if n, err := Cleanup(t.Context(), store, time.Now(), 1); err != nil || n != 1 {
		t.Fatalf("stale-email challenge cleanup n=%d err=%v", n, err)
	}
	if err = ResetAuthentication(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if _, err = id.Session(t.Context(), b.Token); !errors.Is(err, identity.ErrSession) {
		t.Fatal("successful reset retained session")
	}
	var namespaces int
	if err = store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("go_account_namespaces")).Scan(&namespaces); err != nil || namespaces != 5 {
		t.Fatal("reset deleted business coordination", err)
	}
	var uuidNamespace int
	if err = store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("go_account_namespaces") + " WHERE name='uuid'").Scan(&uuidNamespace); err != nil || uuidNamespace != 1 {
		t.Fatal("reset deleted uuid coordination", err)
	}
}
