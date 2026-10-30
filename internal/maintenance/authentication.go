// Package maintenance owns offline reset and bounded authentication cleanup.
package maintenance

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"blessing-skin-go/internal/database"
)

// Every implemented transient credential family is listed here. New domains
// must join the atomic reset before they can issue credentials.
var transientTables = []string{"go_web_sessions", "go_remember_tokens", "go_oauth_codes", "go_oauth_access", "go_oauth_refresh", "go_oauth_pkce", "go_mail_challenges", "go_captchas", "go_browser_limits", "go_web_flashes"}

// ResetAuthentication requires the exclusive deployment instance lock. It keeps
// UID versions and all account, business, key, file and outbox data.
func ResetAuthentication(ctx context.Context, store *database.Store) error {
	return store.Transaction(ctx, func(tx *sql.Tx) error {
		for _, name := range transientTables {
			if _, err := tx.ExecContext(ctx, "DELETE FROM "+store.Table(name)); err != nil {
				return err
			}
		}
		return nil
	})
}

// Cleanup bounds expiry deletion per family, followed by bounded removal of
// obsolete challenges and orphan CAPTCHA rows. Validation enforces expiry.
func Cleanup(ctx context.Context, store *database.Store, now time.Time, batch int) (int64, error) {
	if batch <= 0 {
		return 0, fmt.Errorf("cleanup batch must be positive")
	}
	var total int64
	for _, name := range transientTables {
		result, err := store.DB.ExecContext(ctx, "DELETE FROM "+store.Table(name)+" WHERE expires_at<=? LIMIT ?", now.Unix(), batch)
		if err != nil {
			return total, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return total, err
		}
		total += n
	}
	// Cleanup also removes challenges invalidated by account changes and
	// CAPTCHA rows whose session was removed. LIMIT bounds each deletion.
	for _, q := range []string{
		"DELETE FROM " + store.Table("go_mail_challenges") + " WHERE digest IN (SELECT digest FROM (SELECT c.digest FROM " + store.Table("go_mail_challenges") + " c LEFT JOIN " + store.Table("users") + " u ON u.uid=c.user_uid LEFT JOIN " + store.Table("go_auth_versions") + " v ON v.user_uid=c.user_uid WHERE u.uid IS NULL OR v.user_uid IS NULL OR v.version<>c.version OR BINARY u.email<>BINARY c.target_email LIMIT ?) AS stale)",
		"DELETE FROM " + store.Table("go_captchas") + " WHERE session_digest IN (SELECT session_digest FROM (SELECT c.session_digest FROM " + store.Table("go_captchas") + " c LEFT JOIN " + store.Table("go_web_sessions") + " w ON w.digest=c.session_digest WHERE w.digest IS NULL LIMIT ?) AS stale)",
		"DELETE FROM " + store.Table("go_web_flashes") + " WHERE (session_digest,form) IN (SELECT session_digest,form FROM (SELECT f.session_digest,f.form FROM " + store.Table("go_web_flashes") + " f LEFT JOIN " + store.Table("go_web_sessions") + " w ON w.digest=f.session_digest WHERE w.digest IS NULL LIMIT ?) AS stale)",
	} {
		result, err := store.DB.ExecContext(ctx, q, batch)
		if err != nil {
			return total, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// CheckSchema is read-only. Serve and worker never perform installation or DDL.
func CheckSchema(ctx context.Context, store *database.Store) error {
	for _, name := range append([]string{"go_auth_versions", "go_migrations", "go_outbox", "go_account_namespaces", "go_uuid_bindings", "go_file_hashes", "go_closet_rewards"}, transientTables...) {
		rows, err := store.DB.QueryContext(ctx, "SELECT 1 FROM "+store.Table(name)+" LIMIT 0")
		if err != nil {
			return fmt.Errorf("Go schema unavailable; run offline migrate")
		}
		rows.Close()
	}
	rows, err := store.DB.QueryContext(ctx, "SELECT blocked_at,error_class FROM "+store.Table("go_outbox")+" LIMIT 0")
	if err != nil {
		return fmt.Errorf("Go outbox schema unavailable; run offline migrate")
	}
	rows.Close()
	var namespaces int
	if err = store.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+store.Table("go_account_namespaces")+" WHERE name IN ('email','mail','player-name','registration','uuid')").Scan(&namespaces); err != nil {
		return err
	}
	if namespaces != 5 {
		return fmt.Errorf("Go account namespaces unavailable; run offline migrate")
	}
	return nil
}
