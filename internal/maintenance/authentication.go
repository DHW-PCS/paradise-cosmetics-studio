// Package maintenance owns offline reset and bounded authentication cleanup.
package maintenance

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	database "paradise-cosmetics-studio/internal/database"
	"paradise-cosmetics-studio/internal/modules"
)

// Every implemented transient credential family is listed here:
// transientTables for the expiry cleanup loop (tables carrying
// expires_at), plus pendingConsents for the atomic reset only.
// Pending consent has no expires_at (M4-CONSENT-01): it is cleared by
// reset and by its own current-read stale check, never by the generic
// expiry delete.
var transientTables = []string{"go_web_sessions", "go_remember_tokens", "go_oauth_codes", "go_oauth_access", "go_oauth_refresh", "go_oauth_pkce", "go_mail_challenges", "go_captchas", "go_browser_limits", "go_web_flashes"}

// pendingConsents are cleared in the atomic auth-reset.
var pendingConsents = "go_oauth_consents"

// apiLimits is the Yggdrasil core API rate-limit counter (60/60s). Reset
// clears the counters, the expiry cleanup removes only expired rows, and
// CheckSchema requires the table; a missing table is an ordinary SQL
// error in all three, consistent with the migration contract.
var apiLimits = "go_api_limits"

// yggdrasilTables are the Yggdrasil state families. Reset clears all three
// in one transaction; Cleanup removes only expired rows per UID under the
// users lock; CheckSchema requires all three plus the retained ygg_log.
var yggdrasilTables = []string{"go_yggdrasil_tokens", "go_yggdrasil_joins", "go_yggdrasil_limits"}

// ResetAuthentication requires the exclusive deployment instance lock. It keeps
// UID versions and all account, business, key, file and outbox data.
func ResetAuthentication(ctx context.Context, store *database.Store) error {
	return store.Transaction(ctx, func(tx *sql.Tx) error {
		for _, name := range transientTables {
			if _, err := tx.ExecContext(ctx, "DELETE FROM "+store.Table(name)); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+store.Table(pendingConsents)); err != nil {
			if !isMissingTable(err, pendingConsents) {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+store.Table(apiLimits)); err != nil {
			return err
		}
		for _, name := range yggdrasilTables {
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
	// Pending consent has no expires_at; remove only rows whose bound
	// session or owner identity is stale under a current read, bounded
	// by the same batch. A still-valid pending row never falls to the
	// generic expiry delete above. The consents table appears with its
	// M4-03 migration; until the composition root wires it, cleanup
	// skips the (absent) family instead of failing older callers.
	removed, err := cleanupConsents(ctx, store, now, batch)
	if err != nil {
		return total, err
	}
	total += removed
	// API limit counters expire with their window; cleanup removes only
	// expired counters and never a live window.
	removed, err = cleanupAPILimits(ctx, store, now, batch)
	if err != nil {
		return total, err
	}
	total += removed
	removed, err = cleanupYggdrasil(ctx, store, now, batch)
	if err != nil {
		return total, err
	}
	total += removed
	return total, nil
}

// cleanupConsents discovers up to batch candidates and removes those whose
// users/version/session chain is stale, checking each candidate with a
// per-user locked current read. Discovery never decides deletion alone.
func cleanupConsents(ctx context.Context, store *database.Store, now time.Time, batch int) (int64, error) {
	rows, err := store.DB.QueryContext(ctx, "SELECT auth_digest,user_uid,version,session_digest FROM "+store.Table(pendingConsents)+" LIMIT ?", batch)
	if err != nil {
		if isMissingTable(err, pendingConsents) {
			return 0, nil
		}
		return 0, err
	}
	type candidate struct {
		authDigest, sessionDigest []byte
		uid, version              int64
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		// SELECT order is auth_digest,user_uid,version,session_digest.
		if err = rows.Scan(&c.authDigest, &c.uid, &c.version, &c.sessionDigest); err != nil {
			rows.Close()
			return 0, err
		}
		candidates = append(candidates, c)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	var removed int64
	for _, c := range candidates {
		stale := false
		err = store.Transaction(ctx, func(tx *sql.Tx) error {
			var uid int64
			if err = tx.QueryRowContext(ctx, "SELECT uid FROM "+store.Table("users")+" WHERE uid=? FOR UPDATE", c.uid).Scan(&uid); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					stale = true
					return nil
				}
				return err
			}
			var current int64
			if err = tx.QueryRowContext(ctx, "SELECT version FROM "+store.Table("go_auth_versions")+" WHERE user_uid=? FOR UPDATE", c.uid).Scan(&current); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					stale = true
					return nil
				}
				return err
			}
			if current != c.version {
				stale = true
				return nil
			}
			var userUID sql.NullInt64
			var expiry int64
			if err = tx.QueryRowContext(ctx, "SELECT user_uid,expires_at FROM "+store.Table("go_web_sessions")+" WHERE digest=?", c.sessionDigest).Scan(&userUID, &expiry); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					stale = true
					return nil
				}
				return err
			}
			if !userUID.Valid || userUID.Int64 != c.uid || expiry <= now.Unix() {
				stale = true
				return nil
			}
			return nil
		})
		if err != nil {
			return removed, err
		}
		if !stale {
			continue
		}
		result, err := store.DB.ExecContext(ctx, "DELETE FROM "+store.Table(pendingConsents)+" WHERE auth_digest=? AND session_digest=? AND user_uid=?", c.authDigest, c.sessionDigest, c.uid)
		if err != nil {
			return removed, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return removed, err
		}
		removed += n
	}
	return removed, nil
}

// cleanupAPILimits removes up to batch expired API limit counters.
func cleanupAPILimits(ctx context.Context, store *database.Store, now time.Time, batch int) (int64, error) {
	result, err := store.DB.ExecContext(ctx, "DELETE FROM "+store.Table(apiLimits)+" WHERE expires_at<=? LIMIT ?", now.Unix(), batch)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// cleanupYggdrasil removes expired Yggdrasil state. Tokens and joins are
// discovered first, then deleted per UID under that user's lock with a
// current read; a missing user row confirms an orphan and the deletion
// proceeds in the same transaction. Limits expire on their own expiry.
func cleanupYggdrasil(ctx context.Context, store *database.Store, now time.Time, batch int) (int64, error) {
	if batch <= 0 {
		return 0, fmt.Errorf("cleanup batch must be positive")
	}
	result, err := store.DB.ExecContext(ctx, "DELETE FROM "+store.Table("go_yggdrasil_limits")+" WHERE expires_at<=? LIMIT ?", now.Unix(), batch)
	if err != nil {
		return 0, err
	}
	removed, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	// Tokens: refresh_until is the discard boundary, never access_until.
	count, err := cleanupYggTokens(ctx, store, now, batch)
	if err != nil {
		return removed, err
	}
	removed += count
	joins, err := cleanupYggJoins(ctx, store, now, batch)
	if err != nil {
		return removed, err
	}
	removed += joins
	return removed, nil
}

func cleanupYggTokens(ctx context.Context, store *database.Store, now time.Time, batch int) (int64, error) {
	rows, err := store.DB.QueryContext(ctx, "SELECT DISTINCT user_uid FROM "+store.Table("go_yggdrasil_tokens")+" WHERE refresh_until<=? LIMIT ?", now.Unix(), batch)
	if err != nil {
		return 0, err
	}
	var uids []int64
	for rows.Next() {
		var uid int64
		if err = rows.Scan(&uid); err != nil {
			rows.Close()
			return 0, err
		}
		uids = append(uids, uid)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	var removed int64
	for _, uid := range uids {
		var deleted int64
		err := store.Transaction(ctx, func(tx *sql.Tx) error {
			var exists int64
			err := tx.QueryRowContext(ctx, "SELECT uid FROM "+store.Table("users")+" WHERE uid=? FOR UPDATE", uid).Scan(&exists)
			if errors.Is(err, sql.ErrNoRows) {
				result, err := tx.ExecContext(ctx, "DELETE FROM "+store.Table("go_yggdrasil_tokens")+" WHERE user_uid=? AND refresh_until<=?", uid, now.Unix())
				if err != nil {
					return err
				}
				deleted, err = result.RowsAffected()
				return err
			}
			if err != nil {
				return err
			}
			result, err := tx.ExecContext(ctx, "DELETE FROM "+store.Table("go_yggdrasil_tokens")+" WHERE user_uid=? AND refresh_until<=?", uid, now.Unix())
			if err != nil {
				return err
			}
			deleted, err = result.RowsAffected()
			return err
		})
		if err != nil {
			return removed, err
		}
		removed += deleted
	}
	return removed, nil
}

func cleanupYggJoins(ctx context.Context, store *database.Store, now time.Time, batch int) (int64, error) {
	rows, err := store.DB.QueryContext(ctx, "SELECT DISTINCT user_uid FROM "+store.Table("go_yggdrasil_joins")+" WHERE expires_at<=? LIMIT ?", now.Unix(), batch)
	if err != nil {
		return 0, err
	}
	var uids []int64
	for rows.Next() {
		var uid int64
		if err = rows.Scan(&uid); err != nil {
			rows.Close()
			return 0, err
		}
		uids = append(uids, uid)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	var removed int64
	for _, uid := range uids {
		var deleted int64
		err := store.Transaction(ctx, func(tx *sql.Tx) error {
			var exists int64
			err := tx.QueryRowContext(ctx, "SELECT uid FROM "+store.Table("users")+" WHERE uid=? FOR UPDATE", uid).Scan(&exists)
			if errors.Is(err, sql.ErrNoRows) {
				result, err := tx.ExecContext(ctx, "DELETE FROM "+store.Table("go_yggdrasil_joins")+" WHERE user_uid=? AND expires_at<=?", uid, now.Unix())
				if err != nil {
					return err
				}
				deleted, err = result.RowsAffected()
				return err
			}
			if err != nil {
				return err
			}
			result, err := tx.ExecContext(ctx, "DELETE FROM "+store.Table("go_yggdrasil_joins")+" WHERE user_uid=? AND expires_at<=?", uid, now.Unix())
			if err != nil {
				return err
			}
			deleted, err = result.RowsAffected()
			return err
		})
		if err != nil {
			return removed, err
		}
		removed += deleted
	}
	return removed, nil
}

// isMissingTable reports MySQL/MariaDB "table doesn't exist" for the
// pending-consent family before its migration is wired.
func isMissingTable(err error, table string) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return strings.Contains(text, "doesn't exist") && strings.Contains(text, table)
}

// CheckSchema is read-only. Serve and worker never perform installation or DDL.
func CheckSchema(ctx context.Context, store *database.Store) error {
	for _, name := range append(append([]string{"go_auth_versions", "go_migrations", "go_outbox", "go_account_namespaces", "go_uuid_bindings", "go_file_hashes", "go_closet_rewards", pendingConsents, apiLimits, "ygg_log"}, yggdrasilTables...), transientTables...) {
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
	// The first-party API digest column is part of the session row.
	rows, err = store.DB.QueryContext(ctx, "SELECT api_digest FROM "+store.Table("go_web_sessions")+" LIMIT 0")
	if err != nil {
		return fmt.Errorf("Go API-cookie schema unavailable; run offline migrate")
	}
	rows.Close()
	var namespaces int
	if err = store.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+store.Table("go_account_namespaces")+" WHERE name IN ('email','mail','player-name','registration','uuid')").Scan(&namespaces); err != nil {
		return err
	}
	if namespaces != 5 {
		return fmt.Errorf("Go account namespaces unavailable; run offline migrate")
	}
	if err = modules.CheckStateRows(ctx, store); err != nil {
		return err
	}
	return nil
}
