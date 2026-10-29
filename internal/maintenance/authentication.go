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
var transientTables = []string{"go_web_sessions", "go_remember_tokens", "go_oauth_codes", "go_oauth_access", "go_oauth_refresh", "go_oauth_pkce"}

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

// Cleanup performs at most one indexed batch per family. Credential validation
// already enforces expiry independently of this housekeeping schedule.
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
	return total, nil
}

// CheckSchema is read-only. Serve and worker never perform installation or DDL.
func CheckSchema(ctx context.Context, store *database.Store) error {
	for _, name := range append([]string{"go_auth_versions", "go_migrations", "go_outbox"}, transientTables...) {
		rows, err := store.DB.QueryContext(ctx, "SELECT 1 FROM "+store.Table(name)+" LIMIT 0")
		if err != nil {
			return fmt.Errorf("Go schema unavailable; run offline migrate")
		}
		rows.Close()
	}
	return nil
}
