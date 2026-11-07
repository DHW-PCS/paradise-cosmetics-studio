package modules

import (
	"context"
	"errors"

	"blessing-skin-go/internal/database"
)

// CheckStateRows is a read-only schema/state check for serve and worker: both
// authoritative module option rows must exist exactly once. Duplicates keep
// their history and fail reads; missing rows require the offline takeover.
func CheckStateRows(ctx context.Context, store *database.Store) error {
	for _, key := range stateKeys {
		var count int
		if err := store.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+store.Table("options")+" WHERE option_name=?", key).Scan(&count); err != nil {
			return errors.New("Go schema unavailable; run offline migrate")
		}
		if count > 1 {
			return errors.New("duplicate module state option rows; run offline diagnostics")
		}
		if count == 0 {
			return errors.New("Go module state rows missing; run offline migrate")
		}
	}
	return nil
}
