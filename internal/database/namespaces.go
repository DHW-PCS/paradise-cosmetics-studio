package database

import (
	"context"
	"database/sql"
)

// LockNamespaces takes fixed coordination rows in lexical order. All account
// and player writers share these rows; uniqueness uses the original business
// collation.
func LockNamespaces(ctx context.Context, tx *sql.Tx, s *Store, names ...string) error {
	for i, name := range names {
		if i > 0 && names[i-1] >= name {
			panic("namespaces must be sorted and unique")
		}
		var locked string
		if err := tx.QueryRowContext(ctx, "SELECT name FROM "+s.Table("go_account_namespaces")+" WHERE name=? FOR UPDATE", name).Scan(&locked); err != nil {
			return err
		}
	}
	return nil
}
