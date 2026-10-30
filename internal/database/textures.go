package database

import "context"

// MigrateTextures installs the additive file hash coordination table.
func MigrateTextures(ctx context.Context, s *Store) error {
	for _, m := range []struct{ name, ddl string }{
		{"013_file_hashes", "CREATE TABLE IF NOT EXISTS " + s.Table("go_file_hashes") + ` (hash VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL PRIMARY KEY,generation BIGINT NOT NULL,updated_at BIGINT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`},
	} {
		if err := s.ApplyMigration(ctx, m.name, m.ddl); err != nil {
			return err
		}
	}
	return nil
}
