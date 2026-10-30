package database

import "context"

// MigratePlayers installs the additive UUID binding tables for existing sites.
// The original uuid table is owned by the Yggdrasil module and is never altered.
func MigratePlayers(ctx context.Context, s *Store) error {
	for _, m := range []struct{ name, ddl string }{
		{"012_uuid_bindings", "CREATE TABLE IF NOT EXISTS " + s.Table("go_uuid_bindings") + ` (pid BIGINT UNSIGNED NOT NULL PRIMARY KEY,uuid_row_id BIGINT UNSIGNED NOT NULL,uuid CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,version BIGINT NOT NULL,UNIQUE KEY binding_uuid (uuid)) ENGINE=InnoDB`},
	} {
		if err := s.ApplyMigration(ctx, m.name, m.ddl); err != nil {
			return err
		}
	}
	_, err := s.DB.ExecContext(ctx, "INSERT IGNORE INTO "+s.Table("go_account_namespaces")+" (name) VALUES ('uuid')")
	return err
}
