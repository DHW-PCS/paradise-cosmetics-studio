package yggdrasil

import (
	"context"
	"database/sql"

	"paradise-cosmetics-studio/internal/database"
)

// Migrate creates the Yggdrasil state tables on the offline migration
// ledger. It never touches legacy M1 go_ygg_* tables and never imports
// legacy tokens. ygg_log keeps the legacy shape; an existing table is
// retained untouched.
func Migrate(ctx context.Context, store *database.Store) error {
	migrations := []struct{ name, ddl string }{
		{"022_yggdrasil_tokens", "CREATE TABLE IF NOT EXISTS " + store.Table("go_yggdrasil_tokens") + ` (
digest BINARY(32) NOT NULL PRIMARY KEY,
issuance_order BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
user_uid BIGINT NOT NULL,
version BIGINT NOT NULL,
client_token VARCHAR(255) NULL,
selected_pid BIGINT NULL,
selected_uuid CHAR(36) NULL,
binding_version BIGINT NULL,
yggt VARCHAR(64) NOT NULL,
created_at BIGINT NOT NULL,
access_until BIGINT NOT NULL,
refresh_until BIGINT NOT NULL,
UNIQUE KEY ygg_token_order (issuance_order),
INDEX ygg_token_user_order (user_uid,issuance_order),
INDEX ygg_token_refresh (refresh_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`},
		{"023_yggdrasil_joins", "CREATE TABLE IF NOT EXISTS " + store.Table("go_yggdrasil_joins") + ` (
digest BINARY(32) NOT NULL PRIMARY KEY,
pid BIGINT NOT NULL,
profile_uuid CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
binding_version BIGINT NOT NULL,
user_uid BIGINT NOT NULL,
version BIGINT NOT NULL,
token_digest BINARY(32) NOT NULL,
server_id VARCHAR(255) NOT NULL,
ip VARCHAR(64) NULL,
expires_at BIGINT NOT NULL,
INDEX ygg_join_expiry (expires_at),
INDEX ygg_join_user (user_uid),
INDEX ygg_join_profile (pid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`},
		{"024_yggdrasil_limits", "CREATE TABLE IF NOT EXISTS " + store.Table("go_yggdrasil_limits") + ` (
digest BINARY(32) NOT NULL PRIMARY KEY,
last_at BIGINT NOT NULL,
expires_at BIGINT NOT NULL,
INDEX ygg_limit_expiry (expires_at)
) ENGINE=InnoDB`},
		{"025_ygg_log", "CREATE TABLE IF NOT EXISTS " + store.Table("ygg_log") + ` (
id INT UNSIGNED NOT NULL PRIMARY KEY AUTO_INCREMENT,
action VARCHAR(255) NOT NULL,
user_id INT NOT NULL,
player_id INT NOT NULL,
parameters TEXT NOT NULL,
ip VARCHAR(255) NOT NULL,
time DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`},
	}
	for _, m := range migrations {
		if err := store.ApplyMigration(ctx, m.name, m.ddl); err != nil {
			return err
		}
	}
	return nil
}

// CheckReady is the module enable precondition, called with the exclusive
// module-state locks held. It only verifies that the schema exists and the
// stored private key parses as RSA. No size check and no key generation.
func (s *Service) CheckReady(ctx context.Context, tx *sql.Tx) ([]string, error) {
	for _, name := range []string{"go_yggdrasil_tokens", "go_yggdrasil_joins", "go_yggdrasil_limits", "ygg_log"} {
		rows, err := tx.QueryContext(ctx, "SELECT 1 FROM "+s.Store.Table(name)+" LIMIT 0")
		if err != nil {
			return []string{s.Store.Table(name) + " schema is missing; run offline migrate"}, nil
		}
		rows.Close()
	}
	raw, present, err := optionFromTx(ctx, tx, s.Store, "ygg_private_key")
	if err != nil {
		return nil, err
	}
	if !present || optionString(raw, present) == "" {
		return []string{"ygg_private_key is missing or empty"}, nil
	}
	if _, apiErr := ParsePrivateKey(optionString(raw, present)); apiErr != nil {
		return []string{"ygg_private_key is not a parseable RSA private key"}, nil
	}
	return nil, nil
}
