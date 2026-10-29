package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
)

type migration struct{ name, ddl string }

func (s *Store) migrations() []migration {
	return []migration{
		{"001_auth_versions", "CREATE TABLE IF NOT EXISTS " + s.Table("go_auth_versions") + ` (user_uid BIGINT NOT NULL PRIMARY KEY, version BIGINT NOT NULL) ENGINE=InnoDB`},
		{"002_browser_sessions", "CREATE TABLE IF NOT EXISTS " + s.Table("go_web_sessions") + ` (
digest BINARY(32) NOT NULL PRIMARY KEY, user_uid BIGINT NULL, version BIGINT NULL,
csrf VARCHAR(64) NOT NULL, remember_digest BINARY(32) NULL, expires_at BIGINT NOT NULL,
INDEX session_expiry(expires_at), INDEX session_user(user_uid), INDEX session_remember(remember_digest)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`},
		{"003_remember_tokens", "CREATE TABLE IF NOT EXISTS " + s.Table("go_remember_tokens") + ` (
digest BINARY(32) NOT NULL PRIMARY KEY, user_uid BIGINT NOT NULL, version BIGINT NOT NULL,
expires_at BIGINT NOT NULL, INDEX remember_user(user_uid), INDEX remember_expiry(expires_at)
) ENGINE=InnoDB`},
	}
}

// Migrate only creates Go-owned additive tables for an existing installed site.
// MySQL DDL commits independently; each successful statement has its own ledger row.
func (s *Store) Migrate(ctx context.Context) error {
	var uid int64
	err := s.DB.QueryRowContext(ctx, "SELECT uid FROM "+s.Table("users")+" LIMIT 1").Scan(&uid)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("existing site users table required: %w", err)
	}
	ledger := s.Table("go_migrations")
	if _, err = s.DB.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+ledger+" (name VARCHAR(120) PRIMARY KEY, checksum BINARY(32) NOT NULL) ENGINE=InnoDB"); err != nil {
		return err
	}
	for _, m := range s.migrations() {
		if err = s.ApplyMigration(ctx, m.name, m.ddl); err != nil {
			return err
		}
	}
	return nil
}

// ApplyMigration records each successful additive DDL independently. The caller
// holds the offline instance lock; it never retries a business transaction.
func (s *Store) ApplyMigration(ctx context.Context, name, ddl string) error {
	ledger := s.Table("go_migrations")
	sum := sha256.Sum256([]byte(ddl))
	var saved []byte
	err := s.DB.QueryRowContext(ctx, "SELECT checksum FROM "+ledger+" WHERE name=?", name).Scan(&saved)
	if err == nil {
		if string(saved) != string(sum[:]) {
			return fmt.Errorf("migration checksum changed: %s", name)
		}
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	if _, err = s.DB.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("migration %s: %w", name, err)
	}
	_, err = s.DB.ExecContext(ctx, "INSERT INTO "+ledger+" (name,checksum) VALUES (?,?)", name, sum[:])
	return err
}
