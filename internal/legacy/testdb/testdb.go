// Package testdb provisions a disposable MySQL database for integration tests.
//
// It never touches production: the caller must point M1_TEST_DSN at an isolated
// server, and every test creates and drops its own database.
package testdb

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/go-sql-driver/mysql"

	"paradise-cosmetics-studio/internal/legacy/revocation"
)

// Open returns a connection to a new, empty database. The database is dropped
// when the test ends.
func Open(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("M1_TEST_DSN")
	if dsn == "" {
		t.Skip("M1_TEST_DSN is not set; skipping database integration test")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("testdb: parse M1_TEST_DSN: %v", err)
	}
	if os.Getenv("M1_TEST_ALLOW_REMOTE") != "1" {
		host, _, splitErr := net.SplitHostPort(cfg.Addr)
		if splitErr != nil {
			host = cfg.Addr
		}
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			t.Fatalf("testdb: M1_TEST_DSN must point at a loopback server (set M1_TEST_ALLOW_REMOTE=1 to override)")
		}
	}
	cfg.DBName = ""
	cfg.ParseTime = true
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatalf("testdb: open: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close() })

	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("testdb: random name: %v", err)
	}
	name := "pcs_go_it_" + hex.EncodeToString(buf)
	if _, err := admin.Exec("CREATE DATABASE `" + name + "` DEFAULT CHARACTER SET utf8mb4"); err != nil {
		t.Fatalf("testdb: create database: %v", err)
	}

	cfg.DBName = name
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatalf("testdb: open database: %v", err)
	}
	db.SetMaxOpenConns(8)
	if err := db.Ping(); err != nil {
		t.Fatalf("testdb: ping: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		_, _ = admin.Exec("DROP DATABASE IF EXISTS `" + name + "`")
	})
	if err := schema(db); err != nil {
		t.Fatalf("testdb: schema: %v", err)
	}
	return db
}

// schema is the minimal legacy subset the M1 authentication and Yggdrasil
// ledger code reads and writes.
func schema(db *sql.DB) error {
	statements := []string{
		`CREATE TABLE users (
			uid BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			email VARCHAR(255) NOT NULL,
			nickname VARCHAR(255) NOT NULL,
			password VARCHAR(255) NOT NULL,
			permission INT NOT NULL DEFAULT 0,
			verified TINYINT NOT NULL DEFAULT 1,
			remember_token VARCHAR(100) NULL,
			score BIGINT NOT NULL DEFAULT 0
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE players (
			pid BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			uid BIGINT NOT NULL,
			name VARCHAR(100) NOT NULL,
			tid_skin BIGINT NOT NULL DEFAULT 0,
			tid_cape BIGINT NOT NULL DEFAULT 0,
			last_modified DATETIME NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE uuid (name VARCHAR(100) PRIMARY KEY, uuid CHAR(32) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE invitation_codes (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			code VARCHAR(255) NOT NULL,
			used_by BIGINT NULL,
			used_at DATETIME NULL,
			generated_at DATETIME NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE oauth_clients (
			id BIGINT NOT NULL PRIMARY KEY,
			user_id BIGINT NULL,
			name VARCHAR(255) NULL,
			secret VARCHAR(255) NULL,
			provider VARCHAR(255) NULL,
			redirect TEXT NULL,
			personal_access_client TINYINT NOT NULL DEFAULT 0,
			password_client TINYINT NOT NULL DEFAULT 0,
			revoked TINYINT NOT NULL DEFAULT 0,
			created_at DATETIME NULL,
			updated_at DATETIME NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE oauth_access_tokens (
			id VARCHAR(100) NOT NULL PRIMARY KEY,
			user_id BIGINT NULL,
			client_id BIGINT NOT NULL,
			name VARCHAR(255) NULL,
			scopes TEXT NULL,
			revoked TINYINT NOT NULL DEFAULT 0,
			created_at DATETIME NULL,
			updated_at DATETIME NULL,
			expires_at DATETIME NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE oauth_refresh_tokens (
			id VARCHAR(100) NOT NULL PRIMARY KEY,
			access_token_id VARCHAR(100) NOT NULL,
			revoked TINYINT NOT NULL DEFAULT 0,
			expires_at DATETIME NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE oauth_auth_codes (
			id VARCHAR(100) NOT NULL PRIMARY KEY,
			user_id BIGINT NULL,
			client_id BIGINT NOT NULL,
			scopes TEXT NULL,
			revoked TINYINT NOT NULL DEFAULT 0,
			expires_at DATETIME NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE go_ygg_lock (id INT NOT NULL PRIMARY KEY) ENGINE=InnoDB`,
		`INSERT INTO go_ygg_lock VALUES (1)`,
		`CREATE TABLE go_ygg_users (uid BIGINT NOT NULL PRIMARY KEY, revoked_before BIGINT NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE go_ygg_tokens (
			sequence BIGINT UNSIGNED NOT NULL AUTO_INCREMENT UNIQUE,
			fingerprint CHAR(64) NOT NULL PRIMARY KEY,
			uid BIGINT NOT NULL,
			payload LONGTEXT NOT NULL,
			expires_at BIGINT NOT NULL,
			revoked BOOLEAN NOT NULL DEFAULT 0,
			INDEX(uid)
		) ENGINE=InnoDB`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("%w: %s", err, statement)
		}
	}
	return revocation.New(db, "").EnsureSchema(context.Background())
}
