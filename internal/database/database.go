// Package database contains the MySQL/MariaDB connection and transaction boundary.
package database

import (
	"context"
	"database/sql"
	"strings"

	"github.com/go-sql-driver/mysql"
)

type Store struct {
	DB     *sql.DB
	Prefix string
}

func Open(ctx context.Context, dsn, prefix string, connections int) (*Store, error) {
	c, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	c.ParseTime = true
	db, err := sql.Open("mysql", c.FormatDSN())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(connections)
	db.SetMaxIdleConns(connections)
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db, prefix}, nil
}

func (s *Store) Table(name string) string {
	return "`" + strings.ReplaceAll(s.Prefix+name, "`", "``") + "`"
}

func (s *Store) Transaction(ctx context.Context, f func(*sql.Tx) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = f(tx); err != nil {
		return err
	}
	return tx.Commit()
}
