package yggdrasil

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
)

func UUID3(name string) string {
	b := md5.Sum([]byte("OfflinePlayer:" + name))
	b[6] = (b[6] & 15) | 48
	b[8] = (b[8] & 63) | 128
	return hex.EncodeToString(b[:])
}

// Allocate preserves existing values; ambiguous legacy mappings are reported,
// never repaired by deleting a conflicting row or recalculating its UUID.
func (s *Store) Allocate(ctx context.Context, name, algorithm string) (string, error) {
	var id string
	e := s.locked(ctx, func(tx *sql.Tx) error {
		if algorithm != "v3" && algorithm != "v4" {
			return ErrDenied
		}
		var players int
		if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Prefix+"players WHERE name=?", name).Scan(&players); e != nil {
			return e
		}
		if players != 1 {
			return ErrDenied
		}
		rows, e := tx.QueryContext(ctx, "SELECT uuid FROM "+s.Prefix+"uuid WHERE name=?", name)
		if e != nil {
			return e
		}
		var ids []string
		for rows.Next() {
			var found string
			if e = rows.Scan(&found); e != nil {
				rows.Close()
				return e
			}
			ids = append(ids, found)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if len(ids) > 1 {
			return ErrDenied
		}
		if len(ids) == 1 {
			id = ids[0]
			var n int
			if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Prefix+"uuid WHERE uuid=?", id).Scan(&n); e != nil {
				return e
			}
			if n != 1 {
				return ErrDenied
			}
			return nil
		}
		if algorithm == "v3" {
			id = UUID3(name)
		} else {
			id, e = randomID()
			if e != nil {
				return e
			}
		}
		var n int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Prefix+"uuid WHERE uuid=?", id).Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			return ErrDenied
		}
		_, e = tx.ExecContext(ctx, "INSERT INTO "+s.Prefix+"uuid(name,uuid) VALUES(?,?)", name, id)
		return e
	})
	return id, e
}
