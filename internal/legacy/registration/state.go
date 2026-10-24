package registration

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
)

// Outbox records a pending Go-owned task; rollback must retain this dispatcher
// until a separately verified conversion exists. PHP must not unserialize it.
func SetupOutbox(ctx context.Context, db *sql.DB, prefix string) error {
	if !regexp.MustCompile(`^[A-Za-z0-9_]*$`).MatchString(prefix) {
		return ErrDenied
	}
	_, e := db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+prefix+"go_outbox(id BIGINT AUTO_INCREMENT PRIMARY KEY,user_uid BIGINT NOT NULL,idempotency_key VARCHAR(100) UNIQUE,kind VARCHAR(32) NOT NULL,payload TEXT NOT NULL,delivered BOOLEAN NOT NULL DEFAULT 0) ENGINE=InnoDB")
	return e
}
func Enqueue(ctx context.Context, tx *sql.Tx, prefix string, uid int64, key string) error {
	if len(key) < 1 || len(key) > 100 {
		return ErrDenied
	}
	var email string
	if e := tx.QueryRowContext(ctx, "SELECT email FROM "+prefix+"users WHERE uid=? FOR UPDATE", uid).Scan(&email); e != nil {
		return e
	}
	b, _ := json.Marshal(map[string]string{"template": "test-only", "recipient": email})
	// The same key can be retried only for the same owner. The lock on the user
	// and the database unique key serialize duplicate enqueue operations.
	var owner int64
	e := tx.QueryRowContext(ctx, "SELECT user_uid FROM "+prefix+"go_outbox WHERE idempotency_key=? FOR UPDATE", key).Scan(&owner)
	if e == nil {
		if owner != uid {
			return ErrDenied
		}
		return nil
	}
	if e != sql.ErrNoRows {
		return e
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO "+prefix+"go_outbox(user_uid,idempotency_key,kind,payload) VALUES(?,?,'mail',?)", uid, key, string(b))
	return e
}
func DeletePlayer(ctx context.Context, tx *sql.Tx, prefix string, uid, pid int64) error {
	r, e := tx.ExecContext(ctx, "DELETE FROM "+prefix+"players WHERE uid=? AND pid=?", uid, pid)
	if e != nil {
		return e
	}
	n, e := r.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrDenied
	}
	return nil
}
