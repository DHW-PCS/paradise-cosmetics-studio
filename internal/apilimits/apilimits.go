// Package apilimits implements the Yggdrasil core API fixed-window rate
// limit: 60 requests per 60 seconds, anchored at the first hit of a
// window. It is a single database-backed counter table and is not coupled
// to password admission.
package apilimits

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"strconv"
	"time"

	database "paradise-cosmetics-studio/internal/database"
)

const (
	limit      = 60
	windowSecs = 60
	tableName  = "go_api_limits"
	migration  = "021_go_api_limits"
)

// Decision reports the outcome of one Take call. RetryAfter is in
// seconds and ResetAt is the instant the current window ends, for use in
// Unix rate-limit headers by the HTTP layer.
type Decision struct {
	Allowed    bool
	Limit      int
	Remaining  int
	RetryAfter int
	ResetAt    time.Time
}

// Service is the core API rate limiter over one store.
type Service struct {
	store *database.Store
	// Now supplies the current time; New sets it to time.Now and tests
	// may replace it to control the 60-second window.
	Now func() time.Time
}

// New returns a Service over store.
func New(store *database.Store) *Service {
	return &Service{store: store, Now: time.Now}
}

// Migrate creates the go_api_limits table on the offline migration ledger.
func (s *Service) Migrate(ctx context.Context) error {
	ddl := "CREATE TABLE IF NOT EXISTS " + s.store.Table(tableName) + ` (digest BINARY(20) PRIMARY KEY,count BIGINT NOT NULL,expires_at BIGINT NOT NULL,INDEX limit_expiry(expires_at)) ENGINE=InnoDB`
	return s.store.ApplyMigration(ctx, migration, ddl)
}

// keyFor derives the counter key inside this package only: a positive uid
// keys on its decimal form, otherwise the anonymous domain|ip pair keys.
// Raw tokens and production credentials never enter the key or the row.
func keyFor(uid int64, domain, ip string) []byte {
	var raw string
	if uid > 0 {
		raw = strconv.FormatInt(uid, 10)
	} else {
		raw = domain + "|" + ip
	}
	sum := sha1.Sum([]byte(raw))
	return sum[:]
}

// decide applies the first-hit anchored fixed window to one stored row.
// A denied hit changes neither the count nor the window end.
func decide(count, expiresAt, nowUnix int64) (allowed bool, newCount, newExpires int64) {
	if expiresAt <= nowUnix {
		return true, 1, nowUnix + windowSecs
	}
	if count >= limit {
		return false, count, expiresAt
	}
	return true, count + 1, expiresAt
}

// Take consumes one request from the caller's window atomically. The
// read and write happen in one database transaction on the locked row;
// over-limit hits return Allowed=false without incrementing the count or
// extending the window, and the first hit after the window ends resets it.
func (s *Service) Take(ctx context.Context, uid int64, domain, ip string) (Decision, error) {
	key := keyFor(uid, domain, ip)
	nowUnix := s.Now().Unix()
	var decision Decision
	err := s.store.Transaction(ctx, func(tx *sql.Tx) error {
		// The upsert materialises the row with an exclusive lock so the
		// locked read below serialises concurrent hits on the same key;
		// on an existing row it changes neither count nor expiry.
		if _, err := tx.ExecContext(ctx, "INSERT INTO "+s.store.Table(tableName)+" (digest,count,expires_at) VALUES (?,0,0) ON DUPLICATE KEY UPDATE digest=digest", key); err != nil {
			return err
		}
		var count, expiresAt int64
		if err := tx.QueryRowContext(ctx, "SELECT count,expires_at FROM "+s.store.Table(tableName)+" WHERE digest=? FOR UPDATE", key).Scan(&count, &expiresAt); err != nil {
			return err
		}
		allowed, newCount, newExpires := decide(count, expiresAt, nowUnix)
		if newCount != count || newExpires != expiresAt {
			if _, err := tx.ExecContext(ctx, "UPDATE "+s.store.Table(tableName)+" SET count=?,expires_at=? WHERE digest=?", newCount, newExpires, key); err != nil {
				return err
			}
		}
		decision = Decision{Allowed: allowed, Limit: limit, ResetAt: time.Unix(newExpires, 0).UTC()}
		if allowed {
			decision.Remaining = limit - int(newCount)
		} else {
			decision.RetryAfter = int(newExpires - nowUnix)
		}
		return nil
	})
	if err != nil {
		return Decision{}, err
	}
	return decision, nil
}
