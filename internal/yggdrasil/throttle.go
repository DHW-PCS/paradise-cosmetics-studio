package yggdrasil

import (
	"context"
	"crypto/sha256"
	"database/sql"
)

// EnforceRateLimit applies the username throttle for authenticate and
// signout. The rate comes from ygg_rate_limit in milliseconds; 0 or
// negative disables the check entirely. A denied hit writes nothing.
// Authenticate and Signout call this exactly once; HTTP callers must not
// apply a second counting layer.
func (s *Service) EnforceRateLimit(ctx context.Context, username string) error {
	opts, err := s.opts.load(ctx)
	if err != nil {
		return err
	}
	raw, present := optionPresent(opts, "ygg_rate_limit")
	rateMs := optionInt(raw, present)
	if rateMs <= 0 {
		return nil
	}
	key := rateKey(username)
	nowMs := s.nowMs()
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("go_yggdrasil_limits")+" (digest,last_at,expires_at) VALUES (?,0,0) ON DUPLICATE KEY UPDATE digest=digest", key); err != nil {
			return err
		}
		var lastAt int64
		if err := tx.QueryRowContext(ctx, "SELECT last_at FROM "+s.Store.Table("go_yggdrasil_limits")+" WHERE digest=? FOR UPDATE", key).Scan(&lastAt); err != nil {
			return err
		}
		if lastAt != 0 {
			retryAfter := rateMs - (nowMs - lastAt)
			if retryAfter > 0 {
				seconds := (retryAfter + 999) / 1000
				return ThrottleError(seconds)
			}
		}
		_, err := tx.ExecContext(ctx, "UPDATE "+s.Store.Table("go_yggdrasil_limits")+" SET last_at=?,expires_at=? WHERE digest=?", nowMs, s.now().Unix()+3600, key)
		return err
	})
}

func rateKey(username string) []byte {
	sum := sha256.Sum256([]byte("ygg-rate\x00" + username))
	return sum[:]
}

func (s *Service) nowMs() int64 { return s.now().UnixMilli() }
