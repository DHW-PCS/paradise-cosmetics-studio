package identity

import (
	"context"
	"database/sql"
	"errors"
)

// CheckBrowserTx rechecks the credential in the write owner's transaction.
// The lock order is users, UID version, browser session.
func (s *Service) CheckBrowserTx(ctx context.Context, tx *sql.Tx, b *BrowserSession) (*User, error) {
	if b.User == nil {
		return nil, ErrSession
	}
	u, err := s.accountForUpdate(ctx, tx, b.User.UID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSession
	}
	if err != nil {
		return nil, err
	}
	var current int64
	if err = tx.QueryRowContext(ctx, "SELECT version FROM "+s.Store.Table("go_auth_versions")+" WHERE user_uid=? FOR UPDATE", u.UID).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSession
		}
		return nil, err
	}
	var version, uid, expiry int64
	err = tx.QueryRowContext(ctx, "SELECT user_uid,version,expires_at FROM "+s.Store.Table("go_web_sessions")+" WHERE digest=? FOR UPDATE", Digest(b.Token)).Scan(&uid, &version, &expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSession
	}
	if err != nil {
		return nil, err
	}
	if uid != u.UID || version != current || expiry <= s.now().Unix() || u.Permission < 0 {
		return nil, ErrSession
	}
	return &u.User, nil
}
