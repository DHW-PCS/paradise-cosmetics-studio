package identity

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"
)

// IssueAPI rotates the first-party API cookie secret bound to the current
// browser session. The digest column shares the session row: the secret
// has no independent expiry, and session deletion, rotation back to login,
// UID revocation, or offline auth-reset invalidates it together with the
// session. The caller must already have checked CSRF from the same
// browser session; this function rechecks version and expiry in its own
// transaction so issuance cannot outlive the session it is bound to.
func (s *Service) IssueAPI(ctx context.Context, sessionToken string) (string, error) {
	secret := Token()
	var discovered sql.NullInt64
	err := s.Store.DB.QueryRowContext(ctx, "SELECT user_uid FROM "+s.Store.Table("go_web_sessions")+" WHERE digest=?", Digest(sessionToken)).Scan(&discovered)
	if errors.Is(err, sql.ErrNoRows) || !discovered.Valid {
		return "", ErrSession
	}
	if err != nil {
		return "", err
	}
	uid := discovered.Int64
	err = s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		// Lock order users -> version -> session (CheckBrowserTx/§1).
		u, err := s.accountForUpdate(ctx, tx, uid)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSession
		}
		if err != nil {
			return err
		}
		if u.Permission < 0 {
			return ErrSession
		}
		var current int64
		if err = tx.QueryRowContext(ctx, "SELECT version FROM "+s.Store.Table("go_auth_versions")+" WHERE user_uid=? FOR UPDATE", uid).Scan(&current); errors.Is(err, sql.ErrNoRows) {
			return ErrSession
		} else if err != nil {
			return err
		}
		var sessionUID sql.NullInt64
		var version sql.NullInt64
		var expiry int64
		if err = tx.QueryRowContext(ctx, "SELECT user_uid,version,expires_at FROM "+s.Store.Table("go_web_sessions")+" WHERE digest=? FOR UPDATE", Digest(sessionToken)).Scan(&sessionUID, &version, &expiry); errors.Is(err, sql.ErrNoRows) {
			return ErrSession
		} else if err != nil {
			return err
		}
		if !sessionUID.Valid || sessionUID.Int64 != uid || version.Int64 != current || expiry <= s.now().Unix() {
			return ErrSession
		}
		_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("go_web_sessions")+" SET api_digest=? WHERE digest=?", Digest(secret), Digest(sessionToken))
		return err
	})
	if err != nil {
		return "", err
	}
	return secret, nil
}

// ValidateAPI resolves a first-party API cookie secret to its bound
// session. The caller's CSRF token (including on GET requests) must match
// the session CSRF; a mismatch reports ErrSession. The secret is never a
// bearer token: callers keep explicit Authorization handling separate and
// never fall back to this cookie when a bearer credential was presented.
// The result carries a private proof for NewAPICookieActor, not a web Token.
func (s *Service) ValidateAPI(ctx context.Context, secret, csrf string) (*BrowserSession, error) {
	if secret == "" {
		return nil, ErrSession
	}
	var uid sql.NullInt64
	digest := Digest(secret)
	// Discovery determines only the user lock plan. The current read
	// checks the complete session and CSRF under the ordered locks.
	err := s.Store.DB.QueryRowContext(ctx, "SELECT user_uid FROM "+s.Store.Table("go_web_sessions")+" WHERE api_digest=?", digest).Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSession
	}
	if err != nil {
		return nil, err
	}
	if !uid.Valid {
		return nil, ErrSession
	}
	proof := &apiCookieProof{uid: uid.Int64, digest: digest, csrf: csrf}
	var result *BrowserSession
	err = s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		var err error
		result, err = s.checkAPICookieTx(ctx, tx, proof)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

type apiCookieProof struct {
	uid    int64
	digest []byte
	csrf   string
}

// checkAPICookieTx borrows the business transaction. Both entry validation
// and Actor recheck use users -> UID version -> API-bound session locks.
func (s *Service) checkAPICookieTx(ctx context.Context, tx *sql.Tx, proof *apiCookieProof) (*BrowserSession, error) {
	u, err := s.accountForUpdate(ctx, tx, proof.uid)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSession
	}
	if err != nil {
		return nil, err
	}
	if u.Permission < 0 {
		return nil, ErrSession
	}
	var current int64
	if err = tx.QueryRowContext(ctx, "SELECT version FROM "+s.Store.Table("go_auth_versions")+" WHERE user_uid=? FOR UPDATE", proof.uid).Scan(&current); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSession
	} else if err != nil {
		return nil, err
	}
	var uid, version sql.NullInt64
	var csrf string
	var expiry int64
	if err = tx.QueryRowContext(ctx, "SELECT user_uid,version,csrf,expires_at FROM "+s.Store.Table("go_web_sessions")+" WHERE api_digest=? FOR UPDATE", proof.digest).Scan(&uid, &version, &csrf, &expiry); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSession
	} else if err != nil {
		return nil, err
	}
	if !uid.Valid || uid.Int64 != proof.uid || !version.Valid || version.Int64 != current || expiry <= s.now().Unix() || subtle.ConstantTimeCompare([]byte(proof.csrf), []byte(csrf)) != 1 {
		return nil, ErrSession
	}
	return &BrowserSession{CSRF: csrf, User: &u.User, Version: current, Expires: time.Unix(expiry, 0), apiProof: proof}, nil
}
