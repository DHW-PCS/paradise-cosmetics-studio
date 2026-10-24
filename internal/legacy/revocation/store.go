// Package revocation implements the additive per-user authentication
// revocation state that both Go and the adapted rollback build must honour.
package revocation

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Table is the additive table name; the configured DB prefix is applied by
// Store.
const Table = "legacy_auth_revocations"

// Schema is idempotent and only adds a table.
const Schema = `CREATE TABLE IF NOT EXISTS %s (
  user_uid BIGINT UNSIGNED NOT NULL,
  session_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  password_fingerprint VARBINARY(32) NOT NULL,
  revoked_before BIGINT UNSIGNED NOT NULL DEFAULT 0,
  updated_at DATETIME NOT NULL,
  PRIMARY KEY (user_uid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`

var (
	ErrRevoked    = errors.New("revocation: session revoked")
	ErrNoState    = errors.New("revocation: no state for user")
	ErrBadPayload = errors.New("revocation: missing or invalid go_auth")
)

// State is one user's durable revocation watermark.
type State struct {
	UID                 int64
	SessionVersion      int64
	PasswordFingerprint []byte
	RevokedBefore       int64
	UpdatedAt           time.Time
}

// Store reads and writes the revocation table.
type Store struct {
	db     *sql.DB
	prefix string
}

// New wraps an existing connection.
func New(db *sql.DB, prefix string) *Store {
	return &Store{db: db, prefix: prefix}
}

// EnsureSchema creates the additive table when absent.
func (s *Store) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, fmt.Sprintf(Schema, s.prefix+Table))
	return err
}

// Fingerprint derives a stable MAC over the stored password hash. It lets both
// implementations detect a password change without storing the hash twice.
func Fingerprint(secret []byte, passwordHash string) []byte {
	derived := hmac.New(sha256.New, secret)
	derived.Write([]byte("legacy-auth-fingerprint/v1"))
	key := derived.Sum(nil)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(passwordHash))
	return mac.Sum(nil)
}

// queryer is satisfied by both *sql.DB and *sql.Tx.
type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) get(ctx context.Context, q queryer, uid int64) (*State, error) {
	return s.scanState(ctx, q, uid, "")
}

// getCurrent is a locking read, so it observes a row committed by another
// transaction instead of the caller's older consistent snapshot.
func (s *Store) getCurrent(ctx context.Context, tx *sql.Tx, uid int64) (*State, error) {
	return s.scanState(ctx, tx, uid, " FOR UPDATE")
}

func (s *Store) scanState(ctx context.Context, q queryer, uid int64, suffix string) (*State, error) {
	query := fmt.Sprintf("SELECT user_uid, session_version, password_fingerprint, revoked_before, updated_at FROM %s%s WHERE user_uid = ?%s", s.prefix, Table, suffix)
	var st State
	if err := q.QueryRowContext(ctx, query, uid).Scan(&st.UID, &st.SessionVersion, &st.PasswordFingerprint, &st.RevokedBefore, &st.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoState
		}
		return nil, err
	}
	return &st, nil
}

// Get loads a user's state.
func (s *Store) Get(ctx context.Context, uid int64) (*State, error) {
	return s.get(ctx, s.db, uid)
}

// GetTx loads a user's state inside the caller's transaction.
func (s *Store) GetTx(ctx context.Context, tx *sql.Tx, uid int64) (*State, error) {
	return s.get(ctx, tx, uid)
}

// Ensure creates a baseline row when the user has none. Callers that serialize
// changes for one account must already hold the users row lock.
func (s *Store) Ensure(ctx context.Context, uid int64, passwordHash string, secret []byte, now time.Time) (*State, error) {
	var state *State
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		state, err = s.EnsureTx(ctx, tx, uid, passwordHash, secret, now)
		return err
	})
	return state, err
}

// EnsureTx is Ensure inside the caller's transaction. It locks the account row
// first: two concurrent first-time initializations otherwise deadlock between
// the duplicate-key insert and the current read. Callers that already hold the
// user lock simply re-acquire it in the same transaction.
func (s *Store) EnsureTx(ctx context.Context, tx *sql.Tx, uid int64, passwordHash string, secret []byte, now time.Time) (*State, error) {
	if err := s.lockUserRow(ctx, tx, uid); err != nil {
		return nil, err
	}
	st, err := s.get(ctx, tx, uid)
	if err == nil {
		return st, nil
	}
	if !errors.Is(err, ErrNoState) {
		return nil, err
	}
	q := fmt.Sprintf(`INSERT IGNORE INTO %s%s (user_uid, session_version, password_fingerprint, revoked_before, updated_at) VALUES (?, ?, ?, ?, ?)`, s.prefix, Table)
	if _, err := tx.ExecContext(ctx, q, uid, 1, Fingerprint(secret, passwordHash), 0, now); err != nil {
		return nil, err
	}
	// A failed INSERT IGNORE may mean another transaction created the row; read
	// it with a current read rather than the EARLIER snapshot.
	return s.getCurrent(ctx, tx, uid)
}

// Bump advances the revocation watermark. It is used for password changes and
// "sign out everywhere" style operations.
func (s *Store) Bump(ctx context.Context, uid int64, passwordHash string, secret []byte, now time.Time) (*State, error) {
	var state *State
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		state, err = s.BumpTx(ctx, tx, uid, passwordHash, secret, now)
		return err
	})
	return state, err
}

// BumpTx is Bump inside the caller's transaction.
func (s *Store) BumpTx(ctx context.Context, tx *sql.Tx, uid int64, passwordHash string, secret []byte, now time.Time) (*State, error) {
	if err := BumpTx(ctx, tx, s.prefix, uid, passwordHash, secret, now); err != nil {
		return nil, err
	}
	return s.get(ctx, tx, uid)
}

// BumpTx advances the watermark for prefix inside tx. It is shared with the
// password-change transaction so both writers keep the same version, fingerprint
// and clock semantics.
func BumpTx(ctx context.Context, tx *sql.Tx, prefix string, uid int64, passwordHash string, secret []byte, now time.Time) error {
	q := fmt.Sprintf(`INSERT INTO %s%s (user_uid, session_version, password_fingerprint, revoked_before, updated_at)
VALUES (?, 1, ?, ?, ?)
ON DUPLICATE KEY UPDATE session_version = session_version + 1, password_fingerprint = VALUES(password_fingerprint), revoked_before = VALUES(revoked_before), updated_at = VALUES(updated_at)`, prefix, Table)
	_, err := tx.ExecContext(ctx, q, uid, Fingerprint(secret, passwordHash), now.Unix(), now)
	return err
}

func (s *Store) lockUserRow(ctx context.Context, tx *sql.Tx, uid int64) error {
	var got int64
	return tx.QueryRowContext(ctx, fmt.Sprintf("SELECT uid FROM %susers WHERE uid=? FOR UPDATE", s.prefix), uid).Scan(&got)
}

func (s *Store) withTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Reset deletes a user's state. It exists for isolated PoC fixtures only; a
// production deployment must never call it, because deleting revocation state
// can resurrect messages/tokens that were already rejected.
func (s *Store) Reset(ctx context.Context, uid int64) error {
	q := fmt.Sprintf("DELETE FROM %s%s WHERE user_uid = ?", s.prefix, Table)
	_, err := s.db.ExecContext(ctx, q, uid)
	return err
}

// Payload is the go_auth session attribute.
type Payload struct {
	UID int64
	Rev int64
	IAT int64
}

// Check validates a session's go_auth payload against the durable state.
func (s *Store) Check(ctx context.Context, p *Payload, currentPasswordHash string, secret []byte) error {
	st, err := s.Get(ctx, p.UID)
	if err != nil {
		if errors.Is(err, ErrNoState) {
			return ErrNoState
		}
		return err
	}
	if p.Rev < st.SessionVersion {
		return fmt.Errorf("%w: version %d < %d", ErrRevoked, p.Rev, st.SessionVersion)
	}
	if p.IAT < st.RevokedBefore {
		return fmt.Errorf("%w: issued %d < revoked_before %d", ErrRevoked, p.IAT, st.RevokedBefore)
	}
	expected := Fingerprint(secret, currentPasswordHash)
	if !hmac.Equal(expected, st.PasswordFingerprint) {
		return fmt.Errorf("%w: password changed", ErrRevoked)
	}
	return nil
}
