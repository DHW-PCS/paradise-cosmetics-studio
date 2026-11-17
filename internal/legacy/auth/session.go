// Package auth implements the legacy web login semantics on top of the
// session, password, user and revocation packages.
package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"paradise-cosmetics-studio/internal/legacy/password"
	"paradise-cosmetics-studio/internal/legacy/php"
	"paradise-cosmetics-studio/internal/legacy/remember"
	"paradise-cosmetics-studio/internal/legacy/revocation"
	"paradise-cosmetics-studio/internal/legacy/session"
	"paradise-cosmetics-studio/internal/legacy/users"
)

var (
	ErrUnknownUser  = errors.New("auth: unknown user")
	ErrBadPassword  = errors.New("auth: wrong password")
	ErrBanned       = errors.New("auth: user is banned")
	ErrNoSession    = errors.New("auth: no authenticated session")
	ErrStaleSession = errors.New("auth: session revoked")
	// ErrStaleCredential means the account changed after the credential was
	// verified, so no session may be issued from that verification.
	ErrStaleCredential = errors.New("auth: credential verified against a stale account state")
	// ErrRememberRejected covers a recaller that no longer matches the account.
	ErrRememberRejected = errors.New("auth: remember token rejected")
	// ErrLegacyUnverifiable means an unversioned legacy session cannot be
	// upgraded after a global revocation, because its issue time is unknown.
	ErrLegacyUnverifiable = errors.New("auth: legacy session cannot be upgraded after a revocation")
)

// Service bundles the dependencies used by the web guard.
type Service struct {
	Repo     *users.Repo
	Rev      *revocation.Store
	Hasher   *password.Hasher
	Secret   []byte
	LoginKey string
	Now      func() time.Time

	// afterVerify is a test-only observation point invoked inside the account
	// transaction once the credential has matched. Nil in production.
	afterVerify func()
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// LoginResult binds an authentication to the account state that was actually
// verified. Remember is the recaller token the caller must write to the cookie
// when keep was requested: the token already committed for the account when one
// exists, otherwise the newly created value. It is empty for keep=false.
type LoginResult struct {
	User     *users.User
	State    *revocation.State
	Remember string
}

// Login performs the frozen POST /auth/login checks: required|min:6|max:32,
// email or player-name identification, and the native password verifier.
// A banned user still authenticates here; the authorize middleware blocks the
// request afterwards, exactly like RejectBannedUser.
//
// Verification and issuance hold the users row lock, so a concurrent password
// change or global revocation either commits before this call (and the old
// password fails) or after it (and the issued version is revoked).
func (s *Service) Login(ctx context.Context, identification, raw string, keep bool) (*LoginResult, error) {
	if err := password.ValidateLogin(raw); err != nil {
		return nil, err
	}
	var (
		candidate *users.User
		ok        bool
		err       error
	)
	if users.EmailLooksLikeEmail(identification) {
		candidate, ok, err = s.Repo.ByEmail(ctx, identification)
	} else {
		candidate, ok, err = s.Repo.ByPlayerName(ctx, identification)
	}
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrUnknownUser
	}
	result := &LoginResult{}
	err = s.withLockedUser(ctx, candidate.UID, func(tx *sql.Tx, user *users.User) error {
		// The identification was resolved outside the lock; confirm it still
		// names the locked account before trusting the password check.
		if err := s.confirmIdentification(ctx, tx, identification, user.UID); err != nil {
			return err
		}
		passed, err := s.Hasher.Verify(raw, user.Password)
		if err != nil {
			return err
		}
		if !passed {
			return ErrBadPassword
		}
		if s.afterVerify != nil {
			s.afterVerify()
		}
		state, err := s.Rev.EnsureTx(ctx, tx, user.UID, user.Password, s.Secret, s.now())
		if err != nil {
			return err
		}
		if keep {
			// SessionGuard::ensureRememberTokenIsSet only creates a token when
			// the account has none. Reusing the committed value keeps recallers
			// already handed to other devices valid, and avoids rewriting users
			// on every keep login.
			token := user.RememberToken
			if token == "" {
				created, err := remember.NewToken()
				if err != nil {
					return err
				}
				if err := s.Repo.UpdateRememberTokenTx(ctx, tx, user.UID, created); err != nil {
					return err
				}
				token = created
				// Report the committed account state, so the recaller cookie
				// encodes the same token the database now holds.
				user.RememberToken = created
			}
			result.Remember = token
		}
		result.User, result.State = user, state
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// confirmIdentification re-checks, inside the locked transaction, that the
// login identification still resolves to uid.
func (s *Service) confirmIdentification(ctx context.Context, tx *sql.Tx, identification string, uid int64) error {
	var (
		user *users.User
		ok   bool
		err  error
	)
	if users.EmailLooksLikeEmail(identification) {
		user, ok, err = s.Repo.ByEmailTx(ctx, tx, identification)
	} else {
		user, ok, err = s.Repo.ByPlayerNameTx(ctx, tx, identification)
	}
	if err != nil {
		return err
	}
	if !ok || user.UID != uid {
		return ErrUnknownUser
	}
	return nil
}

// withLockedUser runs fn with the users row locked in one transaction.
func (s *Service) withLockedUser(ctx context.Context, uid int64, fn func(*sql.Tx, *users.User) error) error {
	tx, err := s.Repo.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	user, found, err := s.Repo.ByUIDForUpdate(ctx, tx, uid)
	if err != nil {
		return err
	}
	if !found {
		return ErrUnknownUser
	}
	if err := fn(tx, user); err != nil {
		return err
	}
	return tx.Commit()
}

// Validation is the result of checking an existing session.
type Validation struct {
	User *users.User
	// Legacy is true when the payload predates the Go implementation and has
	// no go_auth attribute. Such sessions are accepted (they are valid natively)
	// but cannot be individually revoked until they are upgraded.
	Legacy bool
}

// ValidateSession resolves the session's uid, applies the ban rule and, for Go
// sessions, the durable revocation predicate.
func (s *Service) ValidateSession(ctx context.Context, attrs *php.Array) (*Validation, error) {
	uid, ok := session.LoginUID(attrs, s.LoginKey)
	if !ok || uid <= 0 {
		return nil, ErrNoSession
	}
	payload, versioned, err := PayloadFromSession(attrs)
	if err != nil {
		return nil, err
	}
	if !versioned {
		// An unversioned legacy payload cannot prove it postdates a global
		// revocation, so once a watermark exists it must re-authenticate.
		state, stateErr := s.Rev.Get(ctx, uid)
		if stateErr != nil && !errors.Is(stateErr, revocation.ErrNoState) {
			return nil, stateErr
		}
		if stateErr == nil && state.RevokedBefore > 0 {
			return nil, fmt.Errorf("%w: legacy session after revocation", ErrStaleSession)
		}
	}
	user, found, err := s.Repo.ByUID(ctx, uid)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNoSession
	}
	if user.Permission == users.Banned {
		return nil, ErrBanned
	}
	if !versioned {
		return &Validation{User: user, Legacy: true}, nil
	}
	if payload.UID != user.UID {
		return nil, ErrStaleSession
	}
	if err := s.Rev.Check(ctx, payload, user.Password, s.Secret); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStaleSession, err)
	}
	return &Validation{User: user}, nil
}

// PayloadFromSession reads the additive go_auth attribute.
func PayloadFromSession(attrs *php.Array) (*revocation.Payload, bool, error) {
	value, present := attrs.Get("go_auth")
	if !present {
		return nil, false, nil
	}
	raw, ok := value.(*php.Array)
	if !ok || raw == nil {
		return nil, false, revocation.ErrBadPayload
	}
	uid, ok := raw.GetInt("uid")
	if !ok || uid <= 0 {
		return nil, false, revocation.ErrBadPayload
	}
	rev, ok := raw.GetInt("rev")
	if !ok || rev <= 0 {
		return nil, false, revocation.ErrBadPayload
	}
	iat, ok := raw.GetInt("iat")
	if !ok || iat <= 0 {
		return nil, false, revocation.ErrBadPayload
	}
	return &revocation.Payload{UID: uid, Rev: rev, IAT: iat}, true, nil
}

// WritePayload mirrors session.NewPayload plus the Go revocation metadata.
func (s *Service) WritePayload(user *users.User, state *revocation.State, csrf, previousURL string) *php.Array {
	attrs := session.NewPayload(s.LoginKey, user.UID, csrf, previousURL)
	s.WriteGoAuth(attrs, user.UID, state)
	return attrs
}

// WriteGoAuth stamps the revocation metadata for an existing payload. The
// version must come from the transaction that verified the credential.
func (s *Service) WriteGoAuth(attrs *php.Array, uid int64, state *revocation.State) {
	attrs.Set("go_auth", php.NewArray().
		Set("uid", uid).
		Set("rev", state.SessionVersion).
		Set("iat", s.now().Unix()))
}

// UpgradeLegacy adds go_auth to an accepted legacy payload so later
// revocation rules apply. The caller must persist the payload. Upgrade is
// refused once a global revocation watermark exists: the legacy payload has no
// issue time, so accepting it would resurrect a possibly-revoked session.
func (s *Service) UpgradeLegacy(ctx context.Context, uid int64) (*revocation.State, error) {
	var state *revocation.State
	err := s.withLockedUser(ctx, uid, func(tx *sql.Tx, user *users.User) error {
		st, err := s.Rev.EnsureTx(ctx, tx, user.UID, user.Password, s.Secret, s.now())
		if err != nil {
			return err
		}
		if st.RevokedBefore > 0 {
			return ErrLegacyUnverifiable
		}
		state = st
		return nil
	})
	return state, err
}

// RememberState validates a recaller against the locked account and returns the
// revocation state bound to that validation. A token rotated by a concurrent
// password change or global revocation is rejected instead of being upgraded to
// the newer version.
func (s *Service) RememberState(ctx context.Context, uid int64, token string) (*users.User, *revocation.State, error) {
	var (
		user  *users.User
		state *revocation.State
	)
	err := s.withLockedUser(ctx, uid, func(tx *sql.Tx, locked *users.User) error {
		if locked.RememberToken == "" || subtle.ConstantTimeCompare([]byte(locked.RememberToken), []byte(token)) != 1 {
			return ErrRememberRejected
		}
		if s.afterVerify != nil {
			s.afterVerify()
		}
		st, err := s.Rev.EnsureTx(ctx, tx, locked.UID, locked.Password, s.Secret, s.now())
		if err != nil {
			return err
		}
		user, state = locked, st
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return user, state, nil
}

// RevokeSessions advances the revocation watermark and rotates the remember
// token in one transaction, invalidating every browser session and recaller for
// the user. Ordinary logout does not call it.
func (s *Service) RevokeSessions(ctx context.Context, uid int64) (*revocation.State, string, error) {
	var (
		state *revocation.State
		token string
	)
	err := s.withLockedUser(ctx, uid, func(tx *sql.Tx, user *users.User) error {
		st, err := s.Rev.BumpTx(ctx, tx, user.UID, user.Password, s.Secret, s.now())
		if err != nil {
			return err
		}
		rotated, err := remember.NewToken()
		if err != nil {
			return err
		}
		if err := s.Repo.UpdateRememberTokenTx(ctx, tx, user.UID, rotated); err != nil {
			return err
		}
		state, token = st, rotated
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return state, token, nil
}

// EnsureState returns the durable revocation state for a credential that was
// already verified. The verified password hash must still match the locked
// account, so a credential checked before a concurrent password change cannot
// obtain the newer session version.
func (s *Service) EnsureState(ctx context.Context, uid int64, verifiedPasswordHash string) (*revocation.State, error) {
	var state *revocation.State
	err := s.withLockedUser(ctx, uid, func(tx *sql.Tx, user *users.User) error {
		if user.Password != verifiedPasswordHash {
			return ErrStaleCredential
		}
		st, err := s.Rev.EnsureTx(ctx, tx, user.UID, user.Password, s.Secret, s.now())
		if err != nil {
			return err
		}
		state = st
		return nil
	})
	return state, err
}
