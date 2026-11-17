// Package identity owns Go browser credentials and the UID revocation boundary.
package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"paradise-cosmetics-studio/internal/admission"
	"paradise-cosmetics-studio/internal/database"
	"paradise-cosmetics-studio/internal/legacy/password"
	"paradise-cosmetics-studio/internal/legacy/users"
)

var (
	ErrCredentials = errors.New("identity: invalid credentials")
	ErrNoAccount   = fmt.Errorf("%w: account not found", ErrCredentials)
	ErrBanned      = fmt.Errorf("%w: account banned", ErrCredentials)
	ErrStale       = errors.New("identity: account changed; authenticate again")
	ErrSession     = errors.New("identity: session expired or revoked")
)

type User struct {
	UID        int64  `json:"uid"`
	Email      string `json:"email"`
	Nickname   string `json:"nickname"`
	Permission int    `json:"permission"`
	Verified   bool   `json:"verified"`
	Locale     string `json:"locale"`
	DarkMode   bool   `json:"is_dark_mode"`
}

type BrowserSession struct {
	Token    string
	CSRF     string
	Remember string
	User     *User
	Expires  time.Time
	Version  int64

	// API-cookie validation carries a separate proof, never a web Token.
	apiProof *apiCookieProof
}

type Service struct {
	Store                             *database.Store
	LoginStore                        *database.Store
	Passwords                         *password.Hasher
	Admission                         *admission.Gate
	SessionLifetime, RememberLifetime time.Duration
	Now                               func() time.Time
}

func Token() string { return base64.RawURLEncoding.EncodeToString(randBytes()) }
func randBytes() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
func Digest(token string) []byte { sum := sha256.Sum256([]byte(token)); return sum[:] }

func (s *Service) now() time.Time { return s.Now() }

func (s *Service) Guest(ctx context.Context) (*BrowserSession, error) {
	b := &BrowserSession{Token: Token(), CSRF: Token(), Expires: s.now().Add(s.SessionLifetime)}
	_, err := s.Store.DB.ExecContext(ctx, "INSERT INTO "+s.Store.Table("go_web_sessions")+" (digest,csrf,expires_at) VALUES (?,?,?)", Digest(b.Token), b.CSRF, b.Expires.Unix())
	return b, err
}

func (s *Service) Session(ctx context.Context, token string) (*BrowserSession, error) {
	var uid, version sql.NullInt64
	var expires int64
	b := &BrowserSession{Token: token}
	err := s.Store.DB.QueryRowContext(ctx, "SELECT user_uid,version,csrf,expires_at FROM "+s.Store.Table("go_web_sessions")+" WHERE digest=?", Digest(token)).Scan(&uid, &version, &b.CSRF, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSession
	}
	if err != nil {
		return nil, err
	}
	if expires <= s.now().Unix() {
		return nil, ErrSession
	}
	b.Expires = time.Unix(expires, 0)
	if uid.Valid {
		u := &User{}
		var current int64
		err = s.Store.DB.QueryRowContext(ctx, "SELECT u.uid,u.email,u.nickname,u.permission,u.verified,COALESCE(u.locale,''),u.is_dark_mode,a.version FROM "+s.Store.Table("users")+" u JOIN "+s.Store.Table("go_auth_versions")+" a ON a.user_uid=u.uid WHERE u.uid=?", uid.Int64).Scan(&u.UID, &u.Email, &u.Nickname, &u.Permission, &u.Verified, &u.Locale, &u.DarkMode, &current)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSession
		}
		if err != nil {
			return nil, err
		}
		if current != version.Int64 || u.Permission < 0 {
			return nil, ErrSession
		}
		b.User = u
		b.Version = current
	}
	b.Expires = s.now().Add(s.SessionLifetime)
	if _, err = s.Store.DB.ExecContext(ctx, "UPDATE "+s.Store.Table("go_web_sessions")+" SET expires_at=? WHERE digest=? AND expires_at>?", b.Expires.Unix(), Digest(token), s.now().Unix()); err != nil {
		return nil, err
	}
	return b, nil
}

// Login releases database connections before the expensive password verifier.
// The issuance transaction rechecks both the password and the revocation version.
type Lookup int

const (
	EmailOrPlayer Lookup = iota
	EmailOnly
)

// PasswordIntent selects the banned policy for a Yggdrasil password proof.
// It is chosen by the calling domain, never by an HTTP request.
type PasswordIntent int

const (
	// PasswordIntentAuthenticate rejects banned accounts both at proof
	// creation and at transaction recheck.
	PasswordIntentAuthenticate PasswordIntent = iota
	// PasswordIntentSignout allows banned accounts through proof creation
	// and transaction recheck; require_verification still applies in the
	// calling domain.
	PasswordIntentSignout
)

// ErrNoVersion reports that the account has no go_auth_versions row. A
// credential recheck must not create the row; issuance may initialize it.
var ErrNoVersion = errors.New("identity: account has no auth version")

// PasswordProof is created only by WithPassword. Its fields cannot be supplied
// by an HTTP caller; issuance must recheck its account snapshot in a transaction.
type PasswordProof struct {
	user           *account
	version        int64
	identification string
	lookup         Lookup
	intent         PasswordIntent
	versionExists  bool
}

func (p *PasswordProof) UID() int64             { return p.user.UID }
func (p *PasswordProof) Version() int64         { return p.version }
func (p *PasswordProof) Intent() PasswordIntent { return p.intent }

// VersionExists reports whether the account had a go_auth_versions row when
// the proof was created. A false value forbids treating the defaulted
// version as an existing credential in recheck.
func (p *PasswordProof) VersionExists() bool { return p.versionExists }

func (s *Service) WithPassword(ctx context.Context, identification, raw string, lookup Lookup, accept func(*PasswordProof) error) error {
	return s.withPassword(ctx, raw, func() (*account, error) { return s.lookupAccount(ctx, identification, lookup) }, identification, lookup, accept)
}

// WithUserPassword verifies the current account by UID, including accounts
// whose email is empty. Callers must recheck the proof in their transaction.
func (s *Service) WithUserPassword(ctx context.Context, uid int64, raw string, accept func(*PasswordProof) error) error {
	return s.withPassword(ctx, raw, func() (*account, error) {
		return scanAccount(s.LoginStore.DB.QueryRowContext(ctx, "SELECT "+accountColumns+" FROM "+s.Store.Table("users")+" u WHERE uid=?", uid))
	}, "", EmailOnly, accept)
}

// WithYggdrasilPassword creates a Yggdrasil password proof under the given
// intent: authenticate rejects banned accounts at this stage, signout
// allows them. Admission, candidate lookup and password computation are
// shared with the browser login; the calling domain must still recheck the
// proof in its own transaction. It performs no token issuance.
func (s *Service) WithYggdrasilPassword(ctx context.Context, identification, raw string, intent PasswordIntent, accept func(*PasswordProof) error) error {
	return s.withPasswordIntent(ctx, raw, func() (*account, error) { return s.lookupAccount(ctx, identification, EmailOrPlayer) }, identification, EmailOrPlayer, intent, accept)
}

func (s *Service) withPassword(ctx context.Context, raw string, load func() (*account, error), identification string, lookup Lookup, accept func(*PasswordProof) error) error {
	return s.withPasswordIntent(ctx, raw, load, identification, lookup, PasswordIntentAuthenticate, accept)
}

func (s *Service) withPasswordIntent(ctx context.Context, raw string, load func() (*account, error), identification string, lookup Lookup, intent PasswordIntent, accept func(*PasswordProof) error) error {
	release, err := s.Admission.Acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	candidate, err := load()
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNoAccount
	}
	if err != nil {
		return err
	}
	if intent == PasswordIntentAuthenticate && candidate.Permission < 0 {
		return ErrBanned
	}

	var version int64 = 1
	versionExists := true
	err = s.LoginStore.DB.QueryRowContext(ctx, "SELECT version FROM "+s.Store.Table("go_auth_versions")+" WHERE user_uid=?", candidate.UID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		versionExists = false
	} else if err != nil {
		return err
	}
	valid, err := s.Passwords.Verify(raw, candidate.Password)
	if err != nil {
		return err
	}
	if !valid {
		return ErrCredentials
	}
	if identification == "" {
		identification = candidate.Email
	}
	return accept(&PasswordProof{user: candidate, version: version, identification: identification, lookup: lookup, intent: intent, versionExists: versionExists})
}

// RegisterSession joins the registration owner's transaction after the users
// row has been created. It initializes the version and replaces the guest.
func (s *Service) RegisterSession(ctx context.Context, tx *sql.Tx, uid int64, guest string) (*BrowserSession, error) {
	u, err := s.accountForUpdate(ctx, tx, uid)
	if err != nil {
		return nil, err
	}
	v, err := s.VersionTx(ctx, tx, uid)
	if err != nil {
		return nil, err
	}
	var guestUID sql.NullInt64
	var expiry int64
	err = tx.QueryRowContext(ctx, "SELECT user_uid,expires_at FROM "+s.Store.Table("go_web_sessions")+" WHERE digest=? FOR UPDATE", Digest(guest)).Scan(&guestUID, &expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSession
	}
	if err != nil {
		return nil, err
	}
	if guestUID.Valid || expiry <= s.now().Unix() {
		return nil, ErrSession
	}
	b, err := s.issue(ctx, tx, &u.User, v, false, "")
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("go_web_sessions")+" WHERE digest=?", Digest(guest))
	return b, err
}

func (s *Service) RecheckPassword(ctx context.Context, tx *sql.Tx, proof *PasswordProof) (*User, error) {
	u, err := s.accountForUpdate(ctx, tx, proof.user.UID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrStale
	}
	if err != nil {
		return nil, err
	}
	if u.Password != proof.user.Password || u.Permission < 0 {
		return nil, ErrStale
	}
	var uid int64
	if proof.lookup == EmailOnly || users.EmailLooksLikeEmail(proof.identification) {
		err = tx.QueryRowContext(ctx, "SELECT uid FROM "+s.Store.Table("users")+" WHERE uid=? AND email=? FOR UPDATE", u.UID, proof.identification).Scan(&uid)
	} else {
		err = tx.QueryRowContext(ctx, "SELECT uid FROM "+s.Store.Table("players")+" WHERE uid=? AND name=? LIMIT 1 FOR UPDATE", u.UID, proof.identification).Scan(&uid)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrStale
	}
	if err != nil {
		return nil, err
	}
	version, err := s.VersionTx(ctx, tx, u.UID)
	if err != nil {
		return nil, err
	}
	if version != proof.version {
		return nil, ErrStale
	}
	return &u.User, nil
}

// RecheckGamePasswordTx rechecks a WithYggdrasilPassword proof inside the
// caller's transaction. It locks the users row, verifies the password hash,
// the identification (account email or player name) and the auth version
// without ever creating a version row. Authenticate intent rejects banned
// accounts; signout intent allows them. A missing version row reports
// ErrNoVersion so signout can succeed without creating state.
func (s *Service) RecheckGamePasswordTx(ctx context.Context, tx *sql.Tx, proof *PasswordProof) (*User, error) {
	u, err := s.accountForUpdate(ctx, tx, proof.user.UID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrStale
	}
	if err != nil {
		return nil, err
	}
	if u.Password != proof.user.Password {
		return nil, ErrStale
	}
	if proof.intent == PasswordIntentAuthenticate && u.Permission < 0 {
		return nil, ErrStale
	}
	var uid int64
	if proof.lookup == EmailOnly || users.EmailLooksLikeEmail(proof.identification) {
		err = tx.QueryRowContext(ctx, "SELECT uid FROM "+s.Store.Table("users")+" WHERE uid=? AND email=? FOR UPDATE", u.UID, proof.identification).Scan(&uid)
	} else {
		err = tx.QueryRowContext(ctx, "SELECT uid FROM "+s.Store.Table("players")+" WHERE uid=? AND name=? LIMIT 1 FOR UPDATE", u.UID, proof.identification).Scan(&uid)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrStale
	}
	if err != nil {
		return nil, err
	}
	var version int64
	err = tx.QueryRowContext(ctx, "SELECT version FROM "+s.Store.Table("go_auth_versions")+" WHERE user_uid=? FOR UPDATE", u.UID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoVersion
	}
	if err != nil {
		return nil, err
	}
	if version != proof.version {
		return nil, ErrStale
	}
	return &u.User, nil
}

func (s *Service) Login(ctx context.Context, identification, raw string, keep bool, old string) (*BrowserSession, error) {
	if err := password.ValidateLogin(raw); err != nil {
		return nil, err
	}
	var result *BrowserSession
	err := s.WithPassword(ctx, identification, raw, EmailOrPlayer, func(proof *PasswordProof) error {
		return s.LoginStore.Transaction(ctx, func(tx *sql.Tx) error {
			u, err := s.RecheckPassword(ctx, tx, proof)
			if err != nil {
				return err
			}
			result, err = s.issue(ctx, tx, u, proof.version, keep, "")
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("go_web_sessions")+" WHERE digest=?", Digest(old))
			return err
		})
	})
	return result, err
}

// VersionTx requires the users row lock. It initializes only during issuance;
// validation never treats a missing version as permission to authenticate.
func (s *Service) VersionTx(ctx context.Context, tx *sql.Tx, uid int64) (int64, error) {
	if _, err := tx.ExecContext(ctx, "INSERT IGNORE INTO "+s.Store.Table("go_auth_versions")+" (user_uid,version) VALUES (?,1)", uid); err != nil {
		return 0, err
	}
	var v int64
	err := tx.QueryRowContext(ctx, "SELECT version FROM "+s.Store.Table("go_auth_versions")+" WHERE user_uid=? FOR UPDATE", uid).Scan(&v)
	return v, err
}

// RevokeUID participates in the account owner's transaction. It must run while
// holding the users row lock, before password/permission changes commit.
func (s *Service) RevokeUID(ctx context.Context, tx *sql.Tx, uid int64) error {
	if _, err := s.VersionTx(ctx, tx, uid); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "UPDATE "+s.Store.Table("go_auth_versions")+" SET version=version+1 WHERE user_uid=?", uid)
	return err
}

func (s *Service) issue(ctx context.Context, tx *sql.Tx, u *User, version int64, keep bool, remember string) (*BrowserSession, error) {
	b := &BrowserSession{Token: Token(), CSRF: Token(), Expires: s.now().Add(s.SessionLifetime), User: u, Version: version}
	if keep {
		remember = Token()
		if _, err := tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("go_remember_tokens")+" (digest,user_uid,version,expires_at) VALUES (?,?,?,?)", Digest(remember), u.UID, version, s.now().Add(s.RememberLifetime).Unix()); err != nil {
			return nil, err
		}
		b.Remember = remember
	}
	var remembered []byte
	if remember != "" {
		remembered = Digest(remember)
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("go_web_sessions")+" (digest,user_uid,version,csrf,remember_digest,expires_at) VALUES (?,?,?,?,?,?)", Digest(b.Token), u.UID, version, b.CSRF, remembered, b.Expires.Unix())
	return b, err
}

func (s *Service) Recall(ctx context.Context, token string) (*BrowserSession, error) {
	var uid int64
	if err := s.Store.DB.QueryRowContext(ctx, "SELECT user_uid FROM "+s.Store.Table("go_remember_tokens")+" WHERE digest=?", Digest(token)).Scan(&uid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSession
		}
		return nil, err
	}
	var result *BrowserSession
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		u, err := s.accountForUpdate(ctx, tx, uid)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSession
		}
		if err != nil {
			return err
		}

		var version, current, expiry int64
		if err = tx.QueryRowContext(ctx, "SELECT version FROM "+s.Store.Table("go_auth_versions")+" WHERE user_uid=? FOR UPDATE", uid).Scan(&current); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrSession
			}
			return err
		}
		if err = tx.QueryRowContext(ctx, "SELECT version,expires_at FROM "+s.Store.Table("go_remember_tokens")+" WHERE digest=? FOR UPDATE", Digest(token)).Scan(&version, &expiry); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrSession
			}
			return err
		}
		if version != current || expiry <= s.now().Unix() || u.Permission < 0 {
			return ErrSession
		}
		result, err = s.issue(ctx, tx, &u.User, current, false, token)
		return err
	})
	return result, err
}

func (s *Service) Logout(ctx context.Context, token string) error {
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		var uid sql.NullInt64
		var remember []byte
		err := tx.QueryRowContext(ctx, "SELECT user_uid,remember_digest FROM "+s.Store.Table("go_web_sessions")+" WHERE digest=?", Digest(token)).Scan(&uid, &remember)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if uid.Valid {
			var ignored int64
			if err = tx.QueryRowContext(ctx, "SELECT uid FROM "+s.Store.Table("users")+" WHERE uid=? FOR UPDATE", uid.Int64).Scan(&ignored); err != nil {
				return err
			}
		}
		if len(remember) > 0 {
			if _, err = tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("go_remember_tokens")+" WHERE digest=?", remember); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("go_web_sessions")+" WHERE remember_digest=?", remember); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("go_web_sessions")+" WHERE digest=?", Digest(token))
		return err
	})
}
