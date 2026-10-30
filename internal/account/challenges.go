package account

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/legacy/password"
	"blessing-skin-go/internal/site"
	"golang.org/x/crypto/hkdf"
)

const MailTopic = "account.mail.v1"

type mailPayload struct {
	UID, Version                  int64
	Purpose, Email, Token, Locale string
}
type sealedMail struct {
	Version int    `json:"v"`
	Sealed  string `json:"sealed"`
}

const mailAAD = "blessing-skin/account-mail/v1"

func mailCipher(key []byte) (cipher.AEAD, error) {
	derived := make([]byte, 32)
	if len(key) < 32 {
		return nil, errors.New("account: APP_KEY too short")
	}
	if _, err := io.ReadFull(hkdf.New(sha256.New, key, nil, []byte(mailAAD)), derived); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func (m *Mail) seal(p mailPayload) (json.RawMessage, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, m.cipher.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	encrypted := m.cipher.Seal(nonce, nonce, body, []byte(mailAAD))
	return json.Marshal(sealedMail{1, base64.RawURLEncoding.EncodeToString(encrypted)})
}
func (m *Mail) open(raw json.RawMessage) (mailPayload, error) {
	var envelope sealedMail
	var p mailPayload
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.Version != 1 {
		return p, errors.New("account: invalid mail envelope")
	}
	data, err := base64.RawURLEncoding.DecodeString(envelope.Sealed)
	if err != nil || len(data) < m.cipher.NonceSize()+m.cipher.Overhead() {
		return p, errors.New("account: invalid mail envelope")
	}
	body, err := m.cipher.Open(nil, data[:m.cipher.NonceSize()], data[m.cipher.NonceSize():], []byte(mailAAD))
	if err != nil {
		return p, errors.New("account: invalid mail envelope")
	}
	if err = json.Unmarshal(body, &p); err != nil || (p.Purpose != "reset" && p.Purpose != "verify") || p.Token == "" || p.UID <= 0 {
		return p, errors.New("account: invalid mail payload")
	}
	return p, nil
}
func (s *Service) issueChallenge(ctx context.Context, tx *sql.Tx, u *identity.User, version int64, purpose, locale string) error {
	token := identity.Token()
	var expiry any
	if purpose == "reset" {
		expiry = s.Now().Add(time.Hour).Unix()
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("go_mail_challenges")+" WHERE user_uid=? AND purpose=?", u.UID, purpose); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("go_mail_challenges")+" (digest,user_uid,version,purpose,target_email,issued_at,expires_at) VALUES (?,?,?,?,?,?,?)", identity.Digest(token), u.UID, version, purpose, u.Email, s.Now().Unix(), expiry); err != nil {
		return err
	}
	payload, err := s.Mail.seal(mailPayload{u.UID, version, purpose, u.Email, token, locale})
	if err != nil {
		return err
	}
	return s.Outbox.Enqueue(ctx, tx, fmt.Sprintf("mail:%x", identity.Digest(token)), MailTopic, payload)
}

// cooldown is called only while holding the mail namespace. Its update belongs
// to the same transaction as the challenge and outbox insertion.
func (s *Service) cooldown(ctx context.Context, tx *sql.Tx, key string, interval time.Duration) error {
	var expiry int64
	err := tx.QueryRowContext(ctx, "SELECT expires_at FROM "+s.Store.Table("go_browser_limits")+" WHERE digest=? FOR UPDATE", identity.Digest(key)).Scan(&expiry)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if expiry > s.Now().Unix() {
		return ErrTooSoon
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("go_browser_limits")+" (digest,count,expires_at) VALUES (?,1,?) ON DUPLICATE KEY UPDATE expires_at=VALUES(expires_at)", identity.Digest(key), s.Now().Add(interval).Unix())
	return err
}
func (s *Service) Forgot(ctx context.Context, email, ip, locale string) error {
	if s.Mail == nil {
		return ErrModuleUnavailable
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if err := database.LockNamespaces(ctx, tx, s.Store, "email", "mail"); err != nil {
			return err
		}
		if err := s.cooldown(ctx, tx, "forgot:"+ip, 180*time.Second); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, "SELECT uid,email,permission FROM "+s.Store.Table("users")+" WHERE email=? ORDER BY uid FOR UPDATE", email)
		if err != nil {
			return err
		}
		var found []identity.User
		for rows.Next() {
			var u identity.User
			if err = rows.Scan(&u.UID, &u.Email, &u.Permission); err != nil {
				rows.Close()
				return err
			}
			found = append(found, u)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(found) == 0 {
			return ErrNotFound
		}
		if len(found) != 1 {
			return ErrAmbiguous
		}
		u := found[0]
		version, err := s.Identity.VersionTx(ctx, tx, u.UID)
		if err != nil {
			return err
		}
		return s.issueChallenge(ctx, tx, &u, version, "reset", locale)
	})
}

var ErrAmbiguous = errors.New("account: ambiguous legacy identity")

func (s *Service) SendVerification(ctx context.Context, b *identity.BrowserSession, locale string) error {
	options, err := s.Site.Options(ctx)
	if err != nil {
		return err
	}
	if !site.Truth(options["require_verification"]) {
		return ErrVerificationDisabled
	}
	if s.Mail == nil {
		return ErrModuleUnavailable
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if err := database.LockNamespaces(ctx, tx, s.Store, "mail"); err != nil {
			return err
		}
		if err := s.cooldown(ctx, tx, "verify:"+b.Token, 60*time.Second); err != nil {
			return err
		}
		u, err := s.Identity.CheckBrowserTx(ctx, tx, b)
		if err != nil {
			return err
		}
		if u.Verified {
			return ErrAlreadyVerified
		}
		return s.issueChallenge(ctx, tx, u, b.Version, "verify", locale)
	})
}
func (s *Service) challengeTx(ctx context.Context, tx *sql.Tx, uid int64, purpose, token string) (*identity.User, error) {
	u := &identity.User{}
	var version int64
	err := tx.QueryRowContext(ctx, "SELECT uid,email,nickname,permission FROM "+s.Store.Table("users")+" WHERE uid=? FOR UPDATE", uid).Scan(&u.UID, &u.Email, &u.Nickname, &u.Permission)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidChallenge
	}
	if err != nil {
		return nil, err
	}
	if err = tx.QueryRowContext(ctx, "SELECT version FROM "+s.Store.Table("go_auth_versions")+" WHERE user_uid=? FOR UPDATE", uid).Scan(&version); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidChallenge
	} else if err != nil {
		return nil, err
	}
	var expectedVersion int64
	var email string
	var expiry sql.NullInt64
	err = tx.QueryRowContext(ctx, "SELECT version,target_email,expires_at FROM "+s.Store.Table("go_mail_challenges")+" WHERE digest=? AND user_uid=? AND purpose=? FOR UPDATE", identity.Digest(token), uid, purpose).Scan(&expectedVersion, &email, &expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidChallenge
	}
	if err != nil {
		return nil, err
	}
	if token == "" || version != expectedVersion || email != u.Email || (expiry.Valid && expiry.Int64 <= s.Now().Unix()) {
		return nil, ErrInvalidChallenge
	}
	return u, nil
}

// InspectChallenge does not consume the token. Only POST changes account state.
func (s *Service) InspectChallenge(ctx context.Context, uid int64, purpose, token string) (*identity.User, error) {
	var u *identity.User
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		var err error
		u, err = s.challengeTx(ctx, tx, uid, purpose, token)
		return err
	})
	return u, err
}
func (s *Service) ResetPassword(ctx context.Context, uid int64, token, raw string) error {
	if err := password.ValidateRegistration(raw); err != nil {
		return err
	}
	hash, err := s.hash(ctx, raw)
	if err != nil {
		return err
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err := s.challengeTx(ctx, tx, uid, "reset", token); err != nil {
			return err
		}
		if err := s.Identity.RevokeUID(ctx, tx, uid); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET password=? WHERE uid=?", hash, uid); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("go_mail_challenges")+" WHERE digest=?", identity.Digest(token))
		return err
	})
}
func (s *Service) Verify(ctx context.Context, uid int64, token, email string) error {
	options, err := s.Site.Options(ctx)
	if err != nil {
		return err
	}
	if !site.Truth(options["require_verification"]) {
		return ErrVerificationDisabled
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		u, err := s.challengeTx(ctx, tx, uid, "verify", token)
		if err != nil {
			return err
		}
		if email != u.Email {
			return ErrEmailMismatch
		}
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET verified=1 WHERE uid=?", uid); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("go_mail_challenges")+" WHERE digest=?", identity.Digest(token))
		return err
	})
}

var ErrEmailMismatch = errors.New("account: challenge email mismatch")
