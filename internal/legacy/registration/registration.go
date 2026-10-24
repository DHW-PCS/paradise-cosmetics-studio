// Package registration implements the M1 transactional invitation prototype.
// The original tables are preserved; duplicate invitation strings fail closed.
package registration

import (
	"blessing-skin-go/internal/legacy/revocation"
	"blessing-skin-go/internal/legacy/users"
	"context"
	"database/sql"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrDenied = errors.New("registration: invalid, duplicate or consumed registration")

type Service struct {
	DB           *sql.DB
	Prefix       string
	InitialScore int64
	FreePlayer   bool
	Now          func() time.Time
}
type Input struct{ Email, Password, Nickname, Player, Code, Source string }
type Result struct {
	UID int64 `json:"uid"`
	PID int64 `json:"pid"`
}

func (s *Service) Setup(ctx context.Context) error {
	if !regexp.MustCompile(`^[A-Za-z0-9_]*$`).MatchString(s.Prefix) {
		return ErrDenied
	}
	for _, q := range []string{"CREATE TABLE IF NOT EXISTS " + s.Prefix + "go_registration_lock (id INT PRIMARY KEY) ENGINE=InnoDB", "INSERT IGNORE INTO " + s.Prefix + "go_registration_lock VALUES(1)"} {
		if _, e := s.DB.ExecContext(ctx, q); e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) Register(ctx context.Context, in Input) (Result, error) {
	var out Result
	if in.Source != "local" || !users.EmailLooksLikeEmail(in.Email) || utf8.RuneCountInString(in.Password) < 8 || utf8.RuneCountInString(in.Password) > 32 || len(in.Password) > 72 || in.Code == "" || in.Nickname == "" || utf8.RuneCountInString(in.Nickname) > 50 {
		return out, ErrDenied
	}
	if s.FreePlayer && !regexp.MustCompile(`^[A-Za-z0-9_]{1,16}$`).MatchString(in.Player) {
		return out, ErrDenied
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	var lock int
	if e = tx.QueryRowContext(ctx, "SELECT id FROM "+s.Prefix+"go_registration_lock WHERE id=1 FOR UPDATE").Scan(&lock); e != nil {
		return out, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT id,used_by FROM "+s.Prefix+"invitation_codes WHERE code=? FOR UPDATE", in.Code)
	if e != nil {
		return out, e
	}
	var id, used int64
	count := 0
	for rows.Next() {
		count++
		if e = rows.Scan(&id, &used); e != nil {
			rows.Close()
			return out, e
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	if count != 1 || used != 0 {
		return out, ErrDenied
	}
	var n int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Prefix+"users WHERE email=?", in.Email).Scan(&n); e != nil {
		return out, e
	}
	if n != 0 {
		return out, ErrDenied
	}
	if s.FreePlayer {
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Prefix+"players WHERE name=?", in.Player).Scan(&n); e != nil {
			return out, e
		}
		if n != 0 {
			return out, ErrDenied
		}
	}
	hashed, e := bcrypt.GenerateFromPassword([]byte(in.Password), 10)
	if e != nil {
		return out, e
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	stamp := now.In(time.FixedZone("CST", 8*3600)).Format("2006-01-02 15:04:05")
	r, e := tx.ExecContext(ctx, "INSERT INTO "+s.Prefix+"users(email,nickname,password,score,permission,verified,register_at,last_sign_at,ip) VALUES(?,?,?,?,0,0,?,?,?)", in.Email, in.Nickname, string(hashed), s.InitialScore, stamp, stamp, "127.0.0.1")
	if e != nil {
		return out, e
	}
	out.UID, e = r.LastInsertId()
	if e != nil {
		return out, e
	}
	if s.FreePlayer {
		r, e = tx.ExecContext(ctx, "INSERT INTO "+s.Prefix+"players(uid,name,tid_skin,tid_cape,last_modified) VALUES(?,?,0,0,?)", out.UID, in.Player, stamp)
		if e != nil {
			return out, e
		}
		out.PID, e = r.LastInsertId()
		if e != nil {
			return out, e
		}
	}
	r, e = tx.ExecContext(ctx, "UPDATE "+s.Prefix+"invitation_codes SET used_by=?,used_at=? WHERE id=? AND used_by=0", out.UID, stamp, id)
	if e != nil {
		return out, e
	}
	nrows, e := r.RowsAffected()
	if e != nil {
		return out, e
	}
	if nrows != 1 {
		return out, ErrDenied
	}
	e = tx.Commit()
	return out, e
}

// ChangePassword is one cross-domain transaction. Ordinary logout does not
// call this; password changes invalidate browser, Passport and Yggdrasil credentials.
func ChangePassword(ctx context.Context, tx *sql.Tx, prefix string, uid int64, password string, secret []byte) error {
	if !regexp.MustCompile(`^[A-Za-z0-9_]*$`).MatchString(prefix) || utf8.RuneCountInString(password) < 8 || utf8.RuneCountInString(password) > 32 || len(password) > 72 {
		return ErrDenied
	}
	b, e := bcrypt.GenerateFromPassword([]byte(password), 10)
	if e != nil {
		return e
	}
	now := time.Now()
	var id int
	if e = tx.QueryRowContext(ctx, "SELECT id FROM "+prefix+"go_ygg_lock WHERE id=1 FOR UPDATE").Scan(&id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO "+prefix+"go_ygg_users(uid,revoked_before) VALUES(?,?) ON DUPLICATE KEY UPDATE revoked_before=GREATEST(revoked_before,VALUES(revoked_before))", uid, now.Unix()); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE "+prefix+"users SET password=?,remember_token=NULL WHERE uid=?", string(b), uid); e != nil {
		return e
	}
	for _, q := range []string{
		"UPDATE " + prefix + "oauth_refresh_tokens r JOIN " + prefix + "oauth_access_tokens a ON a.id=r.access_token_id SET r.revoked=1 WHERE a.user_id=?",
		"UPDATE " + prefix + "oauth_access_tokens SET revoked=1 WHERE user_id=?",
		"UPDATE " + prefix + "oauth_auth_codes SET revoked=1 WHERE user_id=?",
		"UPDATE " + prefix + "go_ygg_tokens SET revoked=1 WHERE uid=?",
	} {
		if _, e = tx.ExecContext(ctx, q, uid); e != nil {
			return e
		}
	}
	if e = revocation.BumpTx(ctx, tx, prefix, uid, string(b), secret, now); e != nil {
		return e
	}
	// The existing browser revocation store's password fingerprint also rejects
	// all old sessions, including legacy rows with no new issuance metadata.
	return nil
}

// ProviderRecovery refuses email-only linking. No provider is installed in
// the frozen production inventory; no network callback is simulated here.
func ProviderRecovery(provider, subject string, allowlist []string, hasMapping, hasPassword bool) string {
	allowed := false
	for _, p := range allowlist {
		if p == provider {
			allowed = true
		}
	}
	if !allowed {
		return "provider_unavailable"
	}
	if strings.TrimSpace(subject) == "" {
		return "new_provider_challenge"
	}
	if hasMapping {
		return "mapped_subject"
	}
	if hasPassword {
		return "authenticate_existing_then_bind"
	}
	return "recover_current_mailbox_then_explicit_bind"
}
