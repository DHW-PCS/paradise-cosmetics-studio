// Package links checks Laravel relative URL signatures with the literal
// configured APP_KEY and prototypes D06 identity-bound single consumption.
package links

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ErrChallenge = errors.New("links: request a new challenge for the current identity")
var ErrDenied = errors.New("links: invalid, expired, consumed or changed identity")

func Verify(raw, key, basePath string, now time.Time) error {
	u, e := url.Parse(raw)
	if e != nil || key == "" || u.Fragment != "" {
		return ErrDenied
	}
	path := u.EscapedPath()
	if basePath != "" {
		if !strings.HasPrefix(path, strings.TrimRight(basePath, "/")+"/") {
			return ErrDenied
		}
		path = strings.TrimPrefix(path, strings.TrimRight(basePath, "/"))
	}
	path = "/" + strings.Trim(path, "/")
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil || len(q["signature"]) != 1 || len(q["expires"]) > 1 {
		return ErrDenied
	}
	signature := q.Get("signature")
	sig, e := hex.DecodeString(signature)
	if e != nil || len(sig) != 32 {
		return ErrDenied
	}
	query := regexp.MustCompile(`(^|&)signature=[^&]+`).ReplaceAllString(u.RawQuery, "")
	query = strings.TrimLeft(query, "&")
	original := strings.TrimRight(path+"?"+query, "?")
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(original))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return ErrDenied
	}
	if rawExpiry := q.Get("expires"); rawExpiry != "" {
		expiry, e := strconv.ParseInt(rawExpiry, 10, 64)
		if e != nil || now.Unix() > expiry {
			return ErrDenied
		}
	}
	return nil
}
func Fingerprint(raw string) string          { h := sha256.Sum256([]byte(raw)); return hex.EncodeToString(h[:]) }
func Identity(email, password string) string { return Fingerprint(email + "\x00" + password) }

type Ledger struct {
	DB                    *sql.DB
	Prefix, Key, BasePath string
	Now                   func() time.Time
}

func (l *Ledger) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}
func (l *Ledger) Setup(ctx context.Context) error {
	if !regexp.MustCompile(`^[A-Za-z0-9_]*$`).MatchString(l.Prefix) {
		return ErrDenied
	}
	_, e := l.DB.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+l.Prefix+"go_link_claims (fingerprint CHAR(64) PRIMARY KEY,uid BIGINT NOT NULL,kind VARCHAR(16) NOT NULL,identity_hash CHAR(64) NOT NULL,expires_at BIGINT NOT NULL,consumed BOOLEAN NOT NULL DEFAULT 0) ENGINE=InnoDB")
	return e
}

// Observe is called by a trusted signing/transition writer at issuance. It is
// not a first-click migration: legacy verify URLs lack identity evidence.
func (l *Ledger) Observe(ctx context.Context, raw, kind, identity string, uid, expiry int64) error {
	if kind != "reset" && kind != "verify" {
		return ErrDenied
	}
	if expiry <= l.now().Unix() || expiry > l.now().Unix()+3600 || uid <= 0 || len(identity) != 64 {
		return ErrDenied
	}
	if e := Verify(raw, l.Key, l.BasePath, l.now()); e != nil {
		return e
	}
	u, _ := url.Parse(raw)
	if kind == "reset" {
		ex, e := strconv.ParseInt(u.Query().Get("expires"), 10, 64)
		if e != nil || expiry > ex {
			return ErrDenied
		}
	}
	_, e := l.DB.ExecContext(ctx, "INSERT INTO "+l.Prefix+"go_link_claims VALUES(?,?,?,?,?,0)", Fingerprint(raw), uid, kind, identity, expiry)
	return e
}

// Consume marks the claim consumed in one transaction. The rollback writer must
// consult this same claim ledger.
func (l *Ledger) Consume(ctx context.Context, raw, kind, identity string, uid int64) error {
	tx, e := l.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e := l.consumeTx(ctx, tx, raw, kind, identity, uid, nil); e != nil {
		return e
	}
	return tx.Commit()
}

// ConsumeReset consumes a reset claim and applies the password change in one
// transaction. lock is applied before the account row so a reset always takes
// the caller's global writer lock first and never inverts the order used by
// uploads and outbox writes.
func (l *Ledger) ConsumeReset(ctx context.Context, raw, identity string, uid int64, lock func(context.Context, *sql.Tx) error, change func(*sql.Tx) error) error {
	tx, e := l.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if lock != nil {
		if e := lock(ctx, tx); e != nil {
			return e
		}
	}
	if e := l.consumeTx(ctx, tx, raw, "reset", identity, uid, change); e != nil {
		return e
	}
	return tx.Commit()
}

// consumeTx checks the claim and applies the change inside the caller's
// transaction. The canonical lock order is global writer lock, then users, then
// the claim; this helper only takes the latter two.
func (l *Ledger) consumeTx(ctx context.Context, tx *sql.Tx, raw, kind, identity string, uid int64, change func(*sql.Tx) error) error {
	if e := Verify(raw, l.Key, l.BasePath, l.now()); e != nil {
		return e
	}
	// Lock the account first so a concurrent password change and this
	// consumption serialize, then read the claim.
	var currentEmail, currentPassword string
	e := tx.QueryRowContext(ctx, "SELECT email,password FROM "+l.Prefix+"users WHERE uid=? FOR UPDATE", uid).Scan(&currentEmail, &currentPassword)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrDenied
	}
	if e != nil {
		return e
	}
	var owner, expiry int64
	var k, version string
	var used bool
	e = tx.QueryRowContext(ctx, "SELECT uid,kind,identity_hash,expires_at,consumed FROM "+l.Prefix+"go_link_claims WHERE fingerprint=? FOR UPDATE", Fingerprint(raw)).Scan(&owner, &k, &version, &expiry, &used)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrChallenge
	}
	if e != nil {
		return e
	}
	if used || owner != uid || k != kind || version != identity || l.now().Unix() > expiry {
		return ErrDenied
	}
	if Identity(currentEmail, currentPassword) != version {
		return ErrDenied
	}
	if change != nil {
		if e = change(tx); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE "+l.Prefix+"go_link_claims SET consumed=1 WHERE fingerprint=?", Fingerprint(raw)); e != nil {
		return e
	}
	return nil
}
