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

// ClaimDomain version-marks the single-consumption claim identity. It keeps a
// claim key out of every other SHA-256 over a raw URL, so a row written under
// the old raw-hash contract can never be mistaken for a claim of a different
// representation. Rows written before this marker cannot be migrated: a raw
// URL cannot be recovered from its digest, so they are left as orphans and new
// claims are rebuilt from controlled issuance instead.
const ClaimDomain = "m1-go-link-claim-v1"

// signatureParam removes the signature parameter from the raw query while
// keeping every other byte, its order and any duplicate parameters intact. This
// is the frozen Laravel expression, not a decoded re-encoding.
var signatureParam = regexp.MustCompile(`(^|&)signature=[^&]+`)

// parseSigned reduces a legacy signed link to the bytes the frozen Laravel
// signer covers: the configured-base-path-relative escaped path plus the raw
// query with the signature parameter removed. Origin, deployment prefix and
// fragment are not part of the signed representation, and the raw query bytes
// keep their original order, duplicates and percent-encoding.
func parseSigned(raw, basePath string) (string, url.Values, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Fragment != "" {
		return "", nil, ErrDenied
	}
	path := u.EscapedPath()
	if basePath != "" {
		if !strings.HasPrefix(path, strings.TrimRight(basePath, "/")+"/") {
			return "", nil, ErrDenied
		}
		path = strings.TrimPrefix(path, strings.TrimRight(basePath, "/"))
	}
	path = "/" + strings.Trim(path, "/")
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil || len(q["signature"]) != 1 || len(q["expires"]) > 1 {
		return "", nil, ErrDenied
	}
	query := signatureParam.ReplaceAllString(u.RawQuery, "")
	query = strings.TrimLeft(query, "&")
	return strings.TrimRight(path+"?"+query, "?"), q, nil
}

// verifySignedLink is the single verification path shared by Verify, Observe
// and Consume. The returned claim key is only produced after the shape, the
// signature and the expiry check pass, so no caller can key the ledger on
// unverified bytes.
func verifySignedLink(raw, key, basePath string, now time.Time) (string, url.Values, error) {
	if key == "" {
		return "", nil, ErrDenied
	}
	target, q, e := parseSigned(raw, basePath)
	if e != nil {
		return "", nil, e
	}
	// Compare the provided signature with the computed lowercase hex string
	// instead of decoding it first: the frozen native signer compares the hex
	// string case-sensitively, so uppercase, mixed-case, odd-length and non-hex
	// encodings must be denied exactly like native does.
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(target))
	want := make([]byte, hex.EncodedLen(mac.Size()))
	hex.Encode(want, mac.Sum(nil))
	if !hmac.Equal([]byte(q.Get("signature")), want) {
		return "", nil, ErrDenied
	}
	if rawExpiry := q.Get("expires"); rawExpiry != "" {
		expiry, e := strconv.ParseInt(rawExpiry, 10, 64)
		if e != nil || now.Unix() > expiry {
			return "", nil, ErrDenied
		}
	}
	return claimKey(target), q, nil
}

func Verify(raw, key, basePath string, now time.Time) error {
	_, _, e := verifySignedLink(raw, key, basePath, now)
	return e
}

// claimKey maps verified signed-link bytes to the single-consumption claim
// identity. Only the deployment-independent representation is hashed, so the
// relative and absolute forms of one signed link share one claim.
func claimKey(target string) string { return Fingerprint(ClaimDomain + "\x00" + target) }

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

// verified returns the claim key and the decoded query of a link whose signed
// representation verified under this ledger's key and base path.
func (l *Ledger) verified(raw string) (string, url.Values, error) {
	return verifySignedLink(raw, l.Key, l.BasePath, l.now())
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
	claim, query, e := l.verified(raw)
	if e != nil {
		return e
	}
	if kind == "reset" {
		ex, e := strconv.ParseInt(query.Get("expires"), 10, 64)
		if e != nil || expiry > ex {
			return ErrDenied
		}
	}
	_, e = l.DB.ExecContext(ctx, "INSERT INTO "+l.Prefix+"go_link_claims VALUES(?,?,?,?,?,0)", claim, uid, kind, identity, expiry)
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
// the claim; this helper only takes the latter two. Observe, the claim lookup
// and the consumption UPDATE all use the same verified claim key.
func (l *Ledger) consumeTx(ctx context.Context, tx *sql.Tx, raw, kind, identity string, uid int64, change func(*sql.Tx) error) error {
	claim, _, e := l.verified(raw)
	if e != nil {
		return e
	}
	// Lock the account first so a concurrent password change and this
	// consumption serialize, then read the claim.
	var currentEmail, currentPassword string
	e = tx.QueryRowContext(ctx, "SELECT email,password FROM "+l.Prefix+"users WHERE uid=? FOR UPDATE", uid).Scan(&currentEmail, &currentPassword)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrDenied
	}
	if e != nil {
		return e
	}
	var owner, expiry int64
	var k, version string
	var used bool
	e = tx.QueryRowContext(ctx, "SELECT uid,kind,identity_hash,expires_at,consumed FROM "+l.Prefix+"go_link_claims WHERE fingerprint=? FOR UPDATE", claim).Scan(&owner, &k, &version, &expiry, &used)
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
	if _, e = tx.ExecContext(ctx, "UPDATE "+l.Prefix+"go_link_claims SET consumed=1 WHERE fingerprint=?", claim); e != nil {
		return e
	}
	return nil
}
