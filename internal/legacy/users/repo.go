// Package users reads the legacy users/players tables.
package users

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

// User is the subset of a legacy users row needed for authentication.
type User struct {
	UID           int64  `json:"uid"`
	Email         string `json:"email"`
	Nickname      string `json:"nickname"`
	Permission    int    `json:"permission"`
	Verified      bool   `json:"verified"`
	Password      string `json:"password"`
	RememberToken string `json:"remember_token"`
}

// Permission levels from App\Models\User.
const (
	Banned     = -1
	Normal     = 0
	Admin      = 1
	SuperAdmin = 2
)

// Repo queries a prefixed legacy schema.
type Repo struct {
	db     *sql.DB
	prefix string
}

// New wraps an existing connection.
func New(db *sql.DB, prefix string) *Repo {
	return &Repo{db: db, prefix: prefix}
}

// Open connects with a database/sql MySQL DSN.
func Open(dsn, prefix string) (*Repo, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("users: ping: %w", err)
	}
	return &Repo{db: db, prefix: prefix}, nil
}

// Close releases the connection pool.
func (r *Repo) Close() error { return r.db.Close() }

// DB exposes the underlying connection for additive stores (revocation).
func (r *Repo) DB() *sql.DB { return r.db }

const columns = "u.uid, u.email, u.nickname, u.permission, u.verified, u.password, COALESCE(u.remember_token, '')"

func (r *Repo) scan(row *sql.Row) (*User, bool, error) {
	var u User
	var verified int
	if err := row.Scan(&u.UID, &u.Email, &u.Nickname, &u.Permission, &verified, &u.Password, &u.RememberToken); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	u.Verified = verified != 0
	return &u, true, nil
}

// ByEmail performs the legacy email lookup (collation controls case).
func (r *Repo) ByEmail(ctx context.Context, email string) (*User, bool, error) {
	q := fmt.Sprintf("SELECT %s FROM %susers u WHERE u.email = ? LIMIT 1", columns, r.prefix)
	return r.scan(r.db.QueryRowContext(ctx, q, email))
}

// ByPlayerName resolves a login identification that is not an email address:
// the frozen controller looks up players.name and takes its owner.
func (r *Repo) ByPlayerName(ctx context.Context, name string) (*User, bool, error) {
	q := fmt.Sprintf("SELECT %s FROM %susers u JOIN %splayers p ON p.uid = u.uid WHERE p.name = ? LIMIT 1",
		columns, r.prefix, r.prefix)
	return r.scan(r.db.QueryRowContext(ctx, q, name))
}

// ByUID loads a user by primary key.
func (r *Repo) ByUID(ctx context.Context, uid int64) (*User, bool, error) {
	q := fmt.Sprintf("SELECT %s FROM %susers u WHERE u.uid = ? LIMIT 1", columns, r.prefix)
	return r.scan(r.db.QueryRowContext(ctx, q, uid))
}

// ByUIDForUpdate locks the user row. Authentication checks that must bind a
// credential to the current account state use it so that a concurrent password
// change or session revocation cannot commit in between.
func (r *Repo) ByUIDForUpdate(ctx context.Context, tx *sql.Tx, uid int64) (*User, bool, error) {
	q := fmt.Sprintf("SELECT %s FROM %susers u WHERE u.uid = ? LIMIT 1 FOR UPDATE", columns, r.prefix)
	return r.scan(tx.QueryRowContext(ctx, q, uid))
}

// ByEmailForUpdate is the locked variant of ByEmail for the password grant.
func (r *Repo) ByEmailForUpdate(ctx context.Context, tx *sql.Tx, email string) (*User, bool, error) {
	q := fmt.Sprintf("SELECT %s FROM %susers u WHERE u.email = ? LIMIT 1 FOR UPDATE", columns, r.prefix)
	return r.scan(tx.QueryRowContext(ctx, q, email))
}

// ByEmailTx reads inside the caller's transaction without locking.
func (r *Repo) ByEmailTx(ctx context.Context, tx *sql.Tx, email string) (*User, bool, error) {
	q := fmt.Sprintf("SELECT %s FROM %susers u WHERE u.email = ? LIMIT 1", columns, r.prefix)
	return r.scan(tx.QueryRowContext(ctx, q, email))
}

// ByPlayerNameTx reads inside the caller's transaction without locking.
func (r *Repo) ByPlayerNameTx(ctx context.Context, tx *sql.Tx, name string) (*User, bool, error) {
	q := fmt.Sprintf("SELECT %s FROM %susers u JOIN %splayers p ON p.uid = u.uid WHERE p.name = ? LIMIT 1",
		columns, r.prefix, r.prefix)
	return r.scan(tx.QueryRowContext(ctx, q, name))
}

// UpdateRememberToken mirrors EloquentUserProvider::updateRememberToken.
func (r *Repo) UpdateRememberToken(ctx context.Context, uid int64, token string) error {
	q := fmt.Sprintf("UPDATE %susers SET remember_token = ? WHERE uid = ?", r.prefix)
	_, err := r.db.ExecContext(ctx, q, token, uid)
	return err
}

// UpdateRememberTokenTx updates the recaller inside the caller's transaction.
func (r *Repo) UpdateRememberTokenTx(ctx context.Context, tx *sql.Tx, uid int64, token string) error {
	q := fmt.Sprintf("UPDATE %susers SET remember_token = ? WHERE uid = ?", r.prefix)
	_, err := tx.ExecContext(ctx, q, token, uid)
	return err
}

// EmailLooksLikeEmail approximates filter_var($s, FILTER_VALIDATE_EMAIL), which
// the frozen login uses to choose between the email and player-name branches.
// The approximation is cross-checked against a PHP-generated corpus; any
// divergence is recorded rather than silently accepted.
func EmailLooksLikeEmail(s string) bool {
	if s == "" || len(s) > 254 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	at := strings.LastIndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return false
	}
	return validLocalPart(s[:at]) && validDomain(s[at+1:])
}

func validLocalPart(local string) bool {
	if strings.HasPrefix(local, `"`) {
		if len(local) < 2 || !strings.HasSuffix(local, `"`) {
			return false
		}
		inner := local[1 : len(local)-1]
		escaped := false
		for i := 0; i < len(inner); i++ {
			c := inner[i]
			if escaped {
				if c < 0x20 || c > 0x7e {
					return false
				}
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' || c == ' ' || c < 0x20 || c > 0x7e {
				return false
			}
		}
		return !escaped
	}
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return false
	}
	for _, atom := range strings.Split(local, ".") {
		if atom == "" {
			return false
		}
		for i := 0; i < len(atom); i++ {
			if !isAText(atom[i]) {
				return false
			}
		}
	}
	return true
}

// isAText is the RFC 5322 atext set; it deliberately excludes dot and @.
func isAText(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-/=?^_`{|}~", c) >= 0
}

func validDomain(domain string) bool {
	if strings.HasPrefix(domain, "[") && strings.HasSuffix(domain, "]") {
		ip := net.ParseIP(domain[1 : len(domain)-1])
		// filter_var accepts IPv4 literals but rejects IPv6 literals.
		return ip != nil && ip.To4() != nil
	}
	if len(domain) > 255 {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	last := labels[len(labels)-1]
	hasLetter := false
	for _, r := range last {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetter = true
			break
		}
	}
	if !hasLetter {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			return false
		}
	}
	return true
}
