// Package passport implements the frozen Passport 10.2.2 / league/oauth2-server
// 8.3.3 token formats needed for the M1-02 proof of concept: RS256 access
// tokens, Defuse v2 password-encrypted authorization codes and refresh tokens,
// the oauth_* tables, and the authorization-code, refresh-token and password
// grants.
package passport

import (
	"crypto/rsa"
	"database/sql"
	"errors"
	"time"

	"blessing-skin-go/internal/legacy/users"
)

// Config holds the frozen settings for the PoC.
type Config struct {
	DB         *sql.DB
	Prefix     string
	Users      *users.Repo
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	AppKey     []byte
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	CodeTTL    time.Duration
	Scopes     []string
	Now        func() time.Time
	// Location matches the application timezone used when Eloquent writes
	// DATETIME columns (Asia/Shanghai, UTC+8, no DST).
	Location *time.Location
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c Config) location() *time.Location {
	if c.Location != nil {
		return c.Location
	}
	return time.FixedZone("CST", 8*60*60)
}

func (c Config) Validate() error {
	if c.DB == nil {
		return errors.New("passport: database is required")
	}
	if c.Users == nil {
		return errors.New("passport: user repository is required")
	}
	if c.PrivateKey == nil || c.PublicKey == nil {
		return errors.New("passport: RSA keys are required")
	}
	if len(c.AppKey) == 0 {
		return errors.New("passport: application key is required")
	}
	if c.AccessTTL <= 0 || c.RefreshTTL <= 0 || c.CodeTTL <= 0 {
		return errors.New("passport: token lifetimes must be positive")
	}
	if len(c.Scopes) == 0 {
		return errors.New("passport: scope list is required")
	}
	return nil
}
