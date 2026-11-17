// Package web implements the legacy HTTP authentication surface used by the
// M1 compatibility proof: the Laravel web middleware stack, CSRF handling, the
// session guard and the small set of routes needed to compare both
// implementations at the protocol level.
package web

import (
	"context"
	"errors"
	"fmt"
	"time"

	"paradise-cosmetics-studio/internal/legacy/auth"
	"paradise-cosmetics-studio/internal/legacy/cache"
	"paradise-cosmetics-studio/internal/legacy/laravel"
	"paradise-cosmetics-studio/internal/legacy/php"
	"paradise-cosmetics-studio/internal/legacy/revocation"
	"paradise-cosmetics-studio/internal/legacy/session"
	"paradise-cosmetics-studio/internal/legacy/users"
)

// UserLookup resolves a user by UID for the recaller and ban paths and can
// rotate the remember token, matching EloquentUserProvider.
type UserLookup interface {
	ByUID(ctx context.Context, uid int64) (*users.User, bool, error)
	UpdateRememberToken(ctx context.Context, uid int64, token string) error
}

// BearerIdentity is the result of validating an OAuth bearer token.
type BearerIdentity struct {
	UID      int64    `json:"uid"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

// BearerValidator validates an access token. A nil validator makes /api/user
// always reject the request.
type BearerValidator func(ctx context.Context, token string) (*BearerIdentity, error)

// Authenticator is the subset of auth.Service the HTTP layer uses. Keeping it
// separate lets HTTP tests stay independent of a live account database.
type Authenticator interface {
	Login(context.Context, string, string, bool) (*auth.LoginResult, error)
	ValidateSession(context.Context, *php.Array) (*auth.Validation, error)
	UpgradeLegacy(context.Context, int64) (*revocation.State, error)
	RememberState(context.Context, int64, string) (*users.User, *revocation.State, error)
}

// Config holds the frozen settings copied from the reference application.
type Config struct {
	Encrypter *laravel.Encrypter
	Sessions  *session.Store
	Cache     *cache.Store
	Auth      Authenticator
	Users     UserLookup

	SessionCookie    laravel.CookieAttributes
	XSRFCookie       string
	RememberCookie   string
	RememberLifetime time.Duration
	LoginKey         string

	Bearer BearerValidator
	Now    func() time.Time
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Validate checks the settings the HTTP layer relies on.
func (c Config) Validate() error {
	if c.Encrypter == nil {
		return errors.New("web: encrypter is required")
	}
	if c.Sessions == nil {
		return errors.New("web: session store is required")
	}
	if c.Auth == nil {
		return errors.New("web: auth service is required")
	}
	if c.Users == nil {
		return errors.New("web: user lookup is required")
	}
	if c.SessionCookie.Name == "" {
		return errors.New("web: session cookie name is required")
	}
	if c.SessionCookie.Lifetime <= 0 {
		return fmt.Errorf("web: invalid session lifetime %s", c.SessionCookie.Lifetime)
	}
	if c.XSRFCookie == "" {
		return errors.New("web: XSRF cookie name is required")
	}
	if c.RememberCookie == "" {
		return errors.New("web: remember cookie name is required")
	}
	if c.RememberLifetime <= 0 {
		return errors.New("web: invalid remember lifetime")
	}
	if c.LoginKey == "" {
		return errors.New("web: login key is required")
	}
	return nil
}
