package laravel

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrCookiePrefix is returned when a decrypted cookie does not start with the
// value prefix bound to its name. Laravel treats such a cookie as absent.
var ErrCookiePrefix = errors.New("laravel: cookie value prefix mismatch")

// CookieValuePrefix mirrors Illuminate\Cookie\CookieValuePrefix::create.
// It is an HMAC-SHA1 over the cookie name plus "v2", hex encoded, then "|".
func CookieValuePrefix(name string, key []byte) string {
	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(name + "v2"))
	return hex.EncodeToString(mac.Sum(nil)) + "|"
}

// RemoveCookieValuePrefix mirrors CookieValuePrefix::remove (substr 41).
func RemoveCookieValuePrefix(value string) string {
	if len(value) <= 41 {
		return ""
	}
	return value[41:]
}

// EncryptCookie mirrors EncryptCookies::encrypt for a single cookie.
func (e *Encrypter) EncryptCookie(name, value string) (string, error) {
	return e.EncryptString(CookieValuePrefix(name, e.key) + value)
}

// DecryptCookie mirrors EncryptCookies::decryptCookie followed by the prefix
// check. A cookie that decrypts but carries a different name's prefix is
// rejected, exactly like the middleware setting the value to null.
func (e *Encrypter) DecryptCookie(name, encoded string) (string, error) {
	plain, err := e.DecryptString(encoded)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(plain, CookieValuePrefix(name, e.key)) {
		return "", ErrCookiePrefix
	}
	return RemoveCookieValuePrefix(plain), nil
}

// DefaultGuardClass is the class whose FQCN is hashed into session keys.
const DefaultGuardClass = `Illuminate\Auth\SessionGuard`

// GuardClassSuffix reproduces sha1(static::class) from SessionGuard::getName.
func GuardClassSuffix(class string) string {
	sum := sha1.Sum([]byte(class))
	return hex.EncodeToString(sum[:])
}

// LoginKey reproduces SessionGuard::getName: login_<guard>_<sha1(class)>.
func LoginKey(guardName, class string) string {
	return "login_" + guardName + "_" + GuardClassSuffix(class)
}

// RecallerCookieName reproduces SessionGuard::getRecallerName.
func RecallerCookieName(guardName, class string) string {
	return "remember_" + guardName + "_" + GuardClassSuffix(class)
}

// CookieAttributes describes the attributes Laravel puts on session cookies.
type CookieAttributes struct {
	Name     string
	Path     string
	Domain   string
	Secure   bool
	HTTPOnly bool
	SameSite string
	Lifetime time.Duration
}

// Attributes returns the attributes of a cookie set by StartSession or
// SessionGuard, without touching the value.
func Attributes(name string, cfg SessionConfig) CookieAttributes {
	return CookieAttributes{
		Name:     name,
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		Secure:   cfg.Secure,
		HTTPOnly: cfg.HTTPOnly,
		SameSite: cfg.SameSite,
		Lifetime: time.Duration(cfg.LifetimeMinutes) * time.Minute,
	}
}

// SessionConfig holds the frozen session settings that affect compatibility.
type SessionConfig struct {
	Cookie          string
	Driver          string
	LifetimeMinutes int
	Encrypt         bool
	Path            string
	Domain          string
	Secure          bool
	HTTPOnly        bool
	SameSite        string
	Files           string
}

// Validate checks the subset of session settings this package understands.
func (c SessionConfig) Validate() error {
	if c.Cookie == "" {
		return errors.New("laravel: session cookie name is empty")
	}
	if c.Driver != "file" {
		return fmt.Errorf("laravel: session driver %q is not supported by the file store", c.Driver)
	}
	if c.LifetimeMinutes <= 0 {
		return fmt.Errorf("laravel: invalid session lifetime %d", c.LifetimeMinutes)
	}
	if c.Encrypt {
		return errors.New("laravel: encrypted session payloads are not supported")
	}
	return nil
}
