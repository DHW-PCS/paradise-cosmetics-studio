// Package remember implements the Laravel "remember me" recaller cookie.
package remember

import (
	"crypto/rand"
	"errors"
	"strconv"
	"strings"
	"time"

	"paradise-cosmetics-studio/internal/legacy/laravel"
)

var ErrMalformed = errors.New("remember: malformed recaller")

const tokenCharset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// NewToken returns a 60-character token shaped like Str::random(60).
func NewToken() (string, error) {
	buf := make([]byte, 60)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = tokenCharset[int(buf[i])%len(tokenCharset)]
	}
	return string(buf), nil
}

// Recaller mirrors SessionGuard::createRecaller's "id|token|password" value.
type Recaller struct {
	UID      int64
	Token    string
	Password string
}

// Parse splits a decrypted recaller value.
func Parse(value string) (*Recaller, error) {
	parts := strings.Split(value, "|")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	uid, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || uid <= 0 || parts[1] == "" {
		return nil, ErrMalformed
	}
	return &Recaller{UID: uid, Token: parts[1], Password: parts[2]}, nil
}

// Format builds the recaller value.
func Format(uid int64, token, password string) string {
	return strconv.FormatInt(uid, 10) + "|" + token + "|" + password
}

// Cookie decrypts a remember_web_* cookie into a recaller.
func Cookie(e *laravel.Encrypter, cookieName, value string) (*Recaller, error) {
	plain, err := e.DecryptCookie(cookieName, value)
	if err != nil {
		return nil, err
	}
	return Parse(plain)
}

// CookieValue encrypts a recaller the way EncryptCookies does.
func CookieValue(e *laravel.Encrypter, cookieName string, r *Recaller) (string, error) {
	return e.EncryptCookie(cookieName, Format(r.UID, r.Token, r.Password))
}

// Duration converts the guard's remember minutes into a cookie lifetime.
func Duration(minutes int) time.Duration {
	return time.Duration(minutes) * time.Minute
}
