package password

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// The legacy controllers apply Laravel's min/max string rules, which use
// mb_strlen (characters, not bytes). The rules are split per entry point so a
// 6-character legacy password can still log in while new passwords are
// required to be longer.

// ErrLength reports a password that violates the frozen length rule.
var ErrLength = errors.New("password: length out of range")

// ValidateLogin checks POST /auth/login: required|min:6|max:32.
func ValidateLogin(raw string) error {
	if raw == "" {
		return ErrEmptyPassword
	}
	return lengthBetween("login", raw, 6, 32)
}

// ValidateRegistration checks local and invitation registration:
// required|min:8|max:32.
func ValidateRegistration(raw string) error {
	if raw == "" {
		return ErrEmptyPassword
	}
	return lengthBetween("registration", raw, 8, 32)
}

// ValidateAdminReset checks the admin password reset path: 8..16.
func ValidateAdminReset(raw string) error {
	if raw == "" {
		return ErrEmptyPassword
	}
	return lengthBetween("admin reset", raw, 8, 16)
}

func lengthBetween(entry, raw string, min, max int) error {
	n := utf8.RuneCountInString(raw)
	if n < min || n > max {
		return fmt.Errorf("%w: %s needs %d-%d characters, got %d", ErrLength, entry, min, max, n)
	}
	return nil
}
