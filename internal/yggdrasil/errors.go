// Package yggdrasil implements the Yggdrasil state domain for the Go rewrite:
// JWT tokens, join tickets, username rate limits and signed profiles.
// Transport stays in the HTTP layer; this package owns only the service
// contract, its typed errors and its persistence.
package yggdrasil

import (
	"errors"
	"fmt"
)

// APIError carries the frozen protocol error contract: status code, error
// short name and message. The HTTP layer renders {error,errorMessage[,cause]}.
type APIError struct {
	Status  int
	Name    string
	Message string
	Cause   string
}

func (e *APIError) Error() string { return fmt.Sprintf("%s: %s", e.Name, e.Message) }

// IsAPIError reports whether err is a protocol APIError.
func IsAPIError(err error) bool {
	_, ok := err.(*APIError)
	return ok
}

// StatusOf returns the HTTP status for an APIError, or 500 for other errors.
func StatusOf(err error) int {
	if e, ok := err.(*APIError); ok {
		return e.Status
	}
	return 500
}

// NameOf returns the error name for an APIError, or InternalServerError.
func NameOf(err error) string {
	if e, ok := err.(*APIError); ok {
		return e.Name
	}
	return "InternalServerError"
}

func illegalArgument(msg string) *APIError {
	return &APIError{Status: 400, Name: "IllegalArgumentException", Message: msg}
}
func unauthorized(msg string) *APIError {
	return &APIError{Status: 401, Name: "UnauthorizedException", Message: msg}
}
func forbidden(msg string) *APIError {
	return &APIError{Status: 403, Name: "ForbiddenOperationException", Message: msg}
}
func notFound(msg string) *APIError {
	return &APIError{Status: 404, Name: "NotFoundException", Message: msg}
}

// Protocol messages mirror the legacy lang files; batch4 renders them verbatim.
var (
	ErrAuthEmpty        = illegalArgument("Email address and password are required.")
	ErrAuthNotMatched   = forbidden("Invalid credential information.")
	ErrTokenInvalid     = forbidden("Invalid AccessToken. Please re-login.")
	ErrTokenNotMatched  = forbidden("ClientToken isn't matched with AccessToken. Please re-login.")
	ErrUserBanned       = forbidden("You're banned.")
	ErrUserNotVerified  = forbidden("Your email isn't verified. Please verify it before logging in.")
	ErrPlayerNotExisted = illegalArgument("Player is not found.")
	ErrPlayerNotMatched = illegalArgument("The player requested doesn't match with that token.")
	ErrPlayerOwner      = forbidden("The player requested doesn't belong to that user.")
	ErrRSAInvalid       = illegalArgument("The RSA private key is invalid.")
	ErrRSALength        = illegalArgument("The RSA private key must be at least 4096 bits.")
	ErrBearer           = unauthorized("Bearer token expired or is not correct.")
	ErrUUIDInvalid      = illegalArgument("Invalid Profile UUID.")
	// ErrTokenMissing is the session join refusal when no valid game
	// credential exists for the profile owner (legacy token.missing).
	ErrTokenMissing = forbidden("No valid credential information.")
	// ErrPlayerNotMatchedForbidden is the join selected-profile mismatch:
	// same player.not-matched text as refresh, but legacy join throws
	// ForbiddenOperationException (403) where refresh throws 400.
	ErrPlayerNotMatchedForbidden = forbidden("The player requested doesn't match with that token.")
	// ErrPlayerNotFound404 is the upload/reset profile absence (legacy
	// NotFoundException, player.not-existed at 404); refresh keeps the
	// 400 IllegalArgumentException form above.
	ErrPlayerNotFound404 = notFound("Player is not found.")
)

// AuthNotExistedError renders the legacy auth.not-existed message for the
// current identification input (legacy trans('...auth.not-existed',
// compact('identification'))). It is constructed per call so the message
// carries the submitted username/email rather than a format placeholder.
func AuthNotExistedError(identification string) *APIError {
	return forbidden("User " + identification + " is not found.")
}

// ErrModuleNotServed marks a business transaction that observed the
// Yggdrasil module unregistered or disabled under its shared state lock.
// The HTTP layer maps it to the module-absent 404.
var ErrModuleNotServed = errors.New("yggdrasil: module not served")

// UUIDInvalidError renders the legacy uuid exception for one profile id.
func UUIDInvalidError(profile string) *APIError {
	return forbidden("Invalid Profile UUID " + profile + ". It doesn't belong to any players.")
}

// QueryMaxError renders player.query-max with the configured limit text.
func QueryMaxError(limit string) *APIError {
	return forbidden("You can query up to " + limit + " players in one request.")
}

// ThrottleError is the signed-in rate-limit refusal.
func ThrottleError(seconds int64) *APIError {
	return forbidden(fmt.Sprintf("%s", throttleMessage(seconds)))
}

func throttleMessage(seconds int64) string {
	return "Too frequent requests. Please try after " + intToString(seconds) + " seconds."
}

func intToString(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	buf := []byte{}
	for v > 0 {
		buf = append([]byte{byte('0' + v%10)}, buf...)
		v /= 10
	}
	if neg {
		return "-" + string(buf)
	}
	return string(buf)
}
