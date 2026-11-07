package yggdrasil

import "github.com/google/uuid"

// Profile is one available player role as seen by the protocol.
type Profile struct {
	ID   string `json:"id"` // dashed UUID, never a bare account id
	Name string `json:"name"`
}

// User is the optional user block of authenticate/refresh responses.
type User struct {
	ID         string `json:"id"`
	Properties []any  `json:"properties"`
}

// SelectedProfileInput is the client's refresh selection: an object with
// id and name. Only id drives the binding check; name drives the
// existence check, exactly like the legacy flow.
type SelectedProfileInput struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// phpTruthy mirrors PHP truthiness for the clientToken gate: "" and "0"
// are falsy, everything else is truthy.
func phpTruthy(s string) bool { return s != "" && s != "0" }

// isUUID reports whether s is a dashed or hex UUID.
func isUUID(s string) bool {
	if _, err := uuid.Parse(s); err == nil {
		return true
	}
	return false
}

// MustDashed normalizes a hex or dashed UUID to dashed form.
func MustDashed(s string) string {
	if d, ok := hexToDashed(s); ok {
		return d
	}
	if parsed, err := uuid.Parse(s); err == nil {
		return parsed.String()
	}
	return s
}

// UserUUID returns the protocol user.id for an email (UUIDv5, DNS).
func UserUUID(email string) string { return userUUIDv5(email) }
