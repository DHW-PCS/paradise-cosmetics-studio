package passport

import "strings"

// DefaultScopes is the frozen Passport::setDefaultScope(['User.Read']) value.
var DefaultScopes = []string{"User.Read"}

// RegisteredScopes mirrors AuthServiceProvider's default scope map. The
// Closet.ReadWrtie spelling is the legacy value and must not be normalized.
var RegisteredScopes = []string{
	"User.Read",
	"Notification.Read",
	"Notification.ReadWrite",
	"Player.Read",
	"Player.ReadWrite",
	"Closet.Read",
	"Closet.ReadWrtie",
	"UsersManagement.Read",
	"UsersManagement.ReadWrite",
	"PlayersManagement.Read",
	"PlayersManagement.ReadWrite",
	"ClosetManagement.Read",
	"ClosetManagement.ReadWrite",
	"ReportsManagement.Read",
	"ReportsManagement.ReadWrite",
}

// ParseScopes splits a space-delimited scope parameter and drops empties.
func ParseScopes(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Fields(value)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func scopeSet(scopes []string) map[string]bool {
	set := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		set[scope] = true
	}
	return set
}

// ValidateScopes checks every requested scope against the registered list and
// returns the first unknown identifier.
func ValidateScopes(scopes []string) (string, bool) {
	registered := scopeSet(RegisteredScopes)
	for _, scope := range scopes {
		if !registered[scope] {
			return scope, false
		}
	}
	return "", true
}

// IntersectScopes keeps requested order and drops duplicates.
func IntersectScopes(scopes []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope == "" || seen[scope] {
			continue
		}
		seen[scope] = true
		out = append(out, scope)
	}
	return out
}
