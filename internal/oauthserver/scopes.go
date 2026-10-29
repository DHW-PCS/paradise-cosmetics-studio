package oauthserver

import (
	"blessing-skin-go/internal/database"
	"context"
)

// DefaultScopes preserves the frozen Passport identifiers, including its typo.
var DefaultScopes = []string{
	"User.Read", "Notification.Read", "Notification.ReadWrite", "Player.Read", "Player.ReadWrite", "Closet.Read", "Closet.ReadWrtie", "UsersManagement.Read", "UsersManagement.ReadWrite", "PlayersManagement.Read", "PlayersManagement.ReadWrite", "ClosetManagement.Read", "ClosetManagement.ReadWrite", "ReportsManagement.Read", "ReportsManagement.ReadWrite",
}

// LoadScopes preserves the installed site's custom scopes at service startup.
// Scope-management writes and cache refresh are delivered with M3/M4.
func LoadScopes(ctx context.Context, store *database.Store) ([]string, error) {
	scopes := append([]string(nil), DefaultScopes...)
	seen := map[string]bool{}
	for _, scope := range scopes {
		seen[scope] = true
	}
	rows, err := store.DB.QueryContext(ctx, "SELECT name FROM "+store.Table("scopes")+" ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			return nil, err
		}
		if !seen[name] {
			seen[name] = true
			scopes = append(scopes, name)
		}
	}
	return scopes, rows.Err()
}
