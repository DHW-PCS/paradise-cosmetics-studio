package oauthserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"blessing-skin-go/internal/identity"
)

// Scopes, personal access tokens and access tokens for the frozen Passport
// management endpoints. All reads and writes authenticate the browser
// session in one transaction and scope every lookup by the current user id,
// so there is no cross-user status channel: a foreign id and a missing id
// share ErrPassportNotFound.
//
// There is no separate personal-token table on this schema: a personal
// token is a go_oauth_access row issued for the personal_access_client
// client with the token name kept in the payload session label (see
// IssuePersonalToken). Lists read that row shape directly; revocation flips
// the access row and the refresh row sharing its request id to inactive,
// which the engine later reads as a dead token.
// ScopeDescription is the frozen Passport /oauth/scopes shape
// (Scope::toArray): id, not name. This is a different contract from the
// /admin/oauth/scopes maintenance rows, which keep their name field.
type ScopeDescription struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

// ScopesList merges the default names with the custom table the way the
// original scope merge did: default names first, custom rows in id order,
// and a custom row on a default name only overrides the description. A
// default without a custom row carries its frozen AuthServiceProvider
// translation key (defaultScopeKeys); a custom row carries its stored
// description verbatim. The table is read live so a published scope shows
// without a restart.
func (s *Server) ScopesList(ctx context.Context, b *identity.BrowserSession) ([]ScopeDescription, error) {
	out := []ScopeDescription{}
	err := s.withBrowser(ctx, b, func(ctx context.Context, tx *sql.Tx, _ *identity.User, _ Snapshot) error {
		rows, err := tx.QueryContext(ctx, "SELECT name,description FROM "+s.cfg.Store.Table("scopes")+" ORDER BY id")
		if err != nil {
			return err
		}
		defer rows.Close()
		custom := map[string]string{}
		var extra []string
		seen := map[string]bool{}
		for _, name := range DefaultScopes {
			seen[name] = true
		}
		for rows.Next() {
			var name, description string
			if err := rows.Scan(&name, &description); err != nil {
				return err
			}
			custom[name] = description
			if !seen[name] {
				seen[name] = true
				extra = append(extra, name)
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, name := range append(append([]string(nil), DefaultScopes...), extra...) {
			description, ok := custom[name]
			if !ok {
				description = defaultScopeKeys[name]
			}
			out = append(out, ScopeDescription{ID: name, Description: description})
		}
		return nil
	})
	return out, err
}

// PersonalTokenRow describes one issued personal token row. ID is the
// stored grant (request) id, the same identifier the revoke endpoints take.
type PersonalTokenRow struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IssuedPersonalToken is the creation response: the plain access token
// plus the stored row the user revoked later.
type IssuedPersonalToken struct {
	AccessToken string           `json:"accessToken"`
	Token       PersonalTokenRow `json:"token"`
}

// CreatePersonalToken delegates issuance to the existing IssuePersonalToken
// service (single snapshot, single transaction, personal client lookup) and
// only adds the management contract: the name must be present and bounded
// by the legacy varchar width, and scope failures stay ErrScope.
func (s *Server) CreatePersonalToken(ctx context.Context, b *identity.BrowserSession, name string, scopes []string) (IssuedPersonalToken, error) {
	if name == "" || len(name) > 255 {
		return IssuedPersonalToken{}, fmt.Errorf("%w: personal token name is required and limited to 255 bytes", ErrInvalidInput)
	}
	issued, err := s.IssuePersonalToken(ctx, b, name, scopes)
	if err != nil {
		return IssuedPersonalToken{}, err
	}
	return IssuedPersonalToken{AccessToken: issued.AccessToken, Token: PersonalTokenRow{ID: issued.ID, Name: name, Scopes: append([]string(nil), scopes...), ExpiresAt: issued.ExpiresAt}}, nil
}

// personalClients returns the stored personal access client ids. A revoked
// personal client keeps its issued rows revocable, so only the active list
// filters on revoked.
func (s *Server) personalClients(ctx context.Context, tx *sql.Tx, activeOnly bool) ([]string, error) {
	query := "SELECT CAST(id AS CHAR) FROM " + s.cfg.Store.Table("oauth_clients") + " WHERE personal_access_client=1"
	if activeOnly {
		query += " AND revoked=0"
	}
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func parseGrantPayload(body []byte) (record, error) {
	var out record
	if err := json.Unmarshal(body, &out); err != nil {
		return record{}, err
	}
	return out, nil
}

// ListPersonalTokens returns the current user's active personal token rows,
// newest expiry first, with the name read back from the payload label.
func (s *Server) ListPersonalTokens(ctx context.Context, b *identity.BrowserSession) ([]PersonalTokenRow, error) {
	out := []PersonalTokenRow{}
	err := s.withBrowser(ctx, b, func(ctx context.Context, tx *sql.Tx, u *identity.User, _ Snapshot) error {
		clients, err := s.personalClients(ctx, tx, true)
		if err != nil {
			return err
		}
		if len(clients) == 0 {
			return nil
		}
		rows, err := tx.QueryContext(ctx, "SELECT request_id,payload,expires_at FROM "+s.cfg.Store.Table("go_oauth_access")+" WHERE user_uid=? AND active=1 AND client_id IN ("+placeholders(len(clients))+") ORDER BY expires_at DESC", append([]any{u.UID}, stringsToAny(clients)...)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, payload string
			var expires int64
			if err := rows.Scan(&id, &payload, &expires); err != nil {
				return err
			}
			grant, err := parseGrantPayload([]byte(payload))
			if err != nil {
				return err
			}
			row := PersonalTokenRow{ID: id, Scopes: append([]string(nil), grant.GrantedScopes...), ExpiresAt: time.Unix(expires, 0).UTC()}
			if grant.Session != nil {
				row.Name = grant.Session.Label
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	return out, err
}

// RevokePersonalToken deactivates one owned personal grant (its access row
// and the refresh rows sharing the request id). Unknown or foreign ids are
// ErrPassportNotFound; revoking an already inactive owned grant succeeds.
func (s *Server) RevokePersonalToken(ctx context.Context, b *identity.BrowserSession, id string) error {
	return s.revokeGrant(ctx, b, id, true)
}

// TokenRow describes one active access token of the current user.
type TokenRow struct {
	ID         string    `json:"id"`
	ClientID   string    `json:"client_id"`
	ClientName string    `json:"client_name"`
	Scopes     []string  `json:"scopes"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// ListTokens returns the current user's active access tokens for
// non-first-party clients, newest expiry first. The frozen
// AuthorizedAccessTokenController@forUser filters out first-party clients
// (personal access and password grant rows); those are managed through the
// separate personal-access-token endpoints.
func (s *Server) ListTokens(ctx context.Context, b *identity.BrowserSession) ([]TokenRow, error) {
	out := []TokenRow{}
	err := s.withBrowser(ctx, b, func(ctx context.Context, tx *sql.Tx, u *identity.User, _ Snapshot) error {
		rows, err := tx.QueryContext(ctx, "SELECT a.request_id,CAST(c.id AS CHAR),c.name,a.payload,a.expires_at FROM "+s.cfg.Store.Table("go_oauth_access")+" a JOIN "+s.cfg.Store.Table("oauth_clients")+" c ON c.id=a.client_id WHERE a.user_uid=? AND a.active=1 AND c.personal_access_client=0 AND c.password_client=0 ORDER BY a.expires_at DESC", u.UID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, clientID, clientName, payload string
			var expires int64
			if err := rows.Scan(&id, &clientID, &clientName, &payload, &expires); err != nil {
				return err
			}
			grant, err := parseGrantPayload([]byte(payload))
			if err != nil {
				return err
			}
			out = append(out, TokenRow{ID: id, ClientID: clientID, ClientName: clientName, Scopes: append([]string(nil), grant.GrantedScopes...), ExpiresAt: time.Unix(expires, 0).UTC()})
		}
		return rows.Err()
	})
	return out, err
}

// RevokeToken deactivates exactly one owned grant: the access row and its
// refresh rows share the request id, so the whole grant dies and nothing
// else does. Already inactive owned grants succeed (204 on repeat).
func (s *Server) RevokeToken(ctx context.Context, b *identity.BrowserSession, id string) error {
	return s.revokeGrant(ctx, b, id, false)
}

func (s *Server) revokeGrant(ctx context.Context, b *identity.BrowserSession, id string, personalOnly bool) error {
	if id == "" {
		return ErrPassportNotFound
	}
	return s.withBrowser(ctx, b, func(ctx context.Context, tx *sql.Tx, u *identity.User, _ Snapshot) error {
		query := "SELECT 1 FROM " + s.cfg.Store.Table("go_oauth_access") + " WHERE request_id=? AND user_uid=?"
		args := []any{id, u.UID}
		if personalOnly {
			clients, err := s.personalClients(ctx, tx, false)
			if err != nil {
				return err
			}
			if len(clients) == 0 {
				return ErrPassportNotFound
			}
			query += " AND client_id IN (" + placeholders(len(clients)) + ")"
			args = append(args, stringsToAny(clients)...)
		}
		query += " LIMIT 1"
		var owned int
		if err := tx.QueryRowContext(ctx, query, args...).Scan(&owned); errors.Is(err, sql.ErrNoRows) {
			return ErrPassportNotFound
		} else if err != nil {
			return err
		}
		// Rotation retains inactive rows, so one row cannot establish that
		// the entire grant is inactive. Revoke all remaining active rows.
		for _, table := range []string{"go_oauth_access", "go_oauth_refresh"} {
			if _, err := tx.ExecContext(ctx, "UPDATE "+s.cfg.Store.Table(table)+" SET active=0 WHERE request_id=? AND active=1", id); err != nil {
				return err
			}
		}
		return nil
	})
}

func placeholders(n int) string {
	return strings.Join(marks(n), ",")
}

func marks(n int) []string {
	marks := make([]string, n)
	for i := range marks {
		marks[i] = "?"
	}
	return marks
}

func stringsToAny(values []string) []any {
	out := make([]any, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}
