package oauthserver

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"blessing-skin-go/internal/identity"
)

// Owner-scoped client management for the frozen Passport endpoints.
//
// The storage/protocol layer never creates, updates or deletes these rows:
// issuance only reads oauth_clients through storage.GetClient, which treats
// a revoked or missing row as not found. Management writes run in one
// transaction, recheck the browser session with CheckBrowserTx and scope
// every lookup by the current user id, so a cross-user id and a missing id
// are indistinguishable (ErrPassportNotFound) and cannot be enumerated.
//
// The legacy table has no created_at/updated_at or app-managed counters on
// this Go schema, so the JSON view only carries the columns the table has.
// Deletion revokes the client row and deactivates every go_oauth_* grant it
// owns in the same transaction; no business data is removed.
var (
	ErrPassportNotFound = errors.New("oauth passport: not found")
	ErrPassportConflict = errors.New("oauth passport: conflict")
)

// ClientRow is the frozen client JSON. Redirect is the comma-separated
// storage string itself, matching the existing frontend string contract.
// Secret hashing is not enabled in the frozen deployment, so the owner
// list returns the stored plaintext secret like the original forUser view.
type ClientRow struct {
	ID                   int64    `json:"id"`
	UserID               int64    `json:"user_id"`
	Name                 string   `json:"name"`
	Secret               string   `json:"secret,omitempty"`
	Redirect             string   `json:"redirect"`
	PersonalAccessClient bool     `json:"personal_access_client"`
	PasswordClient       bool     `json:"password_client"`
	Revoked              bool     `json:"revoked"`
	GrantTypes           []string `json:"grant_types"`
}

// ClientDetail enriches one owned client with the scopes its issuance flow
// may grant today: the pinned snapshot names plus "*".
type ClientDetail struct {
	ClientRow
	Scopes []string `json:"scopes"`
}

var validGrantTypes = map[string]bool{
	"authorization_code": true,
	"client_credentials": true,
	"password":           true,
	"refresh_token":      true,
}

// grantsOf mirrors storage.GetClient: the password flag selects the
// resource-owner flow, a personal row stays client-credentials only and a
// regular user client uses the authorization-code flow.
func grantsOf(password, personal bool) []string {
	if password {
		return []string{"client_credentials", "password", "refresh_token"}
	}
	if personal {
		return []string{"client_credentials"}
	}
	return []string{"client_credentials", "authorization_code", "refresh_token"}
}

func scanClient(row *sql.Row) (ClientRow, error) {
	var out ClientRow
	var secret sql.NullString
	var redirect string
	if err := row.Scan(&out.ID, &out.UserID, &out.Name, &secret, &redirect, &out.PersonalAccessClient, &out.PasswordClient, &out.Revoked); err != nil {
		return ClientRow{}, err
	}
	out.Secret = secret.String
	out.Redirect = redirect
	out.GrantTypes = grantsOf(out.PasswordClient, out.PersonalAccessClient)
	return out, nil
}

func splitRedirects(redirect string) []string {
	if redirect == "" {
		return []string{}
	}
	return strings.Split(redirect, ",")
}

// validateClientInput keeps the frozen Passport rules plus the Go snapshot
// scope contract: the name is required (VARCHAR(255)), every redirect is a
// non-empty absolute http(s) URI without commas (commas are the storage
// separator, so a stored URI can never be read back differently), grant
// types stay inside the protocol set and scopes stay inside snapshot+"*".
// The password grant is never available through user-owned client
// management: frozen store()/update() have no grant input and password
// clients are system rows created by createPasswordGrantClient.
func validateClientInput(name string, redirect, grants, scopes []string, snapshot Snapshot) error {
	if name == "" || len(name) > 255 {
		return fmt.Errorf("%w: name is required and limited to 255 bytes", ErrInvalidInput)
	}
	if len(redirect) == 0 {
		return fmt.Errorf("%w: at least one redirect URI is required", ErrInvalidInput)
	}
	for _, uri := range redirect {
		parsed, err := url.Parse(uri)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || strings.Contains(uri, ",") {
			return fmt.Errorf("%w: redirect must be an absolute http(s) URI", ErrInvalidInput)
		}
	}
	for _, grant := range grants {
		if !validGrantTypes[grant] {
			return fmt.Errorf("%w: unsupported grant type", ErrInvalidInput)
		}
		if grant == "password" {
			return fmt.Errorf("%w: the password grant is reserved for system clients", ErrInvalidInput)
		}
	}
	for _, scope := range scopes {
		if scope == "*" {
			continue
		}
		found := false
		for _, registered := range snapshot.Names {
			if registered == scope {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: scope is outside the current snapshot", ErrInvalidInput)
		}
	}
	return nil
}

// withBrowser runs one management operation in a single transaction with
// the browser credential rechecked inside. The read lease pins one scope
// snapshot for validation only; management never publishes scope facts.
func (s *Server) withBrowser(ctx context.Context, b *identity.BrowserSession, f func(context.Context, *sql.Tx, *identity.User, Snapshot) error) error {
	lease, err := s.policy.AcquireRead(ctx)
	if err != nil {
		return err
	}
	defer lease.Release()
	tx, err := s.cfg.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	u, err := s.cfg.Identity.CheckBrowserTx(ctx, tx, b)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if err = f(ctx, tx, u, lease.Snapshot()); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func clientSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// CreateClient inserts one user-owned regular client. The id comes from the
// database (the legacy table is not AUTO_INCREMENT on the Go schema, so the
// next id is allocated by one atomic INSERT..SELECT; a lost race surfaces
// as ErrPassportConflict). The returned row carries the plaintext secret,
// which storage.GetClient later compares as a plaintext client secret. A
// user-owned client never becomes a password client: the password grant is
// rejected by validateClientInput and the inserted row always has
// password_client=0, so no ordinary caller can mint a credential collector.
func (s *Server) CreateClient(ctx context.Context, b *identity.BrowserSession, name string, redirect string, grants, scopes []string) (ClientRow, error) {
	secret, err := clientSecret()
	if err != nil {
		return ClientRow{}, err
	}
	var created ClientRow
	err = s.withBrowser(ctx, b, func(ctx context.Context, tx *sql.Tx, u *identity.User, snapshot Snapshot) error {
		if err := validateClientInput(name, splitRedirects(redirect), grants, scopes, snapshot); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO "+s.cfg.Store.Table("oauth_clients")+" (id,user_id,name,secret,redirect,password_client) SELECT COALESCE(MAX(id),0)+1,?,?,?,?,0 FROM "+s.cfg.Store.Table("oauth_clients"), u.UID, name, secret, redirect); err != nil {
			if isUniqueViolation(err) {
				return ErrPassportConflict
			}
			return err
		}
		// INSERT..SELECT reports no LastInsertId; the random secret
		// identifies the row we just inserted.
		var id int64
		if err := tx.QueryRowContext(ctx, "SELECT id FROM "+s.cfg.Store.Table("oauth_clients")+" WHERE user_id=? AND secret=?", u.UID, secret).Scan(&id); err != nil {
			return err
		}
		created = ClientRow{ID: id, UserID: u.UID, Name: name, Secret: secret, Redirect: redirect, GrantTypes: grantsOf(false, false)}
		return nil
	})
	return created, err
}

// ListClients returns the current user's non-personal, non-revoked clients
// in id order. Password and personal rows are owned system rows (user_id
// NULL) and never appear here. Secret hashing is not enabled in the frozen
// deployment, so the owner list carries the stored plaintext secret, as the
// original forUser view did; no new hashing mode is introduced.
func (s *Server) ListClients(ctx context.Context, b *identity.BrowserSession) ([]ClientRow, error) {
	out := []ClientRow{}
	err := s.withBrowser(ctx, b, func(ctx context.Context, tx *sql.Tx, u *identity.User, _ Snapshot) error {
		rows, err := tx.QueryContext(ctx, "SELECT id,user_id,name,secret,redirect,personal_access_client,password_client,revoked FROM "+s.cfg.Store.Table("oauth_clients")+" WHERE user_id=? AND personal_access_client=0 AND revoked=0 ORDER BY id", u.UID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row ClientRow
			var secret sql.NullString
			var redirect string
			if err := rows.Scan(&row.ID, &row.UserID, &row.Name, &secret, &redirect, &row.PersonalAccessClient, &row.PasswordClient, &row.Revoked); err != nil {
				return err
			}
			row.Secret = secret.String
			row.Redirect = redirect
			row.GrantTypes = grantsOf(row.PasswordClient, row.PersonalAccessClient)
			out = append(out, row)
		}
		return rows.Err()
	})
	return out, err
}

// ownedClient locks one owner-scoped client row inside the management
// transaction, reporting any missing or foreign id as ErrPassportNotFound.
func (s *Server) ownedClient(ctx context.Context, tx *sql.Tx, uid int64, id int64) (ClientRow, error) {
	row := tx.QueryRowContext(ctx, "SELECT id,user_id,name,secret,redirect,personal_access_client,password_client,revoked FROM "+s.cfg.Store.Table("oauth_clients")+" WHERE id=? AND user_id=? FOR UPDATE", id, uid)
	client, err := scanClient(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ClientRow{}, ErrPassportNotFound
	}
	return client, err
}

// withOwnedClient locks the owner-scoped client before CheckBrowserTx's
// users/version/session locks, matching the OAuth Actor lock order. The
// callback reuses that row; ownership discovery never authorizes the browser.
func (s *Server) withOwnedClient(ctx context.Context, b *identity.BrowserSession, id int64, f func(context.Context, *sql.Tx, *identity.User, ClientRow, Snapshot) error) error {
	if b == nil || b.User == nil {
		return identity.ErrSession
	}
	lease, err := s.policy.AcquireRead(ctx)
	if err != nil {
		return err
	}
	defer lease.Release()
	tx, err := s.cfg.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	client, err := s.ownedClient(ctx, tx, b.User.UID, id)
	if err != nil {
		return err
	}
	u, err := s.cfg.Identity.CheckBrowserTx(ctx, tx, b)
	if err != nil {
		return err
	}
	if err = f(ctx, tx, u, client, lease.Snapshot()); err != nil {
		return err
	}
	return tx.Commit()
}

// GetClientDetail returns one owned client plus its currently grantable
// scopes (the pinned snapshot names and "*").
func (s *Server) GetClientDetail(ctx context.Context, b *identity.BrowserSession, id int64) (ClientDetail, error) {
	var detail ClientDetail
	err := s.withOwnedClient(ctx, b, id, func(_ context.Context, _ *sql.Tx, _ *identity.User, client ClientRow, snapshot Snapshot) error {
		client.Secret = ""
		scopes := append([]string(nil), snapshot.Names...)
		hasWildcard := false
		for _, name := range scopes {
			if name == "*" {
				hasWildcard = true
			}
		}
		if !hasWildcard {
			scopes = append(scopes, "*")
		}
		detail = ClientDetail{ClientRow: client, Scopes: scopes}
		return nil
	})
	return detail, err
}

// UpdateClient rewrites only the owned client's name and redirect — exactly
// the fields the frozen ClientController@update / ClientRepository::update
// touch. The password and personal flags never change: renaming a
// system-issued password client keeps its grants, and a plain client cannot
// gain the password grant (validateClientInput rejects it). The response
// carries the full stored row (personal_access_client, password_client,
// revoked) like the frozen model, with the secret hidden the way the frozen
// update view hides it.
func (s *Server) UpdateClient(ctx context.Context, b *identity.BrowserSession, id int64, name string, redirect string, grants, scopes []string) (ClientRow, error) {
	var updated ClientRow
	err := s.withOwnedClient(ctx, b, id, func(ctx context.Context, tx *sql.Tx, u *identity.User, client ClientRow, snapshot Snapshot) error {
		if err := validateClientInput(name, splitRedirects(redirect), grants, scopes, snapshot); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE "+s.cfg.Store.Table("oauth_clients")+" SET name=?,redirect=? WHERE id=? AND user_id=?", name, redirect, client.ID, u.UID); err != nil {
			return err
		}
		updated = client
		updated.Name = name
		updated.Redirect = redirect
		updated.Secret = ""
		updated.GrantTypes = grantsOf(client.PasswordClient, client.PersonalAccessClient)
		return nil
	})
	return updated, err
}

// DeleteClient revokes the owned client and deactivates every go_oauth_*
// grant row it issued in the same transaction. The client row itself stays
// (revoked=1) so history is preserved; no business data is touched. The
// operation is idempotent for an already-revoked owned client.
func (s *Server) DeleteClient(ctx context.Context, b *identity.BrowserSession, id int64) error {
	return s.withOwnedClient(ctx, b, id, func(ctx context.Context, tx *sql.Tx, _ *identity.User, client ClientRow, _ Snapshot) error {
		if client.Revoked {
			return nil
		}
		if _, err := tx.ExecContext(ctx, "UPDATE "+s.cfg.Store.Table("oauth_clients")+" SET revoked=1 WHERE id=?", client.ID); err != nil {
			return err
		}
		clientID := fmt.Sprintf("%d", client.ID)
		for _, table := range []string{"go_oauth_codes", "go_oauth_access", "go_oauth_refresh", "go_oauth_pkce"} {
			if _, err := tx.ExecContext(ctx, "UPDATE "+s.cfg.Store.Table(table)+" SET active=0 WHERE client_id=?", clientID); err != nil {
				return err
			}
		}
		return nil
	})
}
