// M4-03 slice B: pending-consent storage (one slot per session, single
// consumption) and the /user/oauth/manage authorization data.
package oauthserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
)

var (
	ErrConsent      = errors.New("oauth: consent request unavailable")
	ErrConsentStale = errors.New("oauth: consent display changed; request the authorization page again")
)

// MigrateConsents installs the pending-consent table. There is no
// expires_at: pending validity follows the bound browser session, never a
// fixed wait deadline. Wired by the composition root; slice-B tests call
// it directly.
func MigrateConsents(ctx context.Context, store *database.Store) error {
	ddl := "CREATE TABLE IF NOT EXISTS " + store.Table("go_oauth_consents") + ` (auth_digest BINARY(32) PRIMARY KEY,session_digest BINARY(32) NOT NULL UNIQUE,user_uid BIGINT NOT NULL,version BIGINT NOT NULL,client_id VARCHAR(100) NOT NULL,redirect_uri TEXT NOT NULL,scope TEXT NOT NULL,state TEXT NOT NULL,code_challenge TEXT NULL,code_challenge_method VARCHAR(20) NULL,scopes_display LONGTEXT NOT NULL,client_display LONGTEXT NOT NULL,issued_at BIGINT NOT NULL,INDEX consent_client(client_id),INDEX consent_user(user_uid)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
	return store.ApplyMigration(ctx, "005_go_oauth_consents", ddl)
}

// ScopeDisplay is one displayed scope: the exact requested name and the
// description the user approved.
type ScopeDisplay struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ConsentView is the authorization-page data bound to one pending request.
type ConsentView struct {
	AuthToken   string         `json:"auth_token"`
	ClientID    string         `json:"client_id"`
	ClientName  string         `json:"client_name"`
	RedirectURI string         `json:"redirect_uri"`
	Scopes      []ScopeDisplay `json:"scopes"`
	State       string         `json:"state"`
}

// defaultScopeKeys mirrors the frozen AuthServiceProvider default
// descriptions (translation keys); custom rows override them.
var defaultScopeKeys = map[string]string{
	"User.Read":                   "auth.oauth.scope.user.read",
	"Notification.Read":           "auth.oauth.scope.notification.read",
	"Notification.ReadWrite":      "auth.oauth.scope.notification.readwrite",
	"Player.Read":                 "auth.oauth.scope.player.read",
	"Player.ReadWrite":            "auth.oauth.scope.player.readwrite",
	"Closet.Read":                 "auth.oauth.scope.closet.read",
	"Closet.ReadWrtie":            "auth.oauth.scope.closet.readwrite",
	"UsersManagement.Read":        "auth.oauth.scope.users-management.read",
	"UsersManagement.ReadWrite":   "auth.oauth.scope.users-management.readwrite",
	"PlayersManagement.Read":      "auth.oauth.scope.players-management.read",
	"PlayersManagement.ReadWrite": "auth.oauth.scope.players-management.readwrite",
	"ClosetManagement.Read":       "auth.oauth.scope.closet-management.read",
	"ClosetManagement.ReadWrite":  "auth.oauth.scope.closet-management.readwrite",
	"ReportsManagement.Read":      "auth.oauth.scope.reports-management.read",
	"ReportsManagement.ReadWrite": "auth.oauth.scope.reports-management.readwrite",
}

type consentRow struct {
	authDigest        []byte
	sessionDigest     []byte
	userUID           int64
	version           int64
	clientID          string
	redirectURI       string
	scopeText         string
	state             string
	codeChallenge     sql.NullString
	codeChallengeMeth sql.NullString
	scopesDisplay     string
	clientDisplay     string
	issuedAt          int64
}

// scopeDisplays renders the description the authorization page shows for
// each requested scope from the pinned snapshot.
func (s *Server) scopeDisplays(ctx context.Context, tx *sql.Tx, snapshot Snapshot, requested []string) ([]ScopeDisplay, error) {
	overrides := map[string]string{}
	rows, err := tx.QueryContext(ctx, "SELECT name,description FROM "+s.cfg.Store.Table("scopes"))
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var name, description string
		if err = rows.Scan(&name, &description); err != nil {
			rows.Close()
			return nil, err
		}
		if _, ok := overrides[name]; !ok {
			overrides[name] = description
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	out := make([]ScopeDisplay, 0, len(requested))
	for _, name := range requested {
		description, ok := overrides[name]
		if !ok {
			description = defaultScopeKeys[name]
		}
		if description == "" {
			description = name
		}
		out = append(out, ScopeDisplay{Name: name, Description: description})
	}
	return out, nil
}

// ConsentShow validates the authorize request and stages (or replaces)
// the caller's single pending slot. When the user already holds a valid
// grant for exactly these scopes, it issues the code directly and returns
// a view with no AuthToken (the caller redirects instead).
func (s *Server) ConsentShow(ctx context.Context, r *http.Request, browser *identity.BrowserSession) (*ConsentView, error) {
	if browser == nil || browser.User == nil {
		return nil, identity.ErrSession
	}
	_ = r.ParseForm()
	if r.Form.Get("scope") == "" {
		r.Form.Set("scope", "User.Read")
	}
	var view *ConsentView
	var directRedirect string
	lease, err := s.policy.AcquireRead(ctx)
	if err != nil {
		return nil, err
	}
	err = s.storage.runLeased(ctx, s.cfg.Store.DB, lease, func(ctx context.Context) error {
		request, err := s.provider.NewAuthorizeRequest(ctx, r)
		if err != nil {
			return err
		}
		user, err := s.cfg.Identity.CheckBrowserTx(ctx, root(ctx).tx, browser)
		if err != nil {
			return err
		}
		for _, scope := range request.GetRequestedScopes() {
			if scope != "*" {
				request.GrantScope(scope)
			}
		}
		// Auto-approve when the same user/client already holds a valid
		// grant for exactly the requested scopes (frozen Passport rule).
		if scopes := request.GetRequestedScopes(); len(scopes) > 0 {
			if ok := s.exactGrant(ctx, root(ctx).tx, user.UID, request.GetClient().GetID(), scopes); ok {
				response, err := s.provider.NewAuthorizeResponse(ctx, request, newSession(user.UID, browser.Version))
				if err != nil {
					return err
				}
				code := response.GetCode()
				if code == "" {
					return ErrConsent
				}
				redirectURI := request.GetRedirectURI()
				if redirectURI == nil {
					return ErrConsent
				}
				q := redirectURI.Query()
				q.Set("code", code)
				if state := request.GetState(); state != "" {
					q.Set("state", state)
				}
				target := *redirectURI
				target.RawQuery = q.Encode()
				directRedirect = target.String()
				return nil
			}
		}
		var clientName string
		tx := root(ctx).tx
		if err = tx.QueryRowContext(ctx, "SELECT name FROM "+s.cfg.Store.Table("oauth_clients")+" WHERE id=?", request.GetClient().GetID()).Scan(&clientName); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrConsent
			}
			return err
		}
		displays, err := s.scopeDisplays(ctx, tx, lease.Snapshot(), request.GetRequestedScopes())
		if err != nil {
			return err
		}
		authToken := identity.Token()
		displaysJSON, err := json.Marshal(displays)
		if err != nil {
			return err
		}
		clientJSON, err := json.Marshal(map[string]string{"name": clientName, "id": request.GetClient().GetID()})
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO "+s.cfg.Store.Table("go_oauth_consents")+" (auth_digest,session_digest,user_uid,version,client_id,redirect_uri,scope,state,code_challenge,code_challenge_method,scopes_display,client_display,issued_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE auth_digest=VALUES(auth_digest),user_uid=VALUES(user_uid),version=VALUES(version),client_id=VALUES(client_id),redirect_uri=VALUES(redirect_uri),scope=VALUES(scope),state=VALUES(state),code_challenge=VALUES(code_challenge),code_challenge_method=VALUES(code_challenge_method),scopes_display=VALUES(scopes_display),client_display=VALUES(client_display),issued_at=VALUES(issued_at)",
			identity.Digest(authToken), identity.Digest(browser.Token), user.UID, browser.Version, request.GetClient().GetID(), request.GetRedirectURI().String(),
			strings.Join(request.GetRequestedScopes(), " "), request.GetState(),
			nullableString(request.GetRequestForm().Get("code_challenge")), nullableString(request.GetRequestForm().Get("code_challenge_method")),
			string(displaysJSON), string(clientJSON), unixNow())
		if err != nil {
			return err
		}
		view = &ConsentView{
			AuthToken:   authToken,
			ClientID:    request.GetClient().GetID(),
			ClientName:  clientName,
			RedirectURI: request.GetRedirectURI().String(),
			Scopes:      displays,
			State:       request.GetState(),
		}
		return nil
	})
	if err != nil {
		if directRedirect != "" {
			return nil, err
		}
		return nil, err
	}
	if directRedirect != "" {
		return &ConsentView{ClientID: "", RedirectURI: directRedirect}, nil
	}
	return view, nil
}

// exactGrant reports whether an active, unexpired access grant for exactly
// these scopes exists for the user/client pair.
func (s *Server) exactGrant(ctx context.Context, tx *sql.Tx, uid int64, clientID string, scopes []string) bool {
	rows, err := tx.QueryContext(ctx, "SELECT payload FROM "+s.cfg.Store.Table("go_oauth_access")+" WHERE client_id=? AND user_uid=? AND active=1 AND expires_at>? ORDER BY expires_at DESC", clientID, uid, unixNow())
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var body []byte
		if err = rows.Scan(&body); err != nil {
			return false
		}
		var data record
		if err = json.Unmarshal(body, &data); err != nil {
			return false
		}
		if equalStringSets(data.GrantedScopes, scopes) {
			return true
		}
	}
	return false
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, v := range a {
		set[v] = true
	}
	for _, v := range b {
		if !set[v] {
			return false
		}
	}
	return true
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// consumeConsent verifies the pending binding and deletes the row in the
// caller's transaction (single consumption). It returns the stored row
// plus the currently rebuilt displays for drift comparison.
func (s *Server) consumeConsent(ctx context.Context, tx *sql.Tx, browser *identity.BrowserSession, authToken string) (*consentRow, error) {
	var row consentRow
	err := tx.QueryRowContext(ctx, "SELECT auth_digest,session_digest,user_uid,version,client_id,redirect_uri,scope,state,code_challenge,code_challenge_method,scopes_display,client_display,issued_at FROM "+s.cfg.Store.Table("go_oauth_consents")+" WHERE auth_digest=? FOR UPDATE", identity.Digest(authToken)).Scan(&row.authDigest, &row.sessionDigest, &row.userUID, &row.version, &row.clientID, &row.redirectURI, &row.scopeText, &row.state, &row.codeChallenge, &row.codeChallengeMeth, &row.scopesDisplay, &row.clientDisplay, &row.issuedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrConsent
	}
	if err != nil {
		return nil, err
	}
	if !equalBytes(row.sessionDigest, identity.Digest(browser.Token)) {
		return nil, ErrConsent
	}
	return &row, nil
}

// ConsentApprove consumes the pending request and issues the code;
// the caller redirects to the returned URI.
func (s *Server) ConsentApprove(ctx context.Context, browser *identity.BrowserSession, authToken string) (string, error) {
	if browser == nil || browser.User == nil || authToken == "" {
		return "", ErrConsent
	}
	redirect, err := s.consentDecision(ctx, browser, authToken, true)
	if err != nil {
		return "", err
	}
	return redirect, nil
}

// ConsentDeny consumes the pending request and redirects back with
// error=access_denied, preserving state.
func (s *Server) ConsentDeny(ctx context.Context, browser *identity.BrowserSession, authToken string) (string, error) {
	if browser == nil || browser.User == nil || authToken == "" {
		return "", ErrConsent
	}
	redirect, err := s.consentDecision(ctx, browser, authToken, false)
	if err != nil {
		return "", err
	}
	return redirect, nil
}

func (s *Server) consentDecision(ctx context.Context, browser *identity.BrowserSession, authToken string, approve bool) (string, error) {
	redirect := ""
	lease, err := s.policy.AcquireRead(ctx)
	if err != nil {
		return "", err
	}
	err = s.storage.runLeased(ctx, s.cfg.Store.DB, lease, func(ctx context.Context) error {
		tx := root(ctx).tx
		// Discovery plan only: the client row must be locked before the
		// user rows (PrepareTx order). The pending lock below rechecks
		// that this plan still holds; a replaced pending rolls back.
		var discoveredClient string
		err := tx.QueryRowContext(ctx, "SELECT client_id FROM "+s.cfg.Store.Table("go_oauth_consents")+" WHERE auth_digest=?", identity.Digest(authToken)).Scan(&discoveredClient)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrConsent
		}
		if err != nil {
			return err
		}
		if _, err = s.storage.GetClient(ctx, discoveredClient); err != nil {
			return err
		}
		user, err := s.cfg.Identity.CheckBrowserTx(ctx, tx, browser)
		if err != nil {
			return err
		}
		row, err := s.consumeConsent(ctx, tx, browser, authToken)
		if err != nil {
			return err
		}
		if row.clientID != discoveredClient || row.userUID != user.UID || row.version != browser.Version {
			return ErrConsent
		}
		// Current client, redirect, scopes, and displayed content must
		// still match what the user saw; otherwise the user must see
		// the authorization page again (no silent approval drift).
		var allowScopes []string
		if row.scopeText != "" {
			allowScopes = strings.Fields(row.scopeText)
		}
		displays, err := s.scopeDisplays(ctx, tx, lease.Snapshot(), allowScopes)
		if err != nil {
			return err
		}
		displaysJSON, err := json.Marshal(displays)
		if err != nil {
			return err
		}
		if string(displaysJSON) != row.scopesDisplay {
			return ErrConsentStale
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM "+s.cfg.Store.Table("go_oauth_consents")+" WHERE auth_digest=? AND session_digest=?", identity.Digest(authToken), identity.Digest(browser.Token)); err != nil {
			return err
		}
		redirectURI, _ := url.Parse(row.redirectURI)
		if !approve {
			q := redirectURI.Query()
			q.Set("error", "access_denied")
			if row.state != "" {
				q.Set("state", row.state)
			}
			redirectURI.RawQuery = q.Encode()
			redirect = redirectURI.String()
			return nil
		}
		// Rebuild the authorize request from the stored pending fields so
		// approve cannot be steered to a different redirect or scope set.
		synthesized := consentRequestURI(row)
		authorizeReq, err := httptestRequest(synthesized)
		if err != nil {
			return err
		}
		request, err := s.provider.NewAuthorizeRequest(ctx, authorizeReq)
		if err != nil {
			return err
		}
		for _, scope := range request.GetRequestedScopes() {
			if scope != "*" {
				request.GrantScope(scope)
			}
		}
		response, err := s.provider.NewAuthorizeResponse(ctx, request, newSession(user.UID, browser.Version))
		if err != nil {
			return err
		}
		code := response.GetCode()
		if code == "" {
			return ErrConsent
		}
		q := redirectURI.Query()
		q.Set("code", code)
		if row.state != "" {
			q.Set("state", row.state)
		}
		redirectURI.RawQuery = q.Encode()
		redirect = redirectURI.String()
		return nil
	})
	if err != nil {
		return "", err
	}
	return redirect, nil
}

func consentRequestURI(row *consentRow) string {
	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", row.clientID)
	query.Set("redirect_uri", row.redirectURI)
	if row.scopeText != "" {
		query.Set("scope", row.scopeText)
	}
	if row.state != "" {
		query.Set("state", row.state)
	}
	if row.codeChallenge.Valid && row.codeChallenge.String != "" {
		query.Set("code_challenge", row.codeChallenge.String)
		if row.codeChallengeMeth.Valid && row.codeChallengeMeth.String != "" {
			query.Set("code_challenge_method", row.codeChallengeMeth.String)
		}
	}
	return "https://skin.example.invalid/oauth/authorize?" + query.Encode()
}

func httptestRequest(target string) (*http.Request, error) {
	return http.NewRequest("GET", target, nil)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// AuthorizationView is one currently granted client/scope pair for the
// manage page.
type AuthorizationView struct {
	ClientID   string   `json:"client_id"`
	ClientName string   `json:"client_name"`
	Scopes     []string `json:"scopes"`
	ExpiresAt  int64    `json:"expires_at"`
}

// ListAuthorizations returns the current user's active grants grouped by
// client for /user/oauth/manage. Revoked or expired rows never surface.
// The current browser and the grants are read in one short transaction.
func (s *Server) ListAuthorizations(ctx context.Context, browser *identity.BrowserSession) ([]AuthorizationView, error) {
	if browser == nil || browser.User == nil {
		return nil, identity.ErrSession
	}
	var out []AuthorizationView
	err := s.withBrowser(ctx, browser, func(ctx context.Context, tx *sql.Tx, user *identity.User, _ Snapshot) error {
		rows, err := tx.QueryContext(ctx, "SELECT c.id,c.name,a.payload,a.expires_at FROM "+s.cfg.Store.Table("go_oauth_access")+" a JOIN "+s.cfg.Store.Table("oauth_clients")+" c ON c.id=a.client_id WHERE a.user_uid=? AND a.active=1 AND a.expires_at>? ORDER BY c.id,a.expires_at", user.UID, unixNow())
		if err != nil {
			return err
		}
		defer rows.Close()
		byClient := map[string]int{}
		for rows.Next() {
			var clientID, clientName string
			var payload []byte
			var expires int64
			if err = rows.Scan(&clientID, &clientName, &payload, &expires); err != nil {
				return err
			}
			var data record
			if err = json.Unmarshal(payload, &data); err != nil {
				continue
			}
			if idx, ok := byClient[clientID]; ok {
				out[idx].Scopes = mergeScopes(out[idx].Scopes, data.GrantedScopes)
				if expires > out[idx].ExpiresAt {
					out[idx].ExpiresAt = expires
				}
				continue
			}
			byClient[clientID] = len(out)
			out = append(out, AuthorizationView{ClientID: clientID, ClientName: clientName, Scopes: append([]string(nil), data.GrantedScopes...), ExpiresAt: expires})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func mergeScopes(a, b []string) []string {
	set := map[string]bool{}
	for _, v := range a {
		set[v] = true
	}
	for _, v := range b {
		if !set[v] {
			set[v] = true
			a = append(a, v)
		}
	}
	return a
}

// unixNow is the issuance timestamp clock for consents and grant checks.
func unixNow() int64 { return time.Now().Unix() }
