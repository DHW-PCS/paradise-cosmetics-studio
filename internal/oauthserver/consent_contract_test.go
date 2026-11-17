package oauthserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"authelia.com/provider/oauth2"
	"paradise-cosmetics-studio/internal/identity"
)

func insertConsentContractGrant(t *testing.T, s *Server, id string, uid int64, expires int64, scopes []string) {
	t.Helper()
	state := newSession(uid, 1)
	state.SetExpiresAt(oauth2.AccessToken, time.Unix(expires, 0))
	payload, err := json.Marshal(record{ID: id, Requested: time.Now(), RequestedScopes: scopes, GrantedScopes: scopes, Session: state})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.cfg.Store.DB.ExecContext(t.Context(), "INSERT INTO "+s.cfg.Store.Table("go_oauth_access")+" (signature,request_id,client_id,user_uid,version,active,expires_at,payload) VALUES (?,?, '1',?,1,1,?,?)", identity.Digest(id), id, uid, expires, payload)
	if err != nil {
		t.Fatal(err)
	}
}

// The five later-expiring grants do not match; the sixth valid grant does.
// Exercise ConsentShow so the oracle is direct authorization, not SQL text.
func TestConsentShowAutoApprovesSixthExactGrant(t *testing.T) {
	s := fixture(t)
	if err := MigrateConsents(t.Context(), s.cfg.Store); err != nil {
		t.Fatal(err)
	}
	browser, err := s.cfg.Identity.Login(t.Context(), "user@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	now := unixNow()
	for i := range 5 {
		insertConsentContractGrant(t, s, fmt.Sprintf("nonmatching-%d", i), 1, now+7200+int64(i), []string{"User.Read"})
	}
	view, err := s.ConsentShow(t.Context(), consentAuthorizeURL(t, "Player.Read"), browser)
	if err != nil {
		t.Fatal(err)
	}
	if view.AuthToken == "" {
		t.Fatal("nonmatching grants must still prompt for consent")
	}
	insertConsentContractGrant(t, s, "sixth-exact", 1, now+3600, []string{"Player.Read"})
	view, err = s.ConsentShow(t.Context(), consentAuthorizeURL(t, "Player.Read"), browser)
	if err != nil {
		t.Fatal(err)
	}
	if view.AuthToken != "" {
		t.Fatal("sixth exact grant incorrectly prompted for consent again")
	}
	redirect, err := url.Parse(view.RedirectURI)
	if err != nil {
		t.Fatal("invalid direct-authorization redirect")
	}
	if redirect.Scheme != "https" || redirect.Host != "client.example.invalid" || redirect.Path != "/callback" || redirect.Query().Get("code") == "" || redirect.Query().Get("state") != "synthetic-state" {
		t.Fatal("direct authorization did not preserve the callback, code and state contract")
	}
}

// A browser object from entry validation must not authorize reads after
// logout, UID revocation or session expiry. The live case also checks UID
// scoping; all calls use the production short-transaction list entry.
func TestListAuthorizationsRejectsStaleBrowser(t *testing.T) {
	for _, mutation := range []string{"logout", "uid-version", "session-expiry"} {
		t.Run(mutation, func(t *testing.T) {
			s := fixture(t)
			expires := unixNow() + 3600
			insertConsentContractGrant(t, s, "owned-list-grant", 1, expires, []string{"User.Read"})
			insertConsentContractGrant(t, s, "other-user-grant", 2, expires, []string{"Player.Read"})
			browser, err := s.cfg.Identity.Login(t.Context(), "user@example.invalid", "original-password", false, "")
			if err != nil {
				t.Fatal(err)
			}
			grants, err := s.ListAuthorizations(t.Context(), browser)
			if err != nil {
				t.Fatal(err)
			}
			if len(grants) != 1 || grants[0].ClientID != "1" || grants[0].ExpiresAt != expires || len(grants[0].Scopes) != 1 || grants[0].Scopes[0] != "User.Read" {
				t.Fatal("live browser list did not return exactly its own grant")
			}
			switch mutation {
			case "logout":
				err = s.cfg.Identity.Logout(t.Context(), browser.Token)
			case "uid-version":
				_, err = s.cfg.Store.DB.ExecContext(t.Context(), "UPDATE "+s.cfg.Store.Table("go_auth_versions")+" SET version=version+1 WHERE user_uid=?", browser.User.UID)
			case "session-expiry":
				_, err = s.cfg.Store.DB.ExecContext(t.Context(), "UPDATE "+s.cfg.Store.Table("go_web_sessions")+" SET expires_at=0 WHERE digest=?", identity.Digest(browser.Token))
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.ListAuthorizations(t.Context(), browser); !errors.Is(err, identity.ErrSession) {
				t.Fatalf("stale browser read after %s: %v", mutation, err)
			}
		})
	}
}
