package httpapp

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"paradise-cosmetics-studio/internal/maintenance"
)

// M4-07 prepare: atomic auth-reset x every credential entry (HTTP level).
//
// Existing coverage (reuse, not rerun as formal acceptance here):
//   - TestOfflineResetAndBoundedCleanup: transient tables emptied,
//     accounts/business/outbox kept.
//   - TestResetClearsConsentKeepsAccounts / TestAPILimitsResetClearsCountersKeepsAccounts:
//     consent + API-limit families cleared.
//
// Missing: a single cross-domain check that after ResetAuthentication the
// previously-live browser session, OAuth access token, PAT,
// and Yggdrasil token/join are ALL rejected at their own entry points,
// while the accounts/business data needed to re-authenticate survives.
func TestM407ResetRejectsAllCredentialEntries(t *testing.T) {
	h, id := appFixture(t)
	// F1: PAT creation requires a personal access client row; the shared
	// fixture only seeds clients 1-3, so seed it the same way
	// passportFixture's addPersonalClient does.
	if _, err := id.Store.DB.Exec("INSERT INTO " + id.Store.Table("oauth_clients") + " (id,user_id,name,secret,redirect,personal_access_client) VALUES (4,1,'Personal','synthetic-personal-secret','http://localhost',1)"); err != nil {
		t.Fatal(err)
	}
	userCookie, userCSRF := credentials(t, h, false)

	// --- Establish each credential family while live. ---
	// OAuth password-grant access token.
	form := url.Values{"grant_type": {"password"}, "client_id": {"3"}, "client_secret": {"password-secret"}, "username": {"user@example.invalid"}, "password": {"original-password"}}
	w := requestJSONForm(t, h, "POST", "/oauth/token", form.Encode())
	if w.Code != http.StatusOK {
		t.Fatalf("password grant status=%d body=%s", w.Code, w.Body.String())
	}
	var grant map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &grant); err != nil {
		t.Fatalf("grant decode: %v", err)
	}
	oauthToken, _ := grant["access_token"].(string)
	if oauthToken == "" {
		t.Fatalf("grant missing access_token: %v", grant)
	}
	if w := coreReq(t, h, "GET", "/api/user", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+oauthToken) }); w.Code != http.StatusOK {
		t.Fatalf("baseline api/user with oauth token status=%d body=%s", w.Code, w.Body.String())
	}

	// Personal access token (201 with accessToken).
	w = request(t, h, "POST", "/oauth/personal-access-tokens", `{"name":"m407-pat","scopes":["User.Read"]}`, userCSRF, userCookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("pat create status=%d body=%s", w.Code, w.Body.String())
	}
	var issued struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil || issued.AccessToken == "" {
		t.Fatalf("pat body=%s err=%v", w.Body.String(), err)
	}
	patToken := issued.AccessToken

	// Yggdrasil token.
	_ = yggEnable(t, id)
	yggToken := yggAuthenticateToken(t, h)

	// --- Atomic reset. ---
	if err := maintenance.ResetAuthentication(t.Context(), id.Store); err != nil {
		t.Fatalf("ResetAuthentication: %v", err)
	}
	// Accounts and business data must survive (reauthentication possible).
	var users int
	if err := id.Store.DB.QueryRow("SELECT COUNT(*) FROM " + id.Store.Table("users")).Scan(&users); err != nil || users < 2 {
		t.Fatalf("users after reset=%d err=%v", users, err)
	}

	// --- Every entry must now reject the old credential. ---
	// Browser session contract is Accept-dependent (app.go browser):
	// JSON requests get 401, browser (text/html) requests get a 302
	// redirect to the login page. Assert both sides explicitly (N2);
	// do not collapse them into "401 or 302".
	// JSON side: the shared request() helper sends Accept: application/json.
	w = request(t, h, "GET", "/user", "", "", userCookie)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("browser session (JSON) after reset status=%d body=%s (want 401)", w.Code, w.Body.String())
	}
	// Browser side: htmlRequest sends Accept: text/html (language_test.go),
	// matching a real browser navigation.
	w = htmlRequest(t, h, "/user", userCookie)
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "/auth/login") {
		t.Fatalf("browser session (text/html) after reset status=%d location=%q (want 302 to /auth/login)", w.Code, w.Header().Get("Location"))
	}
	// OAuth access token bearer: must be 401.
	if w := coreReq(t, h, "GET", "/api/user", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+oauthToken) }); w.Code != http.StatusUnauthorized {
		t.Fatalf("oauth token after reset status=%d body=%s", w.Code, w.Body.String())
	}
	// PAT bearer: must be 401.
	if w := coreReq(t, h, "GET", "/api/user", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+patToken) }); w.Code != http.StatusUnauthorized {
		t.Fatalf("pat after reset status=%d body=%s", w.Code, w.Body.String())
	}
	// API cookie path: the session cookie can no longer mint an API secret.
	if w := request(t, h, "POST", "/oauth/token/refresh", `{}`, userCSRF, userCookie); w.Code == http.StatusOK {
		t.Fatalf("api cookie refresh after reset status=200 body=%s", w.Body.String())
	}
	// Yggdrasil token validate: must not be 204.
	w = yggJSON(t, h, "POST", "/api/yggdrasil/authserver/validate", `{"accessToken":"`+yggToken+`"}`)
	if w.Code == http.StatusNoContent {
		t.Fatalf("ygg token survived reset: status=204 body=%s", w.Body.String())
	}
	// Yggdrasil join: must not be 204.
	w = yggJSON(t, h, "POST", "/api/yggdrasil/sessionserver/session/minecraft/join", `{"accessToken":"`+yggToken+`","selectedProfile":"x","serverId":"srv"}`)
	if w.Code == http.StatusNoContent {
		t.Fatalf("ygg join survived reset: status=204 body=%s", w.Body.String())
	}
	// Reauthentication must still be possible with the original password.
	form2 := url.Values{"grant_type": {"password"}, "client_id": {"3"}, "client_secret": {"password-secret"}, "username": {"user@example.invalid"}, "password": {"original-password"}}
	if w := requestJSONForm(t, h, "POST", "/oauth/token", form2.Encode()); w.Code != http.StatusOK {
		t.Fatalf("reauth after reset status=%d body=%s", w.Code, w.Body.String())
	}
}
