package httpapp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/config"
	"paradise-cosmetics-studio/internal/database"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/oauthserver"
	"paradise-cosmetics-studio/internal/site"
	"paradise-cosmetics-studio/internal/testsupport"
	"paradise-cosmetics-studio/web"
)

// passportEnv wires an App around one synthetic database without registering
// the routes (registration stays with the composition root): handlers are
// invoked directly with a real browser session from Login.
type passportEnv struct {
	app   *App
	id    *identity.Service
	oauth *oauthserver.Server
	store *database.Store
}

func passportFixture(t *testing.T) *passportEnv {
	t.Helper()
	store, id := testsupport.Database(t, "site-")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := oauthserver.New(oauthserver.Config{Store: store, Identity: id, PrivateKey: key, Secret: []byte("synthetic-m2-secret-at-least-32-bytes"), Issuer: "https://skin.example.invalid", Scopes: oauthserver.DefaultScopes, AccessLifetime: time.Hour, RefreshLifetime: 24 * time.Hour, CodeLifetime: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if err = srv.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	assets, err := web.Load()
	if err != nil {
		t.Fatal(err)
	}
	a := &App{cfg: config.Config{BaseURL: "http://localhost/skin", Locale: "zh_CN", FallbackLocale: "en"}, identity: id, site: &site.Service{Store: store, Identity: id, Location: time.UTC}, assets: assets, oauth: srv, clock: time.Now}
	return &passportEnv{app: a, id: id, oauth: srv, store: store}
}

func (e *passportEnv) browser(t *testing.T, email string) *identity.BrowserSession {
	t.Helper()
	b, err := e.id.Login(t.Context(), email, "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// call invokes one handler directly with the CSRF header the frozen write
// endpoints carry, and returns the recorded response.
func (e *passportEnv) call(t *testing.T, handler func(http.ResponseWriter, *http.Request, *identity.BrowserSession), method, path, body string, b *identity.BrowserSession, params map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "https://skin.example.invalid"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	if b != nil {
		r.Header.Set("X-CSRF-TOKEN", b.CSRF)
	}
	for key, value := range params {
		r.SetPathValue(key, value)
	}
	w := httptest.NewRecorder()
	handler(w, r, b)
	return w
}

func (e *passportEnv) addPersonalClient(t *testing.T) {
	t.Helper()
	if _, err := e.store.DB.Exec("INSERT INTO " + e.store.Table("oauth_clients") + " (id,user_id,name,secret,redirect,personal_access_client) VALUES (4,1,'Personal','synthetic-personal-secret','http://localhost',1)"); err != nil {
		t.Fatal(err)
	}
}

func TestPassportClientsOwnerAndCRUD(t *testing.T) {
	env := passportFixture(t)
	owner := env.browser(t, "user@example.invalid")
	other := env.browser(t, "admin@example.invalid")

	// Create: 201, id from the database, secret returned exactly once.
	w := env.call(t, env.app.oauthClientCreate, "POST", "/oauth/clients", `{"name":"mine","redirect":"https://app.example.invalid/cb"}`, owner, nil)
	if w.Code != 201 {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	var created struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		Secret   string `json:"secret"`
		Redirect string `json:"redirect"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.ID < 1 || created.Secret == "" || created.Redirect != "https://app.example.invalid/cb" {
		t.Fatalf("create body=%s err=%v", w.Body.String(), err)
	}
	idStr := strconv.FormatInt(created.ID, 10)

	// List: with secret hashing not enabled, the owner sees the stored
	// plaintext secret and the comma-separated redirect string; a foreign
	// user sees an empty array.
	w = env.call(t, env.app.oauthClientsList, "GET", "/oauth/clients", "", owner, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"name":"mine"`) || !strings.Contains(w.Body.String(), `"secret":"`+created.Secret+`"`) || !strings.Contains(w.Body.String(), `"redirect":"https://app.example.invalid/cb"`) {
		t.Fatalf("list status=%d body=%s", w.Code, w.Body.String())
	}
	if w = env.call(t, env.app.oauthClientsList, "GET", "/oauth/clients", "", other, nil); strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("foreign list status=%d body=%s", w.Code, w.Body.String())
	}

	// Cross-user access is 404, indistinguishable from a missing id, on
	// every single-client operation.
	params := map[string]string{"client_id": idStr}
	if w = env.call(t, env.app.oauthClientDetail, "GET", "/oauth/clients/"+idStr, "", other, params); w.Code != 404 {
		t.Fatalf("foreign detail status=%d", w.Code)
	}
	if w = env.call(t, env.app.oauthClientDetail, "GET", "/oauth/clients/"+idStr, "", owner, params); w.Code != 200 || !strings.Contains(w.Body.String(), `"User.Read"`) || !strings.Contains(w.Body.String(), `"*"`) {
		t.Fatalf("detail status=%d body=%s", w.Code, w.Body.String())
	}
	if w = env.call(t, env.app.oauthClientDelete, "DELETE", "/oauth/clients/"+idStr, `{}`, other, params); w.Code != 404 {
		t.Fatalf("foreign delete status=%d", w.Code)
	}

	// Update keeps the id and returns the changed row.
	w = env.call(t, env.app.oauthClientUpdate, "PUT", "/oauth/clients/"+idStr, `{"name":"renamed","redirect":"https://app.example.invalid/other","grant_types":["authorization_code"],"scopes":["User.Read"]}`, owner, params)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"name":"renamed"`) {
		t.Fatalf("update status=%d body=%s", w.Code, w.Body.String())
	}
	if w = env.call(t, env.app.oauthClientUpdate, "PUT", "/oauth/clients/999", `{"name":"x","redirect":"https://a.example.invalid/"}`, owner, map[string]string{"client_id": "999"}); w.Code != 404 {
		t.Fatalf("missing update status=%d", w.Code)
	}

	// Same name under a different owner is fine; malformed redirect,
	// grant and scope values are 422.
	if w = env.call(t, env.app.oauthClientCreate, "POST", "/oauth/clients", `{"name":"mine","redirect":"https://app.example.invalid/cb"}`, other, nil); w.Code != 201 {
		t.Fatalf("same-name create status=%d body=%s", w.Code, w.Body.String())
	}
	for _, body := range []string{
		`{"name":"x","redirect":"not-a-url"}`,
		`{"name":"x","redirect":"https://a.example.invalid/","grant_types":["bogus"]}`,
		`{"name":"x","redirect":"https://a.example.invalid/","scopes":["bogus.scope"]}`,
		`{"name":"","redirect":"https://a.example.invalid/"}`,
		`{"name":"x","redirect":""}`,
	} {
		if w = env.call(t, env.app.oauthClientCreate, "POST", "/oauth/clients", body, owner, nil); w.Code != 422 {
			t.Fatalf("invalid input %s status=%d", body, w.Code)
		}
	}
}

func TestPassportClientDeleteRevokesGrants(t *testing.T) {
	env := passportFixture(t)
	owner := env.browser(t, "user@example.invalid")

	w := env.call(t, env.app.oauthClientCreate, "POST", "/oauth/clients", `{"name":"grant-me","redirect":"https://app.example.invalid/cb"}`, owner, nil)
	if w.Code != 201 {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	var created struct {
		ID     int64  `json:"id"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	// Issue a real authorization-code grant for the new client.
	clientID := created.ID
	authorizeForm := url.Values{"response_type": {"code"}, "client_id": {strconv.FormatInt(clientID, 10)}, "redirect_uri": {"https://app.example.invalid/cb"}, "state": {"synthetic-state"}, "scope": {"User.Read"}}
	authRequest := httptest.NewRequest("GET", "https://skin.example.invalid/oauth/authorize?"+authorizeForm.Encode(), nil)
	code, err := env.oauth.Authorize(t.Context(), authRequest, owner)
	if err != nil || code == "" {
		t.Fatalf("authorize code=%q err=%v", code, err)
	}
	grantForm := url.Values{"grant_type": {"authorization_code"}, "client_id": {strconv.FormatInt(clientID, 10)}, "client_secret": {created.Secret}, "redirect_uri": {"https://app.example.invalid/cb"}, "code": {code}}
	tokenRequest := httptest.NewRequest("POST", "https://skin.example.invalid/oauth/token", strings.NewReader(grantForm.Encode()))
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResponse := httptest.NewRecorder()
	env.oauth.Token(tokenResponse, tokenRequest)
	var grant map[string]any
	if err := json.Unmarshal(tokenResponse.Body.Bytes(), &grant); err != nil {
		t.Fatalf("token body=%s", tokenResponse.Body.String())
	}
	access, _ := grant["access_token"].(string)
	refresh, _ := grant["refresh_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("grant body=%s", tokenResponse.Body.String())
	}
	if _, err := env.oauth.Validate(t.Context(), access, "User.Read"); err != nil {
		t.Fatalf("validate before delete: %v", err)
	}

	if w = env.call(t, env.app.oauthClientDelete, "DELETE", "/oauth/clients/"+strconv.FormatInt(clientID, 10), `{}`, owner, map[string]string{"client_id": strconv.FormatInt(clientID, 10)}); w.Code != 204 {
		t.Fatalf("delete status=%d body=%s", w.Code, w.Body.String())
	}
	// After revocation the grant is dead on every path: validation,
	// refresh and the detail view's revoked flag.
	if _, err := env.oauth.Validate(t.Context(), access, "User.Read"); err == nil {
		t.Fatal("access token survived client revocation")
	}
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "client_id": {strconv.FormatInt(clientID, 10)}, "client_secret": {created.Secret}, "refresh_token": {refresh}}
	refreshRequest := httptest.NewRequest("POST", "https://skin.example.invalid/oauth/token", strings.NewReader(refreshForm.Encode()))
	refreshRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshResponse := httptest.NewRecorder()
	env.oauth.Token(refreshResponse, refreshRequest)
	if refreshResponse.Code == 200 {
		t.Fatal("refresh survived client revocation")
	}
	var revoked int
	if err := env.store.DB.QueryRow("SELECT revoked FROM "+env.store.Table("oauth_clients")+" WHERE id=?", clientID).Scan(&revoked); err != nil || revoked != 1 {
		t.Fatalf("revoked=%d err=%v", revoked, err)
	}
	// The revoked row is filtered from a fresh owner list load.
	if w = env.call(t, env.app.oauthClientsList, "GET", "/oauth/clients", "", owner, nil); w.Code != 200 || strings.Contains(w.Body.String(), `"name":"grant-me"`) {
		t.Fatalf("revoked client reappeared in list status=%d body=%s", w.Code, w.Body.String())
	}
	if w = env.call(t, env.app.oauthClientDetail, "GET", "/oauth/clients/"+strconv.FormatInt(clientID, 10), "", owner, map[string]string{"client_id": strconv.FormatInt(clientID, 10)}); !strings.Contains(w.Body.String(), `"revoked":true`) {
		t.Fatalf("detail after delete status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestPassportPersonalTokens(t *testing.T) {
	env := passportFixture(t)
	env.addPersonalClient(t)
	owner := env.browser(t, "user@example.invalid")
	other := env.browser(t, "admin@example.invalid")

	// Create a personal token: 201 with accessToken and the stored row.
	w := env.call(t, env.app.oauthPersonalTokenCreate, "POST", "/oauth/personal-access-tokens", `{"name":"pat","scopes":["User.Read"]}`, owner, nil)
	if w.Code != 201 || !strings.Contains(w.Body.String(), `"accessToken":"`) {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	var issued struct {
		AccessToken string `json:"accessToken"`
		Token       struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil || issued.Token.Name != "pat" || issued.Token.ID == "" {
		t.Fatalf("create body=%s err=%v", w.Body.String(), err)
	}
	if _, err := env.oauth.Validate(t.Context(), issued.AccessToken, "User.Read"); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// The list reads the stored go_oauth_access row back with its name;
	// a foreign user sees nothing.
	w = env.call(t, env.app.oauthPersonalTokensList, "GET", "/oauth/personal-access-tokens", "", owner, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"name":"pat"`) || !strings.Contains(w.Body.String(), `"User.Read"`) {
		t.Fatalf("list status=%d body=%s", w.Code, w.Body.String())
	}
	var rows []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || len(rows) != 1 || rows[0].ID != issued.Token.ID {
		t.Fatalf("list body=%s err=%v", w.Body.String(), err)
	}
	tokenID := rows[0].ID
	if w = env.call(t, env.app.oauthPersonalTokensList, "GET", "/oauth/personal-access-tokens", "", other, nil); strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("foreign list status=%d body=%s", w.Code, w.Body.String())
	}

	// Cross-user revoke is 404; owner revoke is 204 and idempotent;
	// the token is dead afterwards.
	params := map[string]string{"token_id": tokenID}
	if w = env.call(t, env.app.oauthPersonalTokenDelete, "DELETE", "/oauth/personal-access-tokens/x", `{}`, other, params); w.Code != 404 {
		t.Fatalf("foreign revoke status=%d", w.Code)
	}
	if w = env.call(t, env.app.oauthPersonalTokenDelete, "DELETE", "/oauth/personal-access-tokens/x", `{}`, owner, params); w.Code != 204 {
		t.Fatalf("revoke status=%d body=%s", w.Code, w.Body.String())
	}
	if _, err := env.oauth.Validate(t.Context(), issued.AccessToken, "User.Read"); err == nil {
		t.Fatal("personal token survived revocation")
	}
	if w = env.call(t, env.app.oauthPersonalTokenDelete, "DELETE", "/oauth/personal-access-tokens/x", `{}`, owner, params); w.Code != 204 {
		t.Fatalf("repeat revoke status=%d", w.Code)
	}
	if w = env.call(t, env.app.oauthPersonalTokenDelete, "DELETE", "/oauth/personal-access-tokens/x", `{}`, owner, map[string]string{"token_id": "missing"}); w.Code != 404 {
		t.Fatalf("unknown revoke status=%d", w.Code)
	}

	// Invalid scope and empty name are 422.
	if w = env.call(t, env.app.oauthPersonalTokenCreate, "POST", "/oauth/personal-access-tokens", `{"name":"bad","scopes":["bogus.scope"]}`, owner, nil); w.Code != 422 {
		t.Fatalf("invalid scope status=%d", w.Code)
	}
	if w = env.call(t, env.app.oauthPersonalTokenCreate, "POST", "/oauth/personal-access-tokens", `{"name":"","scopes":[]}`, owner, nil); w.Code != 422 {
		t.Fatalf("empty name status=%d", w.Code)
	}
}

func TestPassportTokensListAndSingleRevoke(t *testing.T) {
	env := passportFixture(t)
	env.addPersonalClient(t)
	owner := env.browser(t, "user@example.invalid")
	other := env.browser(t, "admin@example.invalid")

	// One real authorization-code grant on the regular client (id 1) plus
	// one personal access token. The frozen /oauth/tokens list shows only
	// the former: first-party (personal/password) rows live under the
	// personal-access-token endpoints.
	grantForm := url.Values{"response_type": {"code"}, "client_id": {"1"}, "redirect_uri": {"https://client.example.invalid/callback"}, "state": {"synthetic-state"}, "scope": {"User.Read"}}
	grantRequest := httptest.NewRequest("GET", "https://skin.example.invalid/oauth/authorize?"+grantForm.Encode(), nil)
	code, err := env.oauth.Authorize(t.Context(), grantRequest, owner)
	if err != nil || code == "" {
		t.Fatalf("authorize code=%q err=%v", code, err)
	}
	exchange := url.Values{"grant_type": {"authorization_code"}, "client_id": {"1"}, "client_secret": {"client-secret"}, "redirect_uri": {"https://client.example.invalid/callback"}, "code": {code}}
	exchangeRequest := httptest.NewRequest("POST", "https://skin.example.invalid/oauth/token", strings.NewReader(exchange.Encode()))
	exchangeRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	exchangeResponse := httptest.NewRecorder()
	env.oauth.Token(exchangeResponse, exchangeRequest)
	var grant map[string]any
	if err := json.Unmarshal(exchangeResponse.Body.Bytes(), &grant); err != nil || grant["access_token"] == nil {
		t.Fatalf("grant body=%s err=%v", exchangeResponse.Body.String(), err)
	}
	access := grant["access_token"].(string)

	w := env.call(t, env.app.oauthPersonalTokenCreate, "POST", "/oauth/personal-access-tokens", `{"name":"pat","scopes":["User.Read"]}`, owner, nil)
	if w.Code != 201 {
		t.Fatalf("pat create status=%d body=%s", w.Code, w.Body.String())
	}
	var pat struct {
		AccessToken string                       `json:"accessToken"`
		Token       oauthserver.PersonalTokenRow `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &pat); err != nil || pat.Token.ID == "" {
		t.Fatalf("pat create body=%s err=%v", w.Body.String(), err)
	}

	w = env.call(t, env.app.oauthTokensList, "GET", "/oauth/tokens", "", owner, nil)
	if w.Code != 200 {
		t.Fatalf("tokens status=%d body=%s", w.Code, w.Body.String())
	}
	var listed []struct {
		ID         string `json:"id"`
		ClientID   string `json:"client_id"`
		ClientName string `json:"client_name"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil || len(listed) != 1 || listed[0].ClientID != "1" || listed[0].ClientName != "synthetic" {
		t.Fatalf("tokens body=%s err=%v", w.Body.String(), err)
	}
	// A leaked personal row would surface under its own request id (the
	// PAT's real id) or its "Personal" client name; both are checked so
	// the exclusion stays observable. The single listed row belongs to
	// the regular authorization-code grant above, so an id equality
	// against the PAT could never fire.
	patID := pat.Token.ID
	if strings.Contains(w.Body.String(), patID) || strings.Contains(w.Body.String(), `"client_name":"Personal"`) {
		t.Fatalf("first-party token leaked into /oauth/tokens body=%s", w.Body.String())
	}
	if w = env.call(t, env.app.oauthTokensList, "GET", "/oauth/tokens", "", other, nil); strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("foreign tokens status=%d body=%s", w.Code, w.Body.String())
	}

	first := listed[0].ID
	if w = env.call(t, env.app.oauthTokenDelete, "DELETE", "/oauth/tokens/x", `{}`, other, map[string]string{"token_id": first}); w.Code != 404 {
		t.Fatalf("foreign revoke status=%d", w.Code)
	}
	if w = env.call(t, env.app.oauthTokenDelete, "DELETE", "/oauth/tokens/x", `{}`, owner, map[string]string{"token_id": first}); w.Code != 204 {
		t.Fatalf("revoke status=%d body=%s", w.Code, w.Body.String())
	}
	if w = env.call(t, env.app.oauthTokensList, "GET", "/oauth/tokens", "", owner, nil); strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("list after revoke body=%s", w.Body.String())
	}
	// Exactly the revoked grant dies: the access token is dead while the
	// personal token still validates.
	if _, err := env.oauth.Validate(t.Context(), access, "User.Read"); err == nil {
		t.Fatal("regular grant survived revocation")
	}
	if _, err := env.oauth.Validate(t.Context(), pat.AccessToken, "User.Read"); err != nil {
		t.Fatalf("personal token died with the regular grant: %v", err)
	}
}

func TestPassportScopesListMergesCustomRows(t *testing.T) {
	env := passportFixture(t)
	if _, err := env.store.DB.Exec("INSERT INTO " + env.store.Table("scopes") + " (name,description) VALUES ('User.Read','custom profile'),('acme.read','Acme')"); err != nil {
		t.Fatal(err)
	}
	owner := env.browser(t, "user@example.invalid")
	w := env.call(t, env.app.oauthPassportScopesList, "GET", "/oauth/scopes", "", owner, nil)
	if w.Code != 200 {
		t.Fatalf("scopes status=%d body=%s", w.Code, w.Body.String())
	}
	var rows []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(oauthserver.DefaultScopes)+1 {
		t.Fatalf("scopes count=%d rows=%v", len(rows), rows)
	}
	// Passport shape is id, not name; a custom row on a default name
	// overrides with its stored text, an untouched default carries its
	// frozen translation key, and a custom-only scope keeps its text.
	if rows[0].ID != "User.Read" || rows[0].Name != "" || rows[0].Description != "custom profile" {
		t.Fatalf("first merge row=%+v", rows[0])
	}
	if rows[1].ID != "Notification.Read" || rows[1].Description != "auth.oauth.scope.notification.read" {
		t.Fatalf("default description row=%+v", rows[1])
	}
	if rows[len(rows)-1].ID != "acme.read" || rows[len(rows)-1].Description != "Acme" {
		t.Fatalf("last merge row=%+v", rows[len(rows)-1])
	}
}

func TestPassportSQLFaultAnswersServiceError(t *testing.T) {
	env := passportFixture(t)
	owner := env.browser(t, "user@example.invalid")
	if _, err := env.store.DB.Exec("DROP TABLE " + env.store.Table("oauth_clients")); err != nil {
		t.Fatal(err)
	}
	// A storage fault is never a 404/422: the service error is the contract.
	if w := env.call(t, env.app.oauthClientsList, "GET", "/oauth/clients", "", owner, nil); w.Code != 503 {
		t.Fatalf("list fault status=%d body=%s", w.Code, w.Body.String())
	}
	if w := env.call(t, env.app.oauthClientCreate, "POST", "/oauth/clients", `{"name":"x","redirect":"https://a.example.invalid/"}`, owner, nil); w.Code != 503 {
		t.Fatalf("create fault status=%d body=%s", w.Code, w.Body.String())
	}
}

// The frozen dynamic registration applies verified only to clients and
// tokens (plus manage/authorize in consent.go). Scopes and personal
// tokens keep their existing conditions when verification is required
// and the user is unverified. DB-backed: skipped without a DSN.
func TestPassportVerifiedClientsTokensOnly(t *testing.T) {
	env := passportFixture(t)
	if _, err := env.store.DB.Exec("INSERT INTO " + env.store.Table("options") + " (option_name,option_value) VALUES ('require_verification','true')"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET verified=0 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	env.addPersonalClient(t)
	unverified := env.browser(t, "user@example.invalid")

	if w := env.call(t, env.app.oauthClientsList, "GET", "/oauth/clients", "", unverified, nil); w.Code != 403 {
		t.Fatalf("clients verified status=%d body=%s", w.Code, w.Body.String())
	}
	if w := env.call(t, env.app.oauthTokensList, "GET", "/oauth/tokens", "", unverified, nil); w.Code != 403 {
		t.Fatalf("tokens verified status=%d body=%s", w.Code, w.Body.String())
	}
	if w := env.call(t, env.app.oauthPassportScopesList, "GET", "/oauth/scopes", "", unverified, nil); w.Code != 200 {
		t.Fatalf("scopes must not gain verified status=%d body=%s", w.Code, w.Body.String())
	}
	if w := env.call(t, env.app.oauthPersonalTokensList, "GET", "/oauth/personal-access-tokens", "", unverified, nil); w.Code != 200 {
		t.Fatalf("personal tokens must not gain verified status=%d body=%s", w.Code, w.Body.String())
	}
	if w := env.call(t, env.app.oauthAuthorizeShow, "GET", "/oauth/authorize?client_id=1&redirect_uri=https://client.example.invalid/callback&response_type=code&scope=User.Read&state=0123456789abcdef0123456789abcdef", "", unverified, nil); w.Code != 403 {
		t.Fatalf("authorize verified status=%d body=%s", w.Code, w.Body.String())
	}
}
