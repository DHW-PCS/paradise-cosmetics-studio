// Focused regressions for the M4-03 OAuth confirmed defects fixed in this
// round (FIX-OAUTH): client update must not rewrite password_client, user
// clients must not gain the password grant, the /oauth/tokens list must
// filter first-party rows like the frozen AuthorizedAccessTokenController,
// and approve must map engine protocol errors instead of falling to the
// service error. DB-backed: skipped without a DSN, never counted as pass.
package httpapp

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"paradise-cosmetics-studio/internal/oauthserver"
)

// The password grant is a system-client capability. Frozen store() has no
// grant input; user-created clients can never claim it. client_credentials
// stays accepted because a confidential client already holds that grant in
// the frozen/engine semantics, so no capability is added by listing it.
func TestFixOAuthClientCreateRejectsPasswordGrant(t *testing.T) {
	env := passportFixture(t)
	owner := env.browser(t, "user@example.invalid")

	w := env.call(t, env.app.oauthClientCreate, "POST", "/oauth/clients", `{"name":"x","redirect":"https://a.example.invalid/","grant_types":["password"]}`, owner, nil)
	if w.Code != 422 {
		t.Fatalf("password grant create status=%d body=%s", w.Code, w.Body.String())
	}
	var count int
	if err := env.store.DB.QueryRow("SELECT COUNT(*) FROM " + env.store.Table("oauth_clients") + " WHERE name='x'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("password client row inserted: count=%d err=%v", count, err)
	}

	// client_credentials remains available on user clients (a confidential
	// client holds it in the frozen semantics); the row never becomes a
	// password client.
	w = env.call(t, env.app.oauthClientCreate, "POST", "/oauth/clients", `{"name":"cc","redirect":"https://a.example.invalid/","grant_types":["client_credentials","refresh_token"]}`, owner, nil)
	if w.Code != 201 {
		t.Fatalf("client_credentials create status=%d body=%s", w.Code, w.Body.String())
	}
	var password int
	if err := env.store.DB.QueryRow("SELECT password_client FROM " + env.store.Table("oauth_clients") + " WHERE name='cc'").Scan(&password); err != nil || password != 0 {
		t.Fatalf("password_client=%d err=%v", password, err)
	}
}

// Update touches only name/redirect like frozen ClientRepository::update:
// a user-issued password client keeps its grant, a plain client cannot gain
// one through grant_types, and the response carries the full stored row with
// the secret hidden.
func TestFixOAuthClientUpdatePreservesFrozenNameRedirectOnly(t *testing.T) {
	env := passportFixture(t)
	owner := env.browser(t, "user@example.invalid")

	if _, err := env.store.DB.Exec("INSERT INTO " + env.store.Table("oauth_clients") + " (id,user_id,name,secret,redirect,password_client) VALUES (5,1,'pwd','synthetic-pwd-secret','https://client.example.invalid/callback',1)"); err != nil {
		t.Fatal(err)
	}

	w := env.call(t, env.app.oauthClientUpdate, "PUT", "/oauth/clients/5", `{"name":"renamed-pwd","redirect":"https://client.example.invalid/callback"}`, owner, map[string]string{"client_id": "5"})
	if w.Code != 200 {
		t.Fatalf("update status=%d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, field := range []string{`"name":"renamed-pwd"`, `"password_client":true`, `"personal_access_client":false`, `"revoked":false`} {
		if !strings.Contains(body, field) {
			t.Fatalf("update row missing %s body=%s", field, body)
		}
	}
	if strings.Contains(body, `"secret"`) {
		t.Fatalf("update response leaked the secret body=%s", body)
	}
	var password int
	if err := env.store.DB.QueryRow("SELECT password_client FROM " + env.store.Table("oauth_clients") + " WHERE id=5").Scan(&password); err != nil || password != 1 {
		t.Fatalf("password_client=%d err=%v", password, err)
	}

	// A user rename that carries grant_types must not escalate a plain
	// client into a password client: the grant is rejected and the stored
	// flag stays false.
	created := env.call(t, env.app.oauthClientCreate, "POST", "/oauth/clients", `{"name":"plain","redirect":"https://a.example.invalid/"}`, owner, nil)
	if created.Code != 201 {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var row struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	idStr := strconv.FormatInt(row.ID, 10)
	w = env.call(t, env.app.oauthClientUpdate, "PUT", "/oauth/clients/"+idStr, `{"name":"escalate","redirect":"https://a.example.invalid/","grant_types":["password"]}`, owner, map[string]string{"client_id": idStr})
	if w.Code != 422 {
		t.Fatalf("password grant update status=%d body=%s", w.Code, w.Body.String())
	}
	if err := env.store.DB.QueryRow("SELECT password_client FROM "+env.store.Table("oauth_clients")+" WHERE id=?", idStr).Scan(&password); err != nil || password != 0 {
		t.Fatalf("plain client password_client=%d err=%v", password, err)
	}
}

// A pending consent for a custom scope, staged while the scope existed,
// survives an online deletion without a display drift only when the
// description equals the fallback name; the engine then rejects the rebuilt
// request with ErrInvalidScope. The approve endpoint must surface the
// engine's 400, not the 503 service error.
func TestFixOAuthApproveScopeDeletedOnlineMapsProtocolError(t *testing.T) {
	env := passportFixture(t)
	if err := oauthserver.MigrateConsents(t.Context(), env.store); err != nil {
		t.Fatal(err)
	}
	owner := env.browser(t, "user@example.invalid")
	admin := env.browser(t, "admin@example.invalid")

	scope, err := env.oauth.CreateScope(t.Context(), admin, "acme.read", "acme.read")
	if err != nil {
		t.Fatal(err)
	}
	q := url.Values{"response_type": {"code"}, "client_id": {"1"}, "redirect_uri": {"https://client.example.invalid/callback"}, "state": {"synthetic-state"}, "scope": {"acme.read"}}
	view, err := env.oauth.ConsentShow(t.Context(), httptest.NewRequest("GET", "https://skin.example.invalid/oauth/authorize?"+q.Encode(), nil), owner)
	if err != nil || view.AuthToken == "" {
		t.Fatalf("stage consent view=%+v err=%v", view, err)
	}
	if err := env.oauth.DeleteScope(t.Context(), admin, scope.ID); err != nil {
		t.Fatal(err)
	}
	w := env.call(t, env.app.oauthAuthorizeApprove, "POST", "/oauth/authorize", fmt.Sprintf(`{"auth_token":%q}`, view.AuthToken), owner, nil)
	if w.Code != 400 {
		t.Fatalf("deleted-scope approve status=%d body=%s", w.Code, w.Body.String())
	}
}

// A client revoked between show and approve makes the pending rebuild fail
// with the engine's ErrNotFound; the approve endpoint must answer a 4xx,
// not the service error.
func TestFixOAuthApproveRevokedClientMapsEngineError(t *testing.T) {
	env := passportFixture(t)
	if err := oauthserver.MigrateConsents(t.Context(), env.store); err != nil {
		t.Fatal(err)
	}
	owner := env.browser(t, "user@example.invalid")

	q := url.Values{"response_type": {"code"}, "client_id": {"1"}, "redirect_uri": {"https://client.example.invalid/callback"}, "state": {"synthetic-state"}, "scope": {"User.Read"}}
	view, err := env.oauth.ConsentShow(t.Context(), httptest.NewRequest("GET", "https://skin.example.invalid/oauth/authorize?"+q.Encode(), nil), owner)
	if err != nil || view.AuthToken == "" {
		t.Fatalf("stage consent view=%+v err=%v", view, err)
	}
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("oauth_clients") + " SET revoked=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	w := env.call(t, env.app.oauthAuthorizeApprove, "POST", "/oauth/authorize", fmt.Sprintf(`{"auth_token":%q}`, view.AuthToken), owner, nil)
	if w.Code != 404 {
		t.Fatalf("revoked-client approve status=%d body=%s", w.Code, w.Body.String())
	}
}
