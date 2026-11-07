package httpapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// The four maintenance entries deliver the design's response matrix against
// a live admin session; the policy lease keeps snapshot consumers intact.
func TestOAuthScopeMaintenanceEntries(t *testing.T) {
	h, _ := appFixture(t)
	admin, csrf := credentials(t, h, true)
	member, _ := credentials(t, h, false)

	// List: empty custom set; the base rows never enter the endpoint table.
	w := request(t, h, "GET", "/admin/oauth/scopes", "", "", admin)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("list status=%d body=%s", w.Code, w.Body.String())
	}
	if w := request(t, h, "GET", "/admin/oauth/scopes", "", "", member); w.Code != 403 {
		t.Fatalf("member list status=%d", w.Code)
	}

	// Create: 201 and the stored row; a scope-token violation rejects.
	w = request(t, h, "POST", "/admin/oauth/scopes", `{"name":"custom.read","description":"custom detail"}`, csrf, admin)
	if w.Code != 201 || !strings.Contains(w.Body.String(), `"name":"custom.read"`) {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	if w = request(t, h, "POST", "/admin/oauth/scopes", `{"name":"bad scope","description":"x"}`, csrf, admin); w.Code != 422 {
		t.Fatalf("invalid token status=%d", w.Code)
	}
	if w = request(t, h, "POST", "/admin/oauth/scopes", `{"name":"custom.read","description":"x"}`, csrf, admin); w.Code != 409 {
		t.Fatalf("duplicate status=%d", w.Code)
	}
	// Update keeps the row identity; the response carries the changed row.
	w = request(t, h, "PUT", "/admin/oauth/scopes/1", `{"name":"custom.read","description":"changed"}`, csrf, admin)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"description":"changed"`) {
		t.Fatalf("update status=%d body=%s", w.Code, w.Body.String())
	}
	// Missing and delete.
	if w = request(t, h, "PUT", "/admin/oauth/scopes/99", `{"name":"custom.read","description":"x"}`, csrf, admin); w.Code != 404 {
		t.Fatalf("missing update status=%d", w.Code)
	}
	w = request(t, h, "DELETE", "/admin/oauth/scopes/1", `{}`, csrf, admin)
	if w.Code != 204 {
		t.Fatalf("delete status=%d", w.Code)
	}
	if w = request(t, h, "DELETE", "/admin/oauth/scopes/1", `{}`, csrf, admin); w.Code != 404 {
		t.Fatalf("missing delete status=%d", w.Code)
	}
}

// A published custom scope reaches real issuance without a restart; after a
// delete the same grant stops working immediately.
// requestJSONForm posts one form-encoded target with the JSON accept header.
func requestJSONForm(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://localhost/skin"+target, strings.NewReader(body))
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestOAuthScopePublicationReachesIssuance(t *testing.T) {
	h, _ := appFixture(t)
	admin, csrf := credentials(t, h, true)
	w := request(t, h, "POST", "/admin/oauth/scopes", `{"name":"tenant.read","description":"Tenant Access"}`, csrf, admin)
	if w.Code != 201 {
		t.Fatalf("create status=%d", w.Code)
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.ID < 1 {
		t.Fatalf("create body=%s err=%v", w.Body.String(), err)
	}
	exchange := func(scope string) int {
		body := url.Values{"grant_type": {"password"}, "client_id": {"3"}, "client_secret": {"password-secret"}, "username": {"user@example.invalid"}, "password": {"original-password"}}
		if scope != "" {
			body.Set("scope", scope)
		}
		w := requestJSONForm(t, h, "POST", "/oauth/token", body.Encode())
		return w.Code
	}
	if code := exchange("tenant.read"); code != 200 {
		t.Fatalf("published scope grant status=%d", code)
	}
	// Removal goes through the maintenance entry so the committed snapshot
	// is republished; a direct DB edit bypasses publication by design and
	// would keep the pinned snapshot until restart or next publish.
	if w := request(t, h, "DELETE", "/admin/oauth/scopes/"+strconv.FormatInt(created.ID, 10), `{}`, csrf, admin); w.Code != 204 {
		t.Fatalf("delete status=%d", w.Code)
	}
	w = requestJSONForm(t, h, "POST", "/oauth/token", (&url.Values{"grant_type": {"password"}, "client_id": {"3"}, "client_secret": {"password-secret"}, "username": {"user@example.invalid"}, "password": {"original-password"}, "scope": {"tenant.read"}}).Encode())
	if w.Code != 400 || !strings.Contains(strings.ToLower(w.Body.String()), "invalid_scope") {
		t.Fatalf("removed scope still granted: status=%d body=%s", w.Code, w.Body.String())
	}
	// The default unset (User.Read) keeps working for token flows.
	if w := requestJSONForm(t, h, "POST", "/oauth/token", (&url.Values{"grant_type": {"password"}, "client_id": {"3"}, "client_secret": {"password-secret"}, "username": {"user@example.invalid"}, "password": {"original-password"}}).Encode()); w.Code != 200 {
		t.Fatalf("default scope grant status=%d", w.Code)
	}
}
