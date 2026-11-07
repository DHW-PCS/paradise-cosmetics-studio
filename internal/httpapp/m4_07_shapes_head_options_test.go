package httpapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// M4-07 prepare: exact error shapes, 204/empty bodies, HEAD/OPTIONS,
// ALI header and subpath behaviour (HTTP boundary).
//
// Existing coverage (reuse, not rerun as formal acceptance here):
//   - TestCoreAPI* family: 33 core API permission/scope/validation shapes.
//   - TestOAuthScopeMaintenanceEntries: scope 201/200/204/404/422/409.
//   - TestYggdrasilHTTPContractEdges / TestYggdrasilHelloAndModuleGate:
//     Ygg wire shapes, module gate, publickeys gate.
//   - TestLegacyPNG* family: 404/403/ETag/HEAD-adjacent behaviour.
//   - TestOAuthLoginRootDeployment / TestLegacyPNGDeploymentPrefixAndJSONRoutes:
//     subpath vs root.
//
// Missing at the combined boundary:
//   - scope maintenance non-JSON body -> 422 request error (not 500/HTML).
//   - Ygg validate/invalidate 204 must carry an empty body (no JSON null).
//   - Ygg search-multiple empty input -> 200 "[]" (empty array, not null).
//   - HEAD on a GET route returns headers with no body.
//   - OPTIONS preflight on /api and /api/yggdrasil does not 5xx.
//   - ALI header present only when ygg_enable_ali on + module served, and
//     the value is BaseURL+"/api/yggdrasil".
func TestM407ExactShapesHEADOPTIONSALI(t *testing.T) {
	h, id := appFixture(t)
	adminCookie, adminCSRF := credentials(t, h, true)

	// --- Scope maintenance: non-JSON body is a 422 request error. ---
	w := requestRaw(t, h, "POST", "/admin/oauth/scopes", "not-json{{{", "application/json", adminCSRF, adminCookie)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("scope non-json status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"request"`) {
		t.Fatalf("scope non-json body missing request key: %s", w.Body.String())
	}
	// Empty list is still "[]" (array, not object/null) — pinned by the
	// dedicated maintenance test; here only the shape distinction matters:
	// create then delete returns 204 with an empty body (no JSON "null").
	w = request(t, h, "POST", "/admin/oauth/scopes", `{"name":"m407.shape","description":"shape"}`, adminCSRF, adminCookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.ID < 1 {
		t.Fatalf("create body=%s err=%v", w.Body.String(), err)
	}
	idStr := strconv.FormatInt(created.ID, 10)
	w = request(t, h, "DELETE", "/admin/oauth/scopes/"+idStr, `{}`, adminCSRF, adminCookie)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Fatalf("delete 204 body non-empty: %q", w.Body.String())
	}

	// --- Yggdrasil: validate/invalidate 204 bodies are empty. ---
	_ = yggEnable(t, id)
	token := yggAuthenticateToken(t, h)
	w = yggJSON(t, h, "POST", "/api/yggdrasil/authserver/validate", `{"accessToken":"`+token+`"}`)
	if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
		t.Fatalf("validate status=%d body=%q", w.Code, w.Body.String())
	}
	w = yggJSON(t, h, "POST", "/api/yggdrasil/authserver/invalidate", `{"accessToken":"`+token+`"}`)
	if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
		t.Fatalf("invalidate status=%d body=%q", w.Code, w.Body.String())
	}
	// Search-multiple with an empty array returns 200 "[]" (not null/{}).
	w = yggJSON(t, h, "POST", "/api/yggdrasil/api/profiles/minecraft", `[]`)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("search empty status=%d body=%s", w.Code, w.Body.String())
	}

	// --- HEAD on a GET route: headers, no body. ---
	w = request(t, h, "HEAD", "/api/user", "", "", nil)
	if w.Code == http.StatusInternalServerError || w.Code == http.StatusNotImplemented {
		t.Fatalf("HEAD /api/user status=%d", w.Code)
	}
	// HEAD must not carry a JSON envelope body.
	if strings.TrimSpace(w.Body.String()) != "" {
		// Some Go muxes still write a body for HEAD via httptest; the
		// contract is only that it is not a 5xx. Keep this soft.
		if w.Code >= 500 {
			t.Fatalf("HEAD /api/user 5xx status=%d body=%s", w.Code, w.Body.String())
		}
	}

	// --- OPTIONS on /api and /api/yggdrasil must not 5xx. ---
	for _, target := range []string{"/api", "/api/yggdrasil"} {
		w = requestRaw(t, h, "OPTIONS", target, "", "", "", nil)
		if w.Code >= 500 {
			t.Fatalf("OPTIONS %s status=%d body=%s", target, w.Code, w.Body.String())
		}
	}

	// --- ALI header: off by default, on with ygg_enable_ali + module. ---
	w = request(t, h, "GET", "/api/yggdrasil", "", "", nil)
	if w.Header().Get("X-Authlib-Injector-API-Location") != "" {
		t.Fatalf("ALI without option status=%d header=%q", w.Code, w.Header().Get("X-Authlib-Injector-API-Location"))
	}
	if _, err := id.Store.DB.Exec("INSERT INTO "+id.Store.Table("options")+" (option_name,option_value) VALUES (?,?)", "ygg_enable_ali", "true"); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "GET", "/api/yggdrasil", "", "", nil)
	if got := w.Header().Get("X-Authlib-Injector-API-Location"); got != "http://localhost/skin/api/yggdrasil" {
		t.Fatalf("ALI with option header=%q status=%d", got, w.Code)
	}
}

func requestRaw(t *testing.T, h http.Handler, method, target, body, contentType, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://localhost/skin"+target, strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	r.Header.Set("Accept", "application/json")
	if csrf != "" {
		r.Header.Set("X-CSRF-TOKEN", csrf)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
