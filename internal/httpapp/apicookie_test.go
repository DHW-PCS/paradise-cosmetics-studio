// Slice-B HTTP checks: API cookie refresh/rotation/CSRF and the consent
// handler wiring, against the real fixture application.
package httpapp

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"blessing-skin-go/internal/config"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/oauthserver"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/testsupport"
	"blessing-skin-go/web"
)

func migrateSliceB(t *testing.T, id *identity.Service) {
	t.Helper()
	if err := oauthserver.MigrateConsents(t.Context(), id.Store); err != nil {
		t.Fatal(err)
	}
	if err := oauthserver.MigrateAPIDigest(t.Context(), id.Store); err != nil {
		t.Fatal(err)
	}
}

func consentTestServer(t *testing.T, id *identity.Service) *oauthserver.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server, err := oauthserver.New(oauthserver.Config{Store: id.Store, Identity: id, PrivateKey: key, Secret: []byte("synthetic-slice-b-secret-at-least-32bytes"), Issuer: "http://localhost/skin", Scopes: oauthserver.DefaultScopes, AccessLifetime: time.Hour, RefreshLifetime: 24 * time.Hour, CodeLifetime: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

// sliceApp builds a minimal App carrying the fixture identity service so
// handlers run without relying on Lead's route registration.
//
// N1: the production composition root (New, app.go) always supplies a
// non-nil site service, and the consent handler dereferences its
// head/foot hooks unconditionally (consent.go). This fixture must
// therefore supply the same real site construction appFixture uses
// (site.Service over the fixture store), not a nil site. No product
// nil-guard is added for this incomplete-fixture case.
func sliceApp(t *testing.T, id *identity.Service, server *oauthserver.Server) *App {
	t.Helper()
	assets, err := web.Load()
	if err != nil {
		t.Fatal(err)
	}
	view := &site.Service{Store: id.Store, Identity: id, Location: time.UTC, Modules: testsupport.Modules(id.Store, id)}
	return &App{identity: id, site: view, oauth: server, assets: assets, cfg: config.Config{BaseURL: "http://localhost/skin", FallbackLocale: "en"}}
}

func TestAPICookieRefreshRotatesAndChecksCSRF(t *testing.T) {
	h, id := appFixture(t)
	migrateSliceB(t, id)
	cookie, csrf := credentials(t, h, false)
	b, err := id.Session(t.Context(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	app := sliceApp(t, id, consentTestServer(t, id))

	// Refresh requires CSRF.
	w := app.oauthTokenRefreshRecorder(t, b, "wrong", cookie)
	if w.Code != 419 {
		t.Fatalf("refresh without csrf = %d", w.Code)
	}
	// Refresh issues a fresh opaque secret (never the session token).
	w = app.oauthTokenRefreshRecorder(t, b, csrf, cookie)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "Refreshed." {
		t.Fatalf("refresh = %d %q", w.Code, w.Body.String())
	}
	var api *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == apiCookieName {
			api = c
		}
	}
	if api == nil || api.Value == "" || api.Value == cookie.Value {
		t.Fatalf("api cookie = %+v", api)
	}
	if !api.HttpOnly {
		t.Fatal("api cookie not HttpOnly")
	}
	// The secret resolves only with matching CSRF (including on reads).
	if _, err := id.ValidateAPI(t.Context(), api.Value, csrf); err != nil {
		t.Fatalf("validate api: %v", err)
	}
	if _, err := id.ValidateAPI(t.Context(), api.Value, "wrong"); !errors.Is(err, identity.ErrSession) {
		t.Fatalf("api csrf bypass: %v", err)
	}
	// Rotation invalidates the earlier secret immediately.
	w = app.oauthTokenRefreshRecorder(t, b, csrf, cookie)
	if w.Code != 200 {
		t.Fatalf("second refresh = %d", w.Code)
	}
	var rotated *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == apiCookieName {
			rotated = c
		}
	}
	if rotated == nil || rotated.Value == api.Value {
		t.Fatal("rotation did not replace the secret")
	}
	if _, err := id.ValidateAPI(t.Context(), api.Value, csrf); !errors.Is(err, identity.ErrSession) {
		t.Fatalf("rotated secret accepted: %v", err)
	}
	// Legacy PHP cookie values are never accepted as API cookies.
	if _, err := id.ValidateAPI(t.Context(), "legacy-php-cookie-value", csrf); !errors.Is(err, identity.ErrSession) {
		t.Fatalf("legacy cookie accepted: %v", err)
	}
	// Explicit Bearer precedence helper: a bearer header must never fall
	// through to the cookie path.
	bearerReq := httptest.NewRequest("GET", "/api/users", nil)
	bearerReq.Header.Set("Authorization", "Bearer invalid")
	bearerReq.AddCookie(api)
	if !HasBearer(bearerReq) {
		t.Fatal("bearer request not detected")
	}
	cookieReq := httptest.NewRequest("GET", "/api/users", nil)
	cookieReq.AddCookie(api)
	if HasBearer(cookieReq) {
		t.Fatal("cookie-only request misdetected as bearer")
	}
	if bearerValue(bearerReq) != "invalid" {
		t.Fatalf("bearer value = %q", bearerValue(bearerReq))
	}
}

func (a *App) oauthTokenRefreshRecorder(t *testing.T, b *identity.BrowserSession, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "http://localhost/skin/oauth/token/refresh", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-TOKEN", csrf)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.oauthTokenRefresh(w, r, b)
	return w
}

// TestConsentHandlersStageApproveDeny drives the consent handlers end to
// end (stage, approve, single consumption, deny) without relying on
// Lead's route registration.
func TestConsentHandlersStageApproveDeny(t *testing.T) {
	h, id := appFixture(t)
	migrateSliceB(t, id)
	cookie, csrf := credentials(t, h, false)
	b, err := id.Session(t.Context(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	server := consentTestServer(t, id)
	app := sliceApp(t, id, server)

	form := url.Values{"response_type": {"code"}, "client_id": {"1"}, "redirect_uri": {"https://client.example.invalid/callback"}, "state": {"synthetic-state"}, "scope": {"Player.Read"}}
	r := httptest.NewRequest("GET", "/oauth/authorize?"+form.Encode(), nil)
	w := httptest.NewRecorder()
	app.oauthAuthorizeShow(w, r, b)
	if w.Code != 200 {
		t.Fatalf("show = %d", w.Code)
	}
	var authToken string
	for _, line := range strings.Split(w.Body.String(), `"`) {
		_ = line
	}
	marker := `name="auth_token" value="`
	body := w.Body.String()
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("show body missing auth_token: %s", body)
	}
	rest := body[idx+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("show body: %s", body)
	}
	authToken = rest[:end]
	if authToken == "" {
		t.Fatal("empty auth_token")
	}
	// Approve requires CSRF, then consumes exactly once.
	w = app.consentPost(t, b, csrf, authToken, true)
	if w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "code=") {
		t.Fatalf("approve = %d %q", w.Code, w.Header().Get("Location"))
	}
	w = app.consentPost(t, b, csrf, authToken, true)
	if w.Code != 400 {
		t.Fatalf("replay approve = %d", w.Code)
	}
	// Deny consumes as well and preserves state.
	r2 := httptest.NewRequest("GET", "/oauth/authorize?"+form.Encode(), nil)
	w2 := httptest.NewRecorder()
	app.oauthAuthorizeShow(w2, r2, b)
	body2 := w2.Body.String()
	idx = strings.Index(body2, marker)
	authToken = body2[idx+len(marker) : strings.Index(body2[idx+len(marker):], `"`)+idx+len(marker)]
	w = app.consentPost(t, b, csrf, authToken, false)
	if w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "error=access_denied") {
		t.Fatalf("deny = %d %q", w.Code, w.Header().Get("Location"))
	}
	// Wrong CSRF is rejected before the service runs.
	w = app.consentPost(t, b, "wrong", authToken, true)
	if w.Code != 419 {
		t.Fatalf("deny replay/csrf = %d", w.Code)
	}
}

func (a *App) consentPost(t *testing.T, b *identity.BrowserSession, csrf, token string, approve bool) *httptest.ResponseRecorder {
	t.Helper()
	target := "/oauth/authorize"
	if approve {
		target = "/oauth/authorize"
	} else {
		target = "/oauth/authorize/deny"
	}
	r := httptest.NewRequest("POST", "http://localhost/skin"+target, strings.NewReader(`{"auth_token":"`+token+`"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-TOKEN", csrf)
	w := httptest.NewRecorder()
	if approve {
		a.oauthAuthorizeApprove(w, r, b)
	} else {
		a.oauthAuthorizeDeny(w, r, b)
	}
	return w
}
