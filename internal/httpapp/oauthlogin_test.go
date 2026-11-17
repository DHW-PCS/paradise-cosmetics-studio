package httpapp

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/config"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/oauthserver"
	"paradise-cosmetics-studio/internal/site"
	"paradise-cosmetics-studio/internal/testsupport"
	"paradise-cosmetics-studio/internal/yggdrasil"
)

var oauthLoginPaths = []string{"/auth/login/github", "/auth/login/github/callback"}

func oauthLoginInstall(t *testing.T, id *identity.Service) {
	t.Helper()
	if _, err := id.Store.DB.Exec("UPDATE "+id.Store.Table("options")+" SET option_value=? WHERE option_name='go_module_installations'", `[{"name":"oauth","version":"1.0.6"}]`); err != nil {
		t.Fatal(err)
	}
}

func oauthLoginManage(t *testing.T, h http.Handler, action string, cookie *http.Cookie, csrf string) {
	t.Helper()
	w := request(t, h, "POST", "/admin/plugins/manage", `{"action":"`+action+`","name":"oauth"}`, csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("%s oauth response status=%d body=%s", action, w.Code, w.Body.String())
	}
}

func oauthLoginEnable(t *testing.T, h http.Handler, id *identity.Service) (*http.Cookie, string) {
	t.Helper()
	oauthLoginInstall(t, id)
	admin, csrf := credentials(t, h, true)
	oauthLoginManage(t, h, "enable", admin, csrf)
	return admin, csrf
}

func oauthLoginCount(t *testing.T, id *identity.Service, query string, args ...any) int {
	t.Helper()
	var count int
	if err := id.Store.DB.QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func oauthLoginNotFoundHTML(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != 404 {
		t.Fatalf("status=%d body=%.200s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("404 content-type=%q, want HTML", ct)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Fatalf("404 location=%q, want no redirect", loc)
	}
}

func TestOAuthLoginUnknownDriver404(t *testing.T) {
	h, id := appFixture(t)
	_, _ = oauthLoginEnable(t, h, id)
	for _, path := range oauthLoginPaths {
		oauthLoginNotFoundHTML(t, request(t, h, "GET", path, "", "", nil))
	}
	// A driver name recorded only in oauth_clients.provider is not a
	// configured provider: the entry stays unknown.
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("oauth_clients") + " SET provider='github' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	oauthLoginNotFoundHTML(t, request(t, h, "GET", "/auth/login/github", "", "", nil))
}

func TestOAuthLoginNoSideEffects(t *testing.T) {
	h, id := appFixture(t)
	_, _ = oauthLoginEnable(t, h, id)
	code := strings.Repeat("b", 32)
	if _, err := id.Store.DB.Exec("INSERT INTO "+id.Store.Table("invitation_codes")+" (code,generated_at) VALUES (?,NOW(6))", code); err != nil {
		t.Fatal(err)
	}
	users := oauthLoginCount(t, id, "SELECT COUNT(*) FROM "+id.Store.Table("users"))
	authSessions := oauthLoginCount(t, id, "SELECT COUNT(*) FROM "+id.Store.Table("go_web_sessions")+" WHERE user_uid IS NOT NULL")
	remember := oauthLoginCount(t, id, "SELECT COUNT(*) FROM "+id.Store.Table("go_remember_tokens"))
	for _, path := range oauthLoginPaths {
		w := request(t, h, "GET", path, "", "", nil)
		oauthLoginNotFoundHTML(t, w)
		if loc := w.Header().Get("Location"); strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
			t.Fatalf("external redirect %q", loc)
		}
	}
	if got := oauthLoginCount(t, id, "SELECT COUNT(*) FROM "+id.Store.Table("users")); got != users {
		t.Fatalf("users=%d want %d: external login created a user", got, users)
	}
	if got := oauthLoginCount(t, id, "SELECT COUNT(*) FROM "+id.Store.Table("go_web_sessions")+" WHERE user_uid IS NOT NULL"); got != authSessions {
		t.Fatalf("authenticated sessions=%d want %d: external login issued a credential", got, authSessions)
	}
	if got := oauthLoginCount(t, id, "SELECT COUNT(*) FROM "+id.Store.Table("go_remember_tokens")); got != remember {
		t.Fatalf("remember tokens=%d want %d", got, remember)
	}
	var usedBy int64
	if err := id.Store.DB.QueryRow("SELECT used_by FROM "+id.Store.Table("invitation_codes")+" WHERE code=?", code).Scan(&usedBy); err != nil || usedBy != 0 {
		t.Fatalf("invitation used_by=%d err=%v: external login consumed a code", usedBy, err)
	}
}

func TestOAuthLoginEnabledLoggedInRedirects(t *testing.T) {
	h, id := appFixture(t)
	user, _ := credentials(t, h, false)
	// Uninstalled: a logged-in user still gets 404, proving the handler
	// (not a missing route) decides once the module is served.
	for _, path := range oauthLoginPaths {
		oauthLoginNotFoundHTML(t, request(t, h, "GET", path, "", "", user))
	}
	// Installed but disabled: same 404.
	oauthLoginInstall(t, id)
	for _, path := range oauthLoginPaths {
		oauthLoginNotFoundHTML(t, request(t, h, "GET", path, "", "", user))
	}
	admin, csrf := credentials(t, h, true)
	oauthLoginManage(t, h, "enable", admin, csrf)
	// Enabled and logged in: guest semantics redirect to the user center.
	// The fixture deploys under /skin, so the redirect must carry it.
	for _, path := range oauthLoginPaths {
		w := request(t, h, "GET", path, "", "", user)
		if w.Code != 302 || w.Header().Get("Location") != "http://localhost/skin/user" {
			t.Fatalf("%s status=%d location=%q", path, w.Code, w.Header().Get("Location"))
		}
	}
	// Disabled again: 404 returns.
	oauthLoginManage(t, h, "disable", admin, csrf)
	for _, path := range oauthLoginPaths {
		oauthLoginNotFoundHTML(t, request(t, h, "GET", path, "", "", user))
	}
	// Uninstalled again: 404 returns.
	oauthLoginManage(t, h, "delete", admin, csrf)
	for _, path := range oauthLoginPaths {
		oauthLoginNotFoundHTML(t, request(t, h, "GET", path, "", "", user))
	}
}

func TestOAuthLoginEmptyProviderUI(t *testing.T) {
	h, id := appFixture(t)
	// Even with the module installed and enabled, the empty provider set
	// renders no external-login button on the login/register pages.
	_, _ = oauthLoginEnable(t, h, id)
	for _, path := range []string{"/auth/login", "/auth/register"} {
		w := request(t, h, "GET", path, "", "", nil)
		if w.Code != 200 {
			t.Fatalf("%s status=%d", path, w.Code)
		}
		body := w.Body.String()
		if strings.Contains(body, "/auth/login/") {
			t.Fatalf("%s renders an external-login entry with no provider configured", path)
		}
	}
}

// oauthLoginRootFixture builds a second router through the same composition
// root and synthetic service assembly as appFixture, but deployed at the
// root: BaseURL has no path prefix at all. The shared appFixture is left
// untouched; the /skin tests above remain the subpath deployment.
func oauthLoginRootFixture(t *testing.T) (http.Handler, *identity.Service) {
	t.Helper()
	store, id := testsupport.Database(t, "site-")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oauth, err := oauthserver.New(oauthserver.Config{Store: store, Identity: id, PrivateKey: key, Secret: []byte("synthetic-m2-secret-at-least-32-bytes"), Issuer: "http://localhost", Scopes: oauthserver.DefaultScopes, AccessLifetime: time.Hour, RefreshLifetime: 24 * time.Hour, CodeLifetime: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if err = oauth.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = oauthserver.MigrateConsents(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err = oauthserver.MigrateAPIDigest(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	view := &site.Service{Store: store, Identity: id, Location: time.UTC, Modules: testsupport.Modules(store, id)}
	handler, err := New(config.Config{BaseURL: "http://localhost", Locale: "zh_CN", FallbackLocale: "en", RememberLifetime: 400 * 24 * time.Hour, TexturesDir: t.TempDir()}, id, view, oauth, yggdrasil.New(store, id, nil, []byte("synthetic-yggdrasil-hs256-key-32b"), false, id.Now), "m4-05-test")
	if err != nil {
		t.Fatal(err)
	}
	return handler, id
}

func oauthLoginRootRequest(t *testing.T, h http.Handler, method, target, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://localhost"+target, strings.NewReader(body))
	r.Header.Set("Accept", "application/json")
	if body != "" {
		r.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
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

func oauthLoginRootCredentials(t *testing.T, h http.Handler, admin bool) (*http.Cookie, string) {
	t.Helper()
	w := oauthLoginRootRequest(t, h, "GET", "/auth/login", "", "", nil)
	match := csrfPattern.FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatalf("missing CSRF status=%d", w.Code)
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	email := "user@example.invalid"
	if admin {
		email = "admin@example.invalid"
	}
	w = oauthLoginRootRequest(t, h, "POST", "/auth/login", `{"identification":"`+email+`","password":"original-password"}`, match[1], cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("login failed status=%d", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	w = oauthLoginRootRequest(t, h, "GET", "/user", "", "", cookie)
	match = csrfPattern.FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatal("missing authenticated CSRF")
	}
	return cookie, match[1]
}

func oauthLoginRootManage(t *testing.T, h http.Handler, action string, cookie *http.Cookie, csrf string) {
	t.Helper()
	w := oauthLoginRootRequest(t, h, "POST", "/admin/plugins/manage", `{"action":"`+action+`","name":"oauth"}`, csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("%s oauth response status=%d body=%s", action, w.Code, w.Body.String())
	}
}

func oauthLoginRootEnable(t *testing.T, h http.Handler, id *identity.Service) (*http.Cookie, string) {
	t.Helper()
	oauthLoginInstall(t, id)
	admin, csrf := oauthLoginRootCredentials(t, h, true)
	oauthLoginRootManage(t, h, "enable", admin, csrf)
	return admin, csrf
}

func TestOAuthLoginRootDeployment(t *testing.T) {
	h, id := oauthLoginRootFixture(t)
	user, _ := oauthLoginRootCredentials(t, h, false)
	// Uninstalled at the root: a logged-in user gets 404.
	for _, path := range oauthLoginPaths {
		oauthLoginNotFoundHTML(t, oauthLoginRootRequest(t, h, "GET", path, "", "", user))
	}
	admin, csrf := oauthLoginRootEnable(t, h, id)
	// Enabled at the root: anonymous unknown drivers are HTML 404, and a
	// logged-in user redirects to the root user center, with no /skin.
	for _, path := range oauthLoginPaths {
		oauthLoginNotFoundHTML(t, oauthLoginRootRequest(t, h, "GET", path, "", "", nil))
	}
	for _, path := range oauthLoginPaths {
		w := oauthLoginRootRequest(t, h, "GET", path, "", "", user)
		if w.Code != 302 || w.Header().Get("Location") != "http://localhost/user" {
			t.Fatalf("%s status=%d location=%q", path, w.Code, w.Header().Get("Location"))
		}
	}
	// Disabled and then uninstalled at the root: 404 returns.
	oauthLoginRootManage(t, h, "disable", admin, csrf)
	for _, path := range oauthLoginPaths {
		oauthLoginNotFoundHTML(t, oauthLoginRootRequest(t, h, "GET", path, "", "", user))
	}
	oauthLoginRootManage(t, h, "delete", admin, csrf)
	for _, path := range oauthLoginPaths {
		oauthLoginNotFoundHTML(t, oauthLoginRootRequest(t, h, "GET", path, "", "", user))
	}
}

func TestOAuthLoginDisabledKeepsCoreOAuthAndAPI(t *testing.T) {
	h, id := coreFixture(t)
	admin, csrf := oauthLoginEnable(t, h, id)
	oauthLoginManage(t, h, "disable", admin, csrf)
	user, _ := credentials(t, h, false)
	oauthLoginNotFoundHTML(t, request(t, h, "GET", "/auth/login/github", "", "", user))
	if w := request(t, h, "GET", "/oauth/clients", "", "", user); w.Code != 200 {
		t.Fatalf("core clients status=%d body=%s", w.Code, w.Body.String())
	}
	token := coreToken(t, h, "user@example.invalid", "User.Read")
	if w := coreReq(t, h, "GET", "/api/user", "", bearer(token)); w.Code != 200 || !strings.Contains(w.Body.String(), `"uid":1`) {
		t.Fatalf("core api status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestOAuthLoginStateErrorServerError(t *testing.T) {
	h, id := appFixture(t)
	user, _ := credentials(t, h, false)
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("options") + " SET option_value='poisoned' WHERE option_name='plugins_enabled'"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path   string
		cookie *http.Cookie
	}{
		{"/auth/login/github", nil},
		{"/auth/login/github/callback", user},
	} {
		w := request(t, h, "GET", tc.path, "", "", tc.cookie)
		if w.Code != 503 || !strings.Contains(w.Body.String(), `"code":503`) {
			t.Fatalf("%s status=%d body=%s, want serverError 503", tc.path, w.Code, w.Body.String())
		}
	}
}
