package httpapp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/admission"
	"paradise-cosmetics-studio/internal/config"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/oauthserver"
	"paradise-cosmetics-studio/internal/site"
	"paradise-cosmetics-studio/internal/testsupport"
	"paradise-cosmetics-studio/internal/yggdrasil"
)

func appFixture(t *testing.T) (http.Handler, *identity.Service) {
	return appFixtureWithOptions(t, nil)
}
func appFixtureWithOptions(t *testing.T, options map[string]string) (http.Handler, *identity.Service) {
	t.Helper()
	handler, id, _ := appFixtureWithOptionsAndDir(t, options)
	return handler, id
}

func appFixtureWithOptionsAndDir(t *testing.T, options map[string]string) (http.Handler, *identity.Service, string) {
	t.Helper()
	store, id := testsupport.Database(t, "site-")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oauth, err := oauthserver.New(oauthserver.Config{Store: store, Identity: id, PrivateKey: key, Secret: []byte("synthetic-m2-secret-at-least-32-bytes"), Issuer: "http://localhost/skin", Scopes: oauthserver.DefaultScopes, AccessLifetime: time.Hour, RefreshLifetime: 24 * time.Hour, CodeLifetime: 10 * time.Minute})
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
	texturesDir := t.TempDir()
	view := &site.Service{Store: store, Identity: id, Location: time.UTC, OptionSnapshot: options, Modules: testsupport.Modules(store, id)}
	handler, err := New(config.Config{BaseURL: "http://localhost/skin", Locale: "zh_CN", FallbackLocale: "en", RememberLifetime: 400 * 24 * time.Hour, TexturesDir: texturesDir}, id, view, oauth, yggdrasil.New(store, id, options, []byte("synthetic-yggdrasil-hs256-key-32b"), false, id.Now), "m4-05-test")
	if err != nil {
		t.Fatal(err)
	}
	return handler, id, texturesDir
}

var csrfPattern = regexp.MustCompile(`<meta name="csrf-token" content="([^"]+)">`)

func request(t *testing.T, h http.Handler, method, target, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://localhost/skin"+target, strings.NewReader(body))
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
func credentials(t *testing.T, h http.Handler, admin bool) (*http.Cookie, string) {
	t.Helper()
	w := request(t, h, "GET", "/auth/login", "", "", nil)
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
	w = request(t, h, "POST", "/auth/login", `{"identification":"`+email+`","password":"original-password"}`, match[1], cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("login failed status=%d", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	w = request(t, h, "GET", "/user", "", "", cookie)
	match = csrfPattern.FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatal("missing authenticated CSRF")
	}
	return cookie, match[1]
}

func TestOriginalAccountBrowserSlice(t *testing.T) {
	h, id := appFixture(t)
	for _, raw := range []string{"/skin", "/skin//user"} {
		r := httptest.NewRequest("GET", "http://localhost"+raw, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if !strings.HasPrefix(w.Header().Get("Location"), "/skin/") {
			t.Fatal("canonical redirect escaped deployment subpath")
		}
	}
	old := &http.Cookie{Name: "blessing_skin_session", Value: "legacy-value"}
	if w := request(t, h, "GET", "/user", "", "", old); w.Code != 401 {
		t.Fatal("old cookie accepted")
	}
	cookie, csrf := credentials(t, h, false)
	if w := request(t, h, "GET", "/user/score-info", "", "", cookie); w.Code != 200 || !strings.Contains(w.Body.String(), `"score":71`) {
		t.Fatal("original score missing")
	}
	if w := request(t, h, "GET", "/admin/users", "", "", cookie); w.Code != 403 {
		t.Fatal("ordinary user entered admin")
	}
	if w := request(t, h, "POST", "/auth/logout", `{}`, "wrong", cookie); w.Code != 419 {
		t.Fatal("missing CSRF rejection")
	}
	if w := request(t, h, "PUT", "/user/dark-mode", `{}`, csrf, cookie); w.Code != 204 || w.Body.Len() != 0 {
		t.Fatal("204 serialized a body")
	}
	var dark bool
	if err := id.Store.DB.QueryRow("SELECT is_dark_mode FROM " + id.Store.Table("users") + " WHERE uid=1").Scan(&dark); err != nil || !dark {
		t.Fatal("dark mode was not saved")
	}
	r := httptest.NewRequest("PUT", "http://localhost/skin/user/dark-mode", nil)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-TOKEN", csrf)
	r.AddCookie(cookie)
	empty := httptest.NewRecorder()
	h.ServeHTTP(empty, r)
	if empty.Code != 204 {
		t.Fatal("bodyless JSON PUT rejected")
	}
	if w := request(t, h, "POST", "/auth/login", `{"identification":"user@example.invalid","password":"original-password","keep":false}`, csrf, cookie); w.Code != http.StatusFound {
		t.Fatal("authenticated login bypassed guest guard")
	}
	if w := request(t, h, "POST", "/auth/logout", `{}`, csrf, cookie); w.Code != 200 {
		t.Fatal("logout failed")
	}
	if _, err := id.Session(t.Context(), cookie.Value); err != identity.ErrSession {
		t.Fatal("logout left session active")
	}
	admin, _ := credentials(t, h, true)
	w := request(t, h, "GET", "/admin/users/list?page=1", "", "", admin)
	var data struct {
		Data  []map[string]any `json:"data"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || data.Total != 2 || len(data.Data) != 2 || data.Data[0]["password"] != nil || data.Data[1]["score"] != float64(-10) {
		t.Fatal("admin list changed original data or exposed credentials")
	}
	w = request(t, h, "GET", "/admin/users/list?q=missing", "", "", admin)
	if !strings.Contains(w.Body.String(), `"data":[]`) {
		t.Fatal("empty data is not an array")
	}
}

func TestLoginValidationAndAdmissionResponse(t *testing.T) {
	h, id := appFixture(t)
	w := request(t, h, "GET", "/auth/login", "", "", nil)
	csrf := csrfPattern.FindStringSubmatch(w.Body.String())[1]
	cookie := w.Result().Cookies()[0]
	w = request(t, h, "POST", "/auth/login", `{"identification":null,"password":"short","keep":"true"}`, csrf, cookie)
	if w.Code != 422 || !strings.Contains(w.Body.String(), `"errors"`) {
		t.Fatal("validation shape changed")
	}
	gate, _ := admission.New(admission.Config{Concurrency: 1, Queue: 0, Wait: time.Second})
	id.Admission = gate
	release, err := gate.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	w = request(t, h, "POST", "/auth/login", `{"identification":"user@example.invalid","password":"original-password"}`, csrf, cookie)
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" {
		t.Fatal("overload response is not controlled")
	}
}

func TestInlineJSONAndHTMLAreEscaped(t *testing.T) {
	h, id := appFixture(t)
	_, err := id.Store.DB.Exec("INSERT INTO "+id.Store.Table("options")+" (option_name,option_value) VALUES ('site_name',?)", `</script><img src=x onerror=alert(1)>"中文`)
	if err != nil {
		t.Fatal(err)
	}
	w := request(t, h, "GET", "/auth/login?lang=en", "", "", nil)
	if strings.Contains(w.Body.String(), `</script><img`) {
		t.Fatal("unescaped inline JSON")
	}
	pattern := regexp.MustCompile(`<script id="pcs-globals" type="application/json">(.*?)</script>`)
	match := pattern.FindSubmatch(w.Body.Bytes())
	if len(match) != 2 || !json.Valid(bytes.TrimSpace(match[1])) {
		t.Fatal("globals is not valid escaped JSON")
	}
}

func TestProductInterfaceCopy(t *testing.T) {
	h, _ := appFixture(t)
	w := request(t, h, "GET", "/auth/login?lang=en", "", "", nil)
	for _, text := range []string{"Log In - Paradise Cosmetics Studio", "Log in to manage your skin &amp; players", "Register a new account"} {
		if !strings.Contains(w.Body.String(), text) {
			t.Fatalf("original login copy missing: %s", text)
		}
	}
	cookie, _ := credentials(t, h, false)
	w = request(t, h, "GET", "/user?lang=en", "", "", cookie)
	for _, text := range []string{"Dashboard - Paradise Cosmetics Studio", "Powered with ❤ by", "Paradise Cosmetics Studio", "All rights reserved.", "中文 (简体)", "中文 (正體)", "Русский язык", "Announcement", "What is score?", "Welcome to Paradise Cosmetics Studio {version}!"} {
		if !strings.Contains(w.Body.String(), text) {
			t.Fatalf("product interface copy missing: %s", text)
		}
	}
	if strings.Contains(w.Body.String(), "Blessing Skin Go") || strings.Contains(w.Body.String(), "· MIT") {
		t.Fatal("unapproved interface branding")
	}
	w = request(t, h, "GET", "/auth/login?lang=en", "", "", nil)
	csrf := csrfPattern.FindStringSubmatch(w.Body.String())[1]
	guest := w.Result().Cookies()[0]
	w = request(t, h, "POST", "/auth/login?lang=en", `{"identification":"user@example.invalid","password":"wrong-password"}`, csrf, guest)
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["message"] != "Wrong password." {
		t.Fatal("original login failure copy changed")
	}
}

func TestOriginalLocaleSelectionAndNotFoundCopy(t *testing.T) {
	h, id := appFixture(t)
	for target, want := range map[string]string{"/auth/login?lang=ru": "Вход", "/auth/login?lang=de_DE": "Log In", "/auth/login?lang=zh_HANS_CN": "登录"} {
		w := request(t, h, "GET", target, "", "", nil)
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("locale alias/config changed: %s", target)
		}
	}
	_, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET locale='zh_CN' WHERE uid=1")
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := credentials(t, h, false)
	r := httptest.NewRequest("GET", "http://localhost/skin/user", nil)
	r.AddCookie(cookie)
	r.AddCookie(&http.Cookie{Name: "locale", Value: "en"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "仪表盘 - Paradise Cosmetics Studio") {
		t.Fatal("authenticated account locale did not override browser preference")
	}
	w = request(t, h, "GET", "/missing?lang=zh_CN", "", "", nil)
	if w.Code != 404 || !strings.Contains(w.Body.String(), "这里什么都没有哦") || strings.Contains(w.Body.String(), "404 page not found") {
		t.Fatal("not-found copy changed")
	}
}

// TestBrowserPreview is an opt-in manual acceptance fixture. It owns and cleans
// up its synthetic database and listener when the local stop file is created.
func TestBrowserPreview(t *testing.T) {
	stopFile := os.Getenv("M2_BROWSER_STOP_FILE")
	if stopFile == "" {
		t.Skip("manual browser fixture not requested")
	}
	h, id := appFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + listener.Addr().String()
	// Preserve the subpath while using the dynamically assigned local origin.
	httpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := httptest.NewRecorder()
		h.ServeHTTP(recorder, r)
		for key, values := range recorder.Header() {
			for _, value := range values {
				w.Header().Add(key, strings.ReplaceAll(value, "http://localhost", base))
			}
		}
		w.WriteHeader(recorder.Code)
		_, _ = io.WriteString(w, strings.ReplaceAll(recorder.Body.String(), "http://localhost", base))
	})
	server := httptest.NewUnstartedServer(httpHandler)
	server.Listener = listener
	server.Start()
	defer server.Close()
	_ = id
	t.Logf("preview_url=%s/skin/auth/login", base)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if _, err = os.Stat(stopFile); err == nil {
			return
		}
		select {
		case <-t.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

func TestOriginalForbiddenPageCopy(t *testing.T) {
	h, _ := appFixture(t)
	cookie, _ := credentials(t, h, false)
	for _, tc := range []struct{ locale, want string }{{"zh_CN", "您无权访问此页面。"}, {"en", "You have no permission to access this page."}} {
		r := httptest.NewRequest("GET", "http://localhost/skin/admin/users?lang="+tc.locale, nil)
		r.Header.Set("Accept", "text/html")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := tc.want
		if w.Code != 403 || !strings.Contains(w.Body.String(), want) {
			t.Fatalf("original %s forbidden copy missing", tc.locale)
		}
	}
	w := request(t, h, "GET", "/admin/users?lang=en", "", "", cookie)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "Only admins are permitted to access this page.") {
		t.Fatalf("JSON forbidden contract changed: %s", w.Body.String())
	}
}

func TestAccountPagesAndCAPTCHALoginFailures(t *testing.T) {
	h, id := appFixture(t)
	w := request(t, h, "GET", "/auth/login", "", "", nil)
	match := csrfPattern.FindStringSubmatch(w.Body.String())
	var guest *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == sessionCookie {
			guest = cookie
		}
	}
	if guest == nil || len(match) != 2 {
		t.Fatal("guest missing")
	}
	csrf := match[1]
	w = request(t, h, "POST", "/auth/login", `{"identification":"missing@example.invalid","password":"wrong-password"}`, csrf, guest)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":2`) {
		t.Fatal("missing account response changed")
	}
	for range 4 {
		w = request(t, h, "POST", "/auth/login", `{"identification":"user@example.invalid","password":"wrong-password"}`, csrf, guest)
		if w.Code != 200 {
			t.Fatal("login failure did not retain original response")
		}
	}
	if !strings.Contains(w.Body.String(), `"login_fails":4`) {
		t.Fatal("login_fails absent")
	}
	w = request(t, h, "GET", "/auth/login", "", "", guest)
	if !strings.Contains(w.Body.String(), `"tooManyFails":true`) {
		t.Fatal("page did not require CAPTCHA")
	}
	w = request(t, h, "POST", "/auth/login", `{"identification":"user@example.invalid","password":"original-password"}`, csrf, guest)
	if w.Code != 422 || !strings.Contains(w.Body.String(), `"captcha"`) {
		t.Fatal("server CAPTCHA not enforced")
	}
	if _, err := id.Store.DB.Exec("INSERT INTO "+id.Store.Table("go_captchas")+" (session_digest,answer_digest,expires_at) VALUES (?,?,?)", identity.Digest(guest.Value), identity.Digest("abcde"), time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "POST", "/auth/login", `{"identification":"user@example.invalid","password":"original-password","captcha":"ABCDE"}`, csrf, guest)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatal("valid CAPTCHA rejected")
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == sessionCookie {
			guest = cookie
		}
	}
	w = request(t, h, "GET", "/user/profile", "", "", guest)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `id="change-password"`) || !strings.Contains(w.Body.String(), `id="change-email"`) {
		t.Fatal("profile controls missing")
	}
	w = request(t, h, "GET", "/", "", "", guest)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `splash-head`) {
		t.Fatal("landing page missing")
	}
	w = request(t, h, "GET", "/auth/reset/1?signature=old-php-signature", "", "", nil)
	if w.Code != 403 {
		t.Fatal("old reset URL accepted")
	}
}

func TestEmptyEmailBindingPrecedesAdminAndKeepsUID(t *testing.T) {
	h, id := appFixture(t)
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET email='' WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	b, err := id.Login(t.Context(), "PlayerOne", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: sessionCookie, Value: b.Token}
	w := request(t, h, "GET", "/admin/users", "", "", cookie)
	if w.Code != 302 || w.Header().Get("Location") != "http://localhost/skin/auth/bind" {
		t.Fatal("empty email middleware order changed")
	}
	w = request(t, h, "GET", "/auth/bind", "", "", cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `id="login-form"`) {
		t.Fatal("bind form missing")
	}
	w = request(t, h, "POST", "/auth/bind", `{"email":"bound@example.invalid"}`, b.CSRF, cookie)
	if w.Code != 302 {
		t.Fatal("bind failed")
	}
	var uid int64
	if err = id.Store.DB.QueryRow("SELECT uid FROM " + id.Store.Table("users") + " WHERE email='bound@example.invalid'").Scan(&uid); err != nil || uid != 1 {
		t.Fatal("bind changed account identity")
	}
}

func TestInstalledOptionsHeadFootAndAccountTemplates(t *testing.T) {
	options := testsupport.InstalledOptions(t)
	options["custom_css"] = "<div>body { color: red; }</div>"
	options["custom_js"] = "<script>window.installedFixture = true;</script>"
	options["meta_extras"] = `<meta name="fixture" content="installed"><script>ignoredTag()</script>`
	h, _ := appFixtureWithOptions(t, options)
	cookie, _ := credentials(t, h, false)
	w := request(t, h, "GET", "/user?lang=en", "", "", cookie)
	for _, text := range []string{"Welcome to Blessing Skin 6.0.2!", `name="theme-color" content="#17a2b8"`, `rel="preconnect"`, `rel="shortcut icon"`, "body { color: red; }", "window.installedFixture = true;", `name="fixture" content="installed"`, `class="pcs-avatar"`} {
		if !strings.Contains(w.Body.String(), text) {
			t.Fatalf("installed option/template slot missing: %s", text)
		}
	}
	if strings.Contains(w.Body.String(), "{version}") || strings.Contains(w.Body.String(), "{year}") || strings.Contains(w.Body.String(), "<script>ignoredTag()") {
		t.Fatal("installation or tag filtering changed")
	}
	w = request(t, h, "GET", "/auth/register?lang=en", "", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Welcome to "+options["site_name"]+"!") || !strings.Contains(w.Body.String(), `"player":true`) {
		t.Fatal("registration form contract missing")
	}
}

func TestHTMLBindErrorsRedirectAndFlashOnce(t *testing.T) {
	h, id := appFixture(t)
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET email='' WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	b, err := id.Login(t.Context(), "PlayerOne", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	send := func(method, target, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://localhost/skin"+target, strings.NewReader(body))
		r.Header.Set("Accept", "text/html")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: b.Token})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := send("POST", "/auth/bind?lang=en", "email=invalid&_token="+b.CSRF)
	if w.Code != 302 || w.Header().Get("Location") != "http://localhost/skin/auth/bind?lang=en" {
		t.Fatal("HTML validation lost redirect")
	}
	w = send("GET", "/auth/bind?lang=en", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "alert-warning") || !strings.Contains(w.Body.String(), "valid email") {
		t.Fatal("form error missing")
	}
	w = send("GET", "/auth/bind?lang=en", "")
	if strings.Contains(w.Body.String(), "alert-warning") {
		t.Fatal("form error was not consumed")
	}
}

func TestAuthenticatedLanguagePreferencePersistsAndPrecedesCookie(t *testing.T) {
	h, id := appFixture(t)
	cookie, csrf := credentials(t, h, false)
	w := request(t, h, "GET", "/user?lang=zh_TW", "", "", cookie)
	if w.Code != 200 {
		t.Fatal("language link failed")
	}
	var locale sql.NullString
	if err := id.Store.DB.QueryRow("SELECT locale FROM " + id.Store.Table("users") + " WHERE uid=1").Scan(&locale); err != nil || !locale.Valid || locale.String != "zh_TW" {
		t.Fatal("language preference not persisted", err)
	}
	r := httptest.NewRequest("GET", "http://localhost/skin/user", nil)
	r.Header.Set("Accept-Language", "en")
	r.AddCookie(cookie)
	r.AddCookie(&http.Cookie{Name: "locale", Value: "zh_CN"})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `lang="zh-TW"`) {
		t.Fatal("account preference did not precede cookie/header")
	}
	w = request(t, h, "GET", "/user?lang=", "", "", cookie)
	if err := id.Store.DB.QueryRow("SELECT locale FROM " + id.Store.Table("users") + " WHERE uid=1").Scan(&locale); err != nil || locale.Valid {
		t.Fatal("empty language did not clear nullable preference", err)
	}
	if w := request(t, h, "PUT", "/user/dark-mode", `{}`, csrf, cookie); w.Code != 204 {
		t.Fatal("language update revoked unrelated credential")
	}
}

func TestRegistrationPlayerNameFailureUsesOriginalMessage(t *testing.T) {
	h, _ := appFixture(t)
	w := request(t, h, "GET", "/auth/register?lang=en", "", "", nil)
	csrf := csrfPattern.FindStringSubmatch(w.Body.String())
	var guest *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == sessionCookie {
			guest = cookie
		}
	}
	if len(csrf) != 2 || guest == nil {
		t.Fatal("registration guest missing")
	}
	w = request(t, h, "POST", "/auth/register?lang=en", `{"email":"new@example.invalid","password":"new-password","player_name":"bad name"}`, csrf[1], guest)
	if w.Code != 422 || !strings.Contains(w.Body.String(), "Player name may only contains letters, numbers and underscores.") {
		t.Fatal("original player-name rule message missing")
	}
}

// TestServiceWorkerRoute guards the frozen registration target: the built
// worker is served unchanged from the assets manifest with no-cache headers.
func TestServiceWorkerRoute(t *testing.T) {
	h, _ := appFixture(t)
	w := request(t, h, "GET", "/sw.js", "", "", nil)
	if w.Code != 200 {
		t.Fatalf("sw.js status=%d", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("sw.js cache-control=%q", w.Header().Get("Cache-Control"))
	}
	if !strings.Contains(w.Body.String(), "registerRoute") {
		t.Fatalf("sw.js body does not look like the built worker: %.120s", w.Body.String())
	}
	// The registration URL must keep working with the frozen query string too.
	if q := request(t, h, "GET", "/sw.js?go-m2", "", "", nil); q.Code != 200 || q.Body.String() != w.Body.String() {
		t.Fatalf("sw.js with query status=%d", q.Code)
	}
}
