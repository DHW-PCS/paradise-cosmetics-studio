package httpapp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
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

	"blessing-skin-go/internal/admission"
	"blessing-skin-go/internal/config"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/oauthserver"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/testsupport"
)

func appFixture(t *testing.T) (http.Handler, *identity.Service) {
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
	handler, err := New(config.Config{BaseURL: "http://localhost/skin", Locale: "zh_CN", FallbackLocale: "en", RememberLifetime: 400 * 24 * time.Hour}, id, &site.Service{Store: store, Identity: id, Location: time.UTC}, oauth)
	if err != nil {
		t.Fatal(err)
	}
	return handler, id
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
	pattern := regexp.MustCompile(`<script id="blessing-globals" type="application/json">(.*?)</script>`)
	match := pattern.FindSubmatch(w.Body.Bytes())
	if len(match) != 2 || !json.Valid(bytes.TrimSpace(match[1])) {
		t.Fatal("globals is not valid escaped JSON")
	}
}

func TestOriginalInterfaceCopy(t *testing.T) {
	h, _ := appFixture(t)
	w := request(t, h, "GET", "/auth/login?lang=en", "", "", nil)
	for _, text := range []string{"Log In - Blessing Skin", "Log in to manage your skin &amp; players", "Register a new account"} {
		if !strings.Contains(w.Body.String(), text) {
			t.Fatalf("original login copy missing: %s", text)
		}
	}
	cookie, _ := credentials(t, h, false)
	w = request(t, h, "GET", "/user?lang=en", "", "", cookie)
	for _, text := range []string{"Dashboard - Blessing Skin", "Powered with ❤ by", "Blessing Skin Server", "All rights reserved.", "中文 (简体)", "中文 (正體)", "Русский язык", "Announcement", "What is score?", "Welcome to Blessing Skin {version}!"} {
		if !strings.Contains(w.Body.String(), text) {
			t.Fatalf("original interface copy missing: %s", text)
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
	if !strings.Contains(w.Body.String(), "Dashboard - Blessing Skin") {
		t.Fatal("account locale replaced browser preference")
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
