package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"blessing-skin-go/internal/legacy/auth"
	"blessing-skin-go/internal/legacy/cache"
	"blessing-skin-go/internal/legacy/laravel"
	"blessing-skin-go/internal/legacy/php"
	"blessing-skin-go/internal/legacy/remember"
	"blessing-skin-go/internal/legacy/revocation"
	"blessing-skin-go/internal/legacy/session"
	"blessing-skin-go/internal/legacy/users"
)

var fixedNow = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

type fakeUsers struct {
	user *users.User
	err  error
}

func (f *fakeUsers) ByUID(context.Context, int64) (*users.User, bool, error) {
	if f.err != nil {
		return nil, false, f.err
	}
	if f.user == nil {
		return nil, false, nil
	}
	return f.user, true, nil
}

func (f *fakeUsers) UpdateRememberToken(context.Context, int64, string) error { return f.err }

type fakeAuth struct{ rememberErr error }

func (f *fakeAuth) Login(context.Context, string, string, bool) (*auth.LoginResult, error) {
	return nil, auth.ErrUnknownUser
}

func (f *fakeAuth) ValidateSession(context.Context, *php.Array) (*auth.Validation, error) {
	return nil, auth.ErrNoSession
}

func (f *fakeAuth) UpgradeLegacy(context.Context, int64) (*revocation.State, error) {
	return nil, auth.ErrLegacyUnverifiable
}

func (f *fakeAuth) RememberState(context.Context, int64, string) (*users.User, *revocation.State, error) {
	if f.rememberErr != nil {
		return nil, nil, f.rememberErr
	}
	return nil, nil, auth.ErrRememberRejected
}

type testEnv struct {
	server *Server
	enc    *laravel.Encrypter
	store  *session.Store
	cache  *cache.Store
	login  string
	auth   *fakeAuth
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	key := []byte("0123456789abcdef0123456789abcdef")
	enc, err := laravel.NewEncrypter(key, "AES-256-CBC")
	if err != nil {
		t.Fatal(err)
	}
	store, err := session.NewStore(t.TempDir(), 120*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	store.Now = func() time.Time { return fixedNow }
	cacheStore, err := cache.NewStore(t.TempDir(), "blessing_skin_cache")
	if err != nil {
		t.Fatal(err)
	}
	cacheStore.Now = func() time.Time { return fixedNow }
	loginKey := laravel.LoginKey("web", laravel.DefaultGuardClass)
	authFake := &fakeAuth{}
	cfg := Config{
		Encrypter: enc,
		Sessions:  store,
		Cache:     cacheStore,
		Auth:      authFake,
		Users:     &fakeUsers{},
		SessionCookie: laravel.CookieAttributes{
			Name: "BS_SESSION", Path: "/", HTTPOnly: true, SameSite: "lax",
			Lifetime: 120 * time.Minute,
		},
		XSRFCookie:       "XSRF-TOKEN",
		RememberCookie:   laravel.RecallerCookieName("web", laravel.DefaultGuardClass),
		RememberLifetime: 2628000 * time.Minute,
		LoginKey:         loginKey,
		Now:              func() time.Time { return fixedNow },
	}
	server, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{server: server, enc: enc, store: store, cache: cacheStore, login: loginKey, auth: authFake}
}

func request(method, path string, body string) *http.Request {
	r := httptest.NewRequest(method, "https://m0.invalid"+path, strings.NewReader(body))
	r.Host = "m0.invalid"
	r.Header.Set("X-Forwarded-Proto", "https")
	if body != "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return r
}

func do(t *testing.T, env *testEnv, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	env.server.ServeHTTP(rec, r)
	return rec
}

func cookieByName(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func sessionID(t *testing.T, env *testEnv, rec *httptest.ResponseRecorder) string {
	t.Helper()
	cookie := cookieByName(t, rec, "BS_SESSION")
	if cookie == nil {
		t.Fatal("missing BS_SESSION cookie")
	}
	plain, err := decryptTestCookie(env, "BS_SESSION", cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if !session.ValidID(plain) {
		t.Fatalf("invalid session id %q", plain)
	}
	return plain
}

func decryptTestCookie(env *testEnv, name, value string) (string, error) {
	plain, err := env.enc.DecryptCookie(name, value)
	if err == nil {
		return plain, nil
	}
	decoded, decodeErr := url.QueryUnescape(value)
	if decodeErr != nil {
		return "", err
	}
	return env.enc.DecryptCookie(name, decoded)
}

func csrfFromCookie(t *testing.T, env *testEnv, rec *httptest.ResponseRecorder) string {
	t.Helper()
	cookie := cookieByName(t, rec, "XSRF-TOKEN")
	if cookie == nil {
		t.Fatal("missing XSRF-TOKEN cookie")
	}
	token, err := decryptTestCookie(env, "XSRF-TOKEN", cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestLoginPageCreatesSessionAndCookies(t *testing.T) {
	env := newTestEnv(t)
	rec := do(t, env, request(http.MethodGet, "/auth/login", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	sessionCookie := cookieByName(t, rec, "BS_SESSION")
	if sessionCookie == nil || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected session cookie: %#v", sessionCookie)
	}
	if sessionCookie.MaxAge != 7200 {
		t.Fatalf("session MaxAge = %d, want 7200", sessionCookie.MaxAge)
	}
	xsrf := cookieByName(t, rec, "XSRF-TOKEN")
	if xsrf == nil || xsrf.HttpOnly {
		t.Fatalf("unexpected XSRF cookie: %#v", xsrf)
	}
	token := csrfFromCookie(t, env, rec)
	id := sessionID(t, env, rec)
	attrs, err := env.store.Read(id)
	if err != nil {
		t.Fatal(err)
	}
	stored, ok := attrs.GetString("_token")
	if !ok || stored != token {
		t.Fatalf("session token = %q, cookie token = %q", stored, token)
	}
	if previous, ok := attrs.GetPath("_previous.url"); !ok || previous != "https://m0.invalid/auth/login" {
		t.Fatalf("_previous.url = %v", previous)
	}
}

func TestExistingSessionIDIsReused(t *testing.T) {
	env := newTestEnv(t)
	first := do(t, env, request(http.MethodGet, "/auth/login", ""))
	id := sessionID(t, env, first)

	next := request(http.MethodGet, "/auth/login", "")
	next.AddCookie(cookieByName(t, first, "BS_SESSION"))
	second := do(t, env, next)
	if got := sessionID(t, env, second); got != id {
		t.Fatalf("session id = %s, want %s", got, id)
	}
}

func TestMissingSessionFileKeepsID(t *testing.T) {
	env := newTestEnv(t)
	id, err := session.NewID()
	if err != nil {
		t.Fatal(err)
	}
	value, err := session.SessionCookieValue(env.enc, "BS_SESSION", id)
	if err != nil {
		t.Fatal(err)
	}
	r := request(http.MethodGet, "/auth/login", "")
	r.AddCookie(&http.Cookie{Name: "BS_SESSION", Value: value})
	rec := do(t, env, r)
	if got := sessionID(t, env, rec); got != id {
		t.Fatalf("session id = %s, want the cookie id %s", got, id)
	}
	if _, err := env.store.Read(id); err != nil {
		t.Fatalf("session was not written: %v", err)
	}
}

func TestExpiredSessionIsReplaced(t *testing.T) {
	env := newTestEnv(t)
	id, _ := session.NewID()
	attrs := session.NewPayload(env.login, 1, "token", "")
	if err := env.store.Write(id, attrs); err != nil {
		t.Fatal(err)
	}
	path := env.store.Dir + "/" + id
	old := fixedNow.Add(-121 * time.Minute)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	value, _ := session.SessionCookieValue(env.enc, "BS_SESSION", id)
	r := request(http.MethodGet, "/auth/login", "")
	r.AddCookie(&http.Cookie{Name: "BS_SESSION", Value: value})
	rec := do(t, env, r)
	if got := sessionID(t, env, rec); got != id {
		t.Fatalf("session id = %s, want %s", got, id)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.ModTime().Before(fixedNow.Add(-time.Minute)) {
		t.Fatal("expired session file was not replaced")
	}
}

func TestCorruptSessionIsTreatedAsEmpty(t *testing.T) {
	env := newTestEnv(t)
	id, _ := session.NewID()
	if err := os.WriteFile(env.store.Dir+"/"+id, []byte("not-serialized"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, _ := session.SessionCookieValue(env.enc, "BS_SESSION", id)
	r := request(http.MethodGet, "/auth/login", "")
	r.AddCookie(&http.Cookie{Name: "BS_SESSION", Value: value})
	rec := do(t, env, r)
	if got := sessionID(t, env, rec); got != id {
		t.Fatalf("session id = %s, want %s", got, id)
	}
}

func TestInvalidCookieGetsNewSession(t *testing.T) {
	env := newTestEnv(t)
	r := request(http.MethodGet, "/auth/login", "")
	r.AddCookie(&http.Cookie{Name: "BS_SESSION", Value: "garbage"})
	rec := do(t, env, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if sessionID(t, env, rec) == "garbage" {
		t.Fatal("invalid cookie was accepted")
	}
}

func TestCSRFRejectsMissingAndWrongTokens(t *testing.T) {
	env := newTestEnv(t)
	page := do(t, env, request(http.MethodGet, "/auth/login", ""))
	sessionCookie := cookieByName(t, page, "BS_SESSION")

	for name, token := range map[string]string{"missing": "", "wrong": "not-the-token"} {
		t.Run(name, func(t *testing.T) {
			body := "identification=x&password=abcdef"
			if token != "" {
				body += "&_token=" + token
			}
			r := request(http.MethodPost, "/auth/login", body)
			r.Header.Set("Accept", "application/json")
			r.AddCookie(sessionCookie)
			rec := do(t, env, r)
			if rec.Code != 419 {
				t.Fatalf("status = %d, want 419", rec.Code)
			}
			// StartSession still persists the session, but VerifyCsrfToken
			// never reaches its cookie callback, so XSRF is absent.
			if cookieByName(t, rec, "BS_SESSION") == nil {
				t.Fatal("419 response did not set the session cookie")
			}
			if cookieByName(t, rec, "XSRF-TOKEN") != nil {
				t.Fatal("419 response set an XSRF cookie")
			}
		})
	}
}

func TestCSRFAcceptsBothHeaderForms(t *testing.T) {
	env := newTestEnv(t)
	page := do(t, env, request(http.MethodGet, "/auth/login", ""))
	sessionCookie := cookieByName(t, page, "BS_SESSION")
	token := csrfFromCookie(t, env, page)
	xsrfCookie := cookieByName(t, page, "XSRF-TOKEN")

	for name, setup := range map[string]func(*http.Request){
		"x-csrf-token": func(r *http.Request) { r.Header.Set("X-CSRF-TOKEN", token) },
		"x-xsrf-token": func(r *http.Request) { r.Header.Set("X-XSRF-TOKEN", xsrfCookie.Value) },
		"_token":       func(r *http.Request) {},
	} {
		t.Run(name, func(t *testing.T) {
			body := "identification=x"
			if name == "_token" {
				body += "&_token=" + token
			}
			r := request(http.MethodPost, "/auth/login", body)
			r.Header.Set("Accept", "application/json")
			r.AddCookie(sessionCookie)
			setup(r)
			rec := do(t, env, r)
			if rec.Code == 419 {
				t.Fatal("valid CSRF token was rejected")
			}
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422 from validation", rec.Code)
			}
		})
	}
}

func TestMalformedXSRFHeaderIsRejected(t *testing.T) {
	env := newTestEnv(t)
	page := do(t, env, request(http.MethodGet, "/auth/login", ""))
	r := request(http.MethodPost, "/auth/login", "identification=x&password=abcdef")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("X-XSRF-TOKEN", "garbage")
	r.AddCookie(cookieByName(t, page, "BS_SESSION"))
	if rec := do(t, env, r); rec.Code != 419 {
		t.Fatalf("status = %d, want 419", rec.Code)
	}
}

func TestValidationErrors(t *testing.T) {
	env := newTestEnv(t)
	page := do(t, env, request(http.MethodGet, "/auth/login", ""))
	sessionCookie := cookieByName(t, page, "BS_SESSION")
	token := csrfFromCookie(t, env, page)

	cases := []struct {
		name   string
		body   string
		fields []string
	}{
		{"missing", "password=abcdef", []string{"identification"}},
		{"short", "identification=x&password=12345", []string{"password"}},
		{"long", "identification=x&password=" + strings.Repeat("a", 33), []string{"password"}},
		{"unicode-short", "identification=x&password=" + strings.Repeat("密", 5), []string{"password"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := request(http.MethodPost, "/auth/login", tc.body+"&_token="+token)
			r.Header.Set("Accept", "application/json")
			r.AddCookie(sessionCookie)
			rec := do(t, env, r)
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422", rec.Code)
			}
			var payload struct {
				Message string              `json:"message"`
				Errors  map[string][]string `json:"errors"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			for _, field := range tc.fields {
				if len(payload.Errors[field]) == 0 {
					t.Fatalf("missing error for %s: %s", field, rec.Body.String())
				}
			}
			if cookieByName(t, rec, "BS_SESSION") == nil || cookieByName(t, rec, "XSRF-TOKEN") == nil {
				t.Fatal("422 response should persist the session and refresh XSRF")
			}
		})
	}
}

func TestUnauthenticatedAuthorize(t *testing.T) {
	env := newTestEnv(t)

	r := request(http.MethodGet, "/user", "")
	rec := do(t, env, r)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://m0.invalid/auth/login" {
		t.Fatalf("redirect = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if cookieByName(t, rec, "BS_SESSION") == nil || cookieByName(t, rec, "XSRF-TOKEN") == nil {
		t.Fatal("rendered auth redirect should persist the session and XSRF")
	}

	r = request(http.MethodGet, "/user", "")
	r.Header.Set("Accept", "application/json")
	rec = do(t, env, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != `{"message":"Unauthenticated."}` {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestLogoutRequiresAuthentication(t *testing.T) {
	env := newTestEnv(t)
	page := do(t, env, request(http.MethodGet, "/auth/login", ""))
	sessionCookie := cookieByName(t, page, "BS_SESSION")
	token := csrfFromCookie(t, env, page)

	r := request(http.MethodPost, "/auth/logout", "_token="+token)
	r.Header.Set("Accept", "application/json")
	r.AddCookie(sessionCookie)
	rec := do(t, env, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if cookieByName(t, rec, "BS_SESSION") == nil {
		t.Fatal("401 response should still persist the session")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	env := newTestEnv(t)
	rec := do(t, env, request(http.MethodGet, "/auth/logout", ""))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestInternalErrorIsLogged(t *testing.T) {
	env := newTestEnv(t)
	env.auth.rememberErr = errors.New("boom")
	value, err := remember.CookieValue(env.enc, env.server.cfg.RememberCookie,
		&remember.Recaller{UID: 1, Token: "token", Password: "hash"})
	if err != nil {
		t.Fatal(err)
	}
	r := request(http.MethodGet, "/user", "")
	r.AddCookie(&http.Cookie{Name: env.server.cfg.RememberCookie, Value: value})
	rec := do(t, env, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
