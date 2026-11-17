package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/legacy/auth"
	"paradise-cosmetics-studio/internal/legacy/cache"
	"paradise-cosmetics-studio/internal/legacy/laravel"
	"paradise-cosmetics-studio/internal/legacy/password"
	"paradise-cosmetics-studio/internal/legacy/php"
	"paradise-cosmetics-studio/internal/legacy/registration"
	"paradise-cosmetics-studio/internal/legacy/remember"
	"paradise-cosmetics-studio/internal/legacy/revocation"
	"paradise-cosmetics-studio/internal/legacy/session"
	"paradise-cosmetics-studio/internal/legacy/testdb"
	"paradise-cosmetics-studio/internal/legacy/users"
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
	return sessionIDFromRecorder(t, env.enc, rec)
}

// sessionIDFromRecorder decrypts the session cookie of a response. It is shared
// with the live-database environment, which has no *testEnv.
func sessionIDFromRecorder(t *testing.T, enc *laravel.Encrypter, rec *httptest.ResponseRecorder) string {
	t.Helper()
	cookie := cookieByName(t, rec, "BS_SESSION")
	if cookie == nil {
		t.Fatal("missing BS_SESSION cookie")
	}
	plain, err := decryptCookieValue(enc, "BS_SESSION", cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if !session.ValidID(plain) {
		t.Fatalf("invalid session id %q", plain)
	}
	return plain
}

func decryptTestCookie(env *testEnv, name, value string) (string, error) {
	return decryptCookieValue(env.enc, name, value)
}

// decryptCookieValue mirrors PHP's cookie decoding: the wire value may be
// URL-encoded, and the encrypter needs the decoded payload.
func decryptCookieValue(enc *laravel.Encrypter, name, value string) (string, error) {
	plain, err := enc.DecryptCookie(name, value)
	if err == nil {
		return plain, nil
	}
	decoded, decodeErr := url.QueryUnescape(value)
	if decodeErr != nil {
		return "", err
	}
	return enc.DecryptCookie(name, decoded)
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

// ---------------------------------------------------------------------------
// R07: remember-me multi-device semantics against a real account database.
// ---------------------------------------------------------------------------

// liveEnv is the web server backed by the real auth service and a disposable
// MySQL database. It is only used by tests that need committed account state;
// the pure-HTTP fixtures above stay database-free.
type liveEnv struct {
	server *Server
	enc    *laravel.Encrypter
	store  *session.Store
	login  string
	svc    *auth.Service
	repo   *users.Repo
	db     *sql.DB
}

func newLiveEnv(t *testing.T) *liveEnv {
	t.Helper()
	db := testdb.Open(t)
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
	hasher, err := password.New("BCRYPT", "")
	if err != nil {
		t.Fatal(err)
	}
	loginKey := laravel.LoginKey("web", laravel.DefaultGuardClass)
	repo := users.New(db, "")
	svc := &auth.Service{
		Repo:     repo,
		Rev:      revocation.New(db, ""),
		Hasher:   hasher,
		Secret:   key,
		LoginKey: loginKey,
	}
	cfg := Config{
		Encrypter: enc,
		Sessions:  store,
		Cache:     cacheStore,
		Auth:      svc,
		Users:     repo,
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
	return &liveEnv{server: server, enc: enc, store: store, login: loginKey, svc: svc, repo: repo, db: db}
}

// seedUser inserts a synthetic web account. permission uses users.* constants.
func (e *liveEnv) seedUser(t *testing.T, email, raw, remember string, permission int) int64 {
	t.Helper()
	hash, err := e.svc.Hasher.Hash(raw)
	if err != nil {
		t.Fatal(err)
	}
	result, err := e.db.Exec(`INSERT INTO users(email,nickname,password,permission,verified,remember_token)
		VALUES(?,?,?,?,1,?)`, email, "Nick", hash, permission, remember)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return uid
}

func readRememberToken(t *testing.T, db *sql.DB, uid int64) string {
	t.Helper()
	var token string
	if err := db.QueryRow("SELECT COALESCE(remember_token,'') FROM users WHERE uid=?", uid).Scan(&token); err != nil {
		t.Fatal(err)
	}
	return token
}

func readPasswordHash(t *testing.T, db *sql.DB, uid int64) string {
	t.Helper()
	var hash string
	if err := db.QueryRow("SELECT password FROM users WHERE uid=?", uid).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	return hash
}

// browser keeps the cookies one independent client would keep. Two browsers
// therefore model two devices with separate sessions and cookie jars.
type browser struct {
	t       *testing.T
	env     *liveEnv
	cookies map[string]*http.Cookie
}

func newBrowser(t *testing.T, env *liveEnv) *browser {
	return &browser{t: t, env: env, cookies: map[string]*http.Cookie{}}
}

func (b *browser) apply(rec *httptest.ResponseRecorder) {
	for _, cookie := range rec.Result().Cookies() {
		expired := cookie.MaxAge < 0 || (!cookie.Expires.IsZero() && cookie.Expires.Before(fixedNow))
		if expired || cookie.Value == "" {
			delete(b.cookies, cookie.Name)
			continue
		}
		b.cookies[cookie.Name] = cookie
	}
}

// do sends one request with the browser's cookies. Non-GET requests carry the
// CSRF token from memory so each case only exercises the behaviour under test.
func (b *browser) do(method, path, body, contentType, accept string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://m0.invalid"+path, strings.NewReader(body))
	r.Host = "m0.invalid"
	r.Header.Set("X-Forwarded-Proto", "https")
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	if xsrf := b.cookies["XSRF-TOKEN"]; method != http.MethodGet && xsrf != nil {
		if token, err := decryptCookieValue(b.env.enc, "XSRF-TOKEN", xsrf.Value); err == nil {
			r.Header.Set("X-CSRF-TOKEN", token)
		}
	}
	for _, cookie := range b.cookies {
		r.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	b.env.server.ServeHTTP(rec, r)
	b.apply(rec)
	return rec
}

func (b *browser) openLogin() *httptest.ResponseRecorder {
	return b.do(http.MethodGet, "/auth/login", "", "", "text/html")
}

func (b *browser) login(identification, raw string, keep bool) *httptest.ResponseRecorder {
	b.openLogin()
	form := url.Values{}
	form.Set("identification", identification)
	form.Set("password", raw)
	if keep {
		form.Set("keep", "1")
	}
	return b.do(http.MethodPost, "/auth/login", form.Encode(),
		"application/x-www-form-urlencoded", "application/json")
}

// dropSession keeps only the recaller, which is what a browser does once the
// session cookie is gone (expired, cleared or another tab's logout).
func (b *browser) dropSession() {
	delete(b.cookies, "BS_SESSION")
	delete(b.cookies, "XSRF-TOKEN")
}

func (b *browser) recaller() *remember.Recaller {
	b.t.Helper()
	cookie := b.cookies[b.env.server.cfg.RememberCookie]
	if cookie == nil {
		b.t.Fatal("missing recaller cookie")
	}
	recaller, err := decodeRecallerCookie(b.env.enc, b.env.server.cfg.RememberCookie, cookie.Value)
	if err != nil {
		b.t.Fatal(err)
	}
	return recaller
}

func decodeRecallerCookie(enc *laravel.Encrypter, name, value string) (*remember.Recaller, error) {
	recaller, err := remember.Cookie(enc, name, value)
	if err == nil {
		return recaller, nil
	}
	decoded, decodeErr := url.QueryUnescape(value)
	if decodeErr != nil {
		return nil, err
	}
	return remember.Cookie(enc, name, decoded)
}

type legacyBody struct {
	Code    int                 `json:"code"`
	Message string              `json:"message"`
	Errors  map[string][]string `json:"errors"`
}

func decodeLegacyBody(t *testing.T, rec *httptest.ResponseRecorder) legacyBody {
	t.Helper()
	var body legacyBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return body
}

// restoreFromRecaller drops the session and asks for a protected page with only
// the recaller cookie, then reports whether the recaller authenticated.
func (b *browser) restoreFromRecaller() (*httptest.ResponseRecorder, bool) {
	b.dropSession()
	rec := b.do(http.MethodGet, "/user", "", "", "application/json")
	return rec, rec.Code == http.StatusOK
}

// TestRememberKeepsMultipleDevices is the R07 acceptance case: two independent
// devices keep-login, and both recallers still restore after their sessions are
// gone. Before the fix the second login rotated the shared token and silently
// logged the first device out.
func TestRememberKeepsMultipleDevices(t *testing.T) {
	env := newLiveEnv(t)
	uid := env.seedUser(t, "keep-a@example.invalid", "password-1", "", users.Normal)

	deviceA := newBrowser(t, env)
	responseA := deviceA.login("keep-a@example.invalid", "password-1", true)
	if body := decodeLegacyBody(t, responseA); body.Code != 0 {
		t.Fatalf("device A login code = %d (%s)", body.Code, body.Message)
	}
	recallerA := deviceA.recaller()
	tokenA := readRememberToken(t, env.db, uid)
	if len(tokenA) != 60 {
		t.Fatalf("remember token length = %d, want 60", len(tokenA))
	}
	if recallerA.Token != tokenA {
		t.Fatalf("device A recaller token does not match the committed token")
	}

	deviceB := newBrowser(t, env)
	responseB := deviceB.login("keep-a@example.invalid", "password-1", true)
	if body := decodeLegacyBody(t, responseB); body.Code != 0 {
		t.Fatalf("device B login code = %d (%s)", body.Code, body.Message)
	}
	recallerB := deviceB.recaller()
	tokenB := readRememberToken(t, env.db, uid)
	if tokenB != tokenA {
		t.Fatalf("second keep login rotated the token: %q -> %q", tokenA, tokenB)
	}
	if recallerB.Token != tokenA {
		t.Fatalf("device B recaller token does not match the shared token")
	}

	// Two independent sessions, not one reused session.
	if sidA, sidB := sessionIDFromRecorder(t, env.enc, responseA), sessionIDFromRecorder(t, env.enc, responseB); sidA == sidB {
		t.Fatalf("both devices share session id %s", sidA)
	}

	for name, device := range map[string]*browser{"A": deviceA, "B": deviceB} {
		rec, restored := device.restoreFromRecaller()
		if !restored {
			t.Fatalf("device %s recaller failed to restore: status %d body %s",
				name, rec.Code, rec.Body.String())
		}
		sid := sessionIDFromRecorder(t, env.enc, rec)
		attrs, err := env.store.Read(sid)
		if err != nil {
			t.Fatalf("device %s session not persisted: %v", name, err)
		}
		if got, ok := attrs.GetInt(env.login); !ok || got != uid {
			t.Fatalf("device %s session login uid = %v, want %d", name, got, uid)
		}
	}
}

// TestLogoutRotatesRememberTokenAndInvalidatesOtherDevices keeps the frozen
// SessionGuard::logout rule: ordinary logout cycles the token, so it signs every
// device out, and reusing the old token must not restore either device.
func TestLogoutRotatesRememberTokenAndInvalidatesOtherDevices(t *testing.T) {
	env := newLiveEnv(t)
	uid := env.seedUser(t, "logout@example.invalid", "password-1", "", users.Normal)

	deviceA := newBrowser(t, env)
	deviceA.login("logout@example.invalid", "password-1", true)
	deviceB := newBrowser(t, env)
	deviceB.login("logout@example.invalid", "password-1", true)
	before := readRememberToken(t, env.db, uid)

	response := deviceA.do(http.MethodPost, "/auth/logout", "",
		"application/x-www-form-urlencoded", "application/json")
	if body := decodeLegacyBody(t, response); body.Code != 0 {
		t.Fatalf("logout code = %d (%s)", body.Code, body.Message)
	}
	after := readRememberToken(t, env.db, uid)
	if after == before {
		t.Fatalf("logout did not rotate the remember token")
	}
	for name, device := range map[string]*browser{"A": deviceA, "B": deviceB} {
		rec, restored := device.restoreFromRecaller()
		if restored {
			t.Fatalf("device %s was restored from a recaller revoked by logout", name)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("device %s status = %d, want 401", name, rec.Code)
		}
	}
}

// TestGlobalRevocationRejectsRecaller keeps the sign-out-everywhere path honest:
// rotating the token and advancing the watermark must reject the old recaller.
func TestGlobalRevocationRejectsRecaller(t *testing.T) {
	env := newLiveEnv(t)
	uid := env.seedUser(t, "revoke@example.invalid", "password-1", "", users.Normal)
	device := newBrowser(t, env)
	device.login("revoke@example.invalid", "password-1", true)
	before := readRememberToken(t, env.db, uid)

	if _, _, err := env.svc.RevokeSessions(context.Background(), uid); err != nil {
		t.Fatalf("revoke sessions: %v", err)
	}
	if after := readRememberToken(t, env.db, uid); after == before {
		t.Fatalf("global revocation did not rotate the remember token")
	}
	rec, restored := device.restoreFromRecaller()
	if restored || rec.Code != http.StatusUnauthorized {
		t.Fatalf("old recaller restored after global revocation: status %d", rec.Code)
	}
}

// TestChangePasswordRejectsRecaller covers the password-change writer: it clears
// the remember token and bumps the watermark, so neither the old session nor the
// old recaller may come back.
func TestChangePasswordRejectsRecaller(t *testing.T) {
	env := newLiveEnv(t)
	uid := env.seedUser(t, "change@example.invalid", "password-1", "", users.Normal)
	device := newBrowser(t, env)
	device.login("change@example.invalid", "password-1", true)
	oldSession := device.cookies["BS_SESSION"]

	tx, err := env.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := registration.ChangePassword(context.Background(), tx, "", uid, "new-password-1", env.svc.Secret); err != nil {
		_ = tx.Rollback()
		t.Fatalf("change password: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if token := readRememberToken(t, env.db, uid); token != "" {
		t.Fatalf("remember token = %q after a password change, want empty", token)
	}

	rec, restored := device.restoreFromRecaller()
	if restored || rec.Code != http.StatusUnauthorized {
		t.Fatalf("old recaller restored after a password change: status %d", rec.Code)
	}
	// The pre-change browser session must not survive either.
	if oldSession != nil {
		device.cookies["BS_SESSION"] = oldSession
		if rec := device.do(http.MethodGet, "/user", "", "", "application/json"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("pre-change session status = %d, want 401", rec.Code)
		}
	}
}

// TestBannedRecallerIsRejected keeps RejectBannedUser's frozen outcome: a valid
// recaller for a banned account reaches the ban response and is not upgraded to
// an allowed session.
func TestBannedRecallerIsRejected(t *testing.T) {
	env := newLiveEnv(t)
	env.seedUser(t, "banned-keep@example.invalid", "password-1", "", users.Banned)
	device := newBrowser(t, env)
	if body := decodeLegacyBody(t, device.login("banned-keep@example.invalid", "password-1", true)); body.Code != 0 {
		t.Fatalf("banned keep login code = %d (%s)", body.Code, body.Message)
	}
	rec, restored := device.restoreFromRecaller()
	if restored {
		t.Fatal("banned recaller restored an authenticated session")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("banned recaller status = %d, want 403", rec.Code)
	}
}

// TestNonKeepLoginDoesNotRotateExistingRecaller keeps the other frozen half: a
// login without keep neither creates nor cycles the token, so an existing
// recaller on another device stays valid.
func TestNonKeepLoginDoesNotRotateExistingRecaller(t *testing.T) {
	env := newLiveEnv(t)
	uid := env.seedUser(t, "nokeep@example.invalid", "password-1", "existing-token", users.Normal)

	device := newBrowser(t, env)
	if body := decodeLegacyBody(t, device.login("nokeep@example.invalid", "password-1", false)); body.Code != 0 {
		t.Fatalf("non-keep login code = %d (%s)", body.Code, body.Message)
	}
	if cookie := device.cookies[env.server.cfg.RememberCookie]; cookie != nil {
		t.Fatal("non-keep login set a recaller cookie")
	}
	if token := readRememberToken(t, env.db, uid); token != "existing-token" {
		t.Fatalf("remember token = %q after a non-keep login", token)
	}

	value, err := remember.CookieValue(env.enc, env.server.cfg.RememberCookie, &remember.Recaller{
		UID: uid, Token: "existing-token", Password: readPasswordHash(t, env.db, uid),
	})
	if err != nil {
		t.Fatal(err)
	}
	old := newBrowser(t, env)
	old.cookies[env.server.cfg.RememberCookie] = &http.Cookie{Name: env.server.cfg.RememberCookie, Value: value}
	if rec, restored := old.restoreFromRecaller(); !restored {
		t.Fatalf("existing recaller stopped working after a non-keep login: status %d", rec.Code)
	}
}

// TestKeepLoginNeedsNoWriteWhenTokenExists proves the fix is conditional rather
// than merely "write the same value again": with a failing users UPDATE trigger,
// a keep login on an existing token still succeeds, while a keep login that must
// create a token fails cleanly without issuing a recaller.
func TestKeepLoginNeedsNoWriteWhenTokenExists(t *testing.T) {
	t.Run("existing token", func(t *testing.T) {
		env := newLiveEnv(t)
		uid := env.seedUser(t, "nowrite@example.invalid", "password-1", "existing-token", users.Normal)
		installUsersUpdateFailure(t, env.db)

		device := newBrowser(t, env)
		response := device.login("nowrite@example.invalid", "password-1", true)
		if body := decodeLegacyBody(t, response); body.Code != 0 {
			t.Fatalf("keep login code = %d (%s); it tried to write the existing token", body.Code, body.Message)
		}
		if got := readRememberToken(t, env.db, uid); got != "existing-token" {
			t.Fatalf("remember token = %q", got)
		}
		if recaller := device.recaller(); recaller.Token != "existing-token" {
			t.Fatalf("issued recaller token = %q", recaller.Token)
		}
	})
	t.Run("missing token", func(t *testing.T) {
		env := newLiveEnv(t)
		uid := env.seedUser(t, "nowrite-empty@example.invalid", "password-1", "", users.Normal)
		installUsersUpdateFailure(t, env.db)

		device := newBrowser(t, env)
		response := device.login("nowrite-empty@example.invalid", "password-1", true)
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 from the failed token write", response.Code)
		}
		if cookie := device.cookies[env.server.cfg.RememberCookie]; cookie != nil {
			t.Fatal("a failed token write still issued a recaller cookie")
		}
		if got := readRememberToken(t, env.db, uid); got != "" {
			t.Fatalf("remember token = %q after a rolled-back login", got)
		}
	})
}

func installUsersUpdateFailure(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`CREATE TRIGGER m1_fail_remember BEFORE UPDATE ON users
		FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'm1 remember write'`); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}
}
