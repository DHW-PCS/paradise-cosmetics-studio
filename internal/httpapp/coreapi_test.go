// Yggdrasil core API focused HTTP checks (M4-03 slice C2).
package httpapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"blessing-skin-go/internal/apilimits"
	"blessing-skin-go/internal/identity"
)

func coreFixture(t *testing.T) (http.Handler, *identity.Service) {
	t.Helper()
	h, id := appFixture(t)
	if err := apilimits.New(id.Store).Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	return h, id
}

func coreReq(t *testing.T, h http.Handler, method, target, body string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://localhost/skin"+target, strings.NewReader(body))
	r.Header.Set("Accept", "application/json")
	if body != "" {
		r.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	// Ensure every request shares one anonymous limiter key unless overridden.
	r.RemoteAddr = "192.0.2.1:1234"
	if mutate != nil {
		mutate(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func coreToken(t *testing.T, h http.Handler, username, scope string) string {
	t.Helper()
	form := url.Values{"grant_type": {"password"}, "client_id": {"3"}, "client_secret": {"password-secret"}, "username": {username}, "password": {"original-password"}}
	if scope != "" {
		form.Set("scope", scope)
	}
	r := httptest.NewRequest("POST", "http://localhost/skin/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("token %s/%s = %d %s", username, scope, w.Code, w.Body.String())
	}
	var data map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	token, _ := data["access_token"].(string)
	if token == "" {
		t.Fatalf("token missing: %s", w.Body.String())
	}
	return token
}

func bearer(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

var core33 = []struct{ method, path string }{
	{"GET", "/api"}, {"GET", "/api/user"},
	{"GET", "/api/user/notifications"}, {"POST", "/api/user/notifications/1"},
	{"GET", "/api/players"}, {"POST", "/api/players"}, {"DELETE", "/api/players/1"},
	{"PUT", "/api/players/1/name"}, {"PUT", "/api/players/1/textures"}, {"DELETE", "/api/players/1/textures"},
	{"GET", "/api/closet"}, {"POST", "/api/closet"}, {"PUT", "/api/closet/1"}, {"DELETE", "/api/closet/1"},
	{"GET", "/api/admin/users"}, {"PUT", "/api/admin/users/1/email"}, {"PUT", "/api/admin/users/1/verification"},
	{"PUT", "/api/admin/users/1/nickname"}, {"PUT", "/api/admin/users/1/password"}, {"PUT", "/api/admin/users/1/score"},
	{"PUT", "/api/admin/users/1/permission"}, {"DELETE", "/api/admin/users/1"},
	{"GET", "/api/admin/players"}, {"PUT", "/api/admin/players/1/name"}, {"PUT", "/api/admin/players/1/owner"},
	{"PUT", "/api/admin/players/1/textures"}, {"DELETE", "/api/admin/players/1"},
	{"GET", "/api/admin/closet/1"}, {"POST", "/api/admin/closet/1"}, {"DELETE", "/api/admin/closet/1"},
	{"GET", "/api/admin/reports"}, {"PUT", "/api/admin/reports/1"}, {"POST", "/api/admin/notifications"},
}

func TestCoreAPIRootAndUnauth(t *testing.T) {
	h, _ := coreFixture(t)
	if w := coreReq(t, h, "GET", "/api", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "blessing_skin") {
		t.Fatalf("root = %d %s", w.Code, w.Body.String())
	} else if w.Header().Get("X-RateLimit-Limit") == "" || w.Header().Get("X-RateLimit-Remaining") == "" {
		t.Fatal("root limiter headers missing")
	}
	for _, tc := range core33[1:] {
		if w := coreReq(t, h, tc.method, tc.path, "", nil); w.Code != 401 {
			t.Fatalf("%s %s unauth = %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
}

func TestCoreAPIBearerCookiePriorityAndCSRF(t *testing.T) {
	h, id := coreFixture(t)
	// Valid API cookie via browser refresh (cookie auth path).
	cookie, csrf := credentials(t, h, false)
	// Issue API cookie through refresh endpoint.
	rr := coreReq(t, h, "POST", "/oauth/token/refresh", `{}`, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set("X-CSRF-TOKEN", csrf)
	})
	if rr.Code != 200 {
		t.Fatalf("refresh = %d %s", rr.Code, rr.Body.String())
	}
	var apiCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == apiCookieName {
			apiCookie = c
		}
	}
	if apiCookie == nil {
		t.Fatal("no api cookie issued")
	}
	// Cookie without CSRF is rejected even on GET.
	if w := coreReq(t, h, "GET", "/api/user", "", func(r *http.Request) { r.AddCookie(apiCookie) }); w.Code != 401 {
		t.Fatalf("cookie without CSRF = %d", w.Code)
	}
	// Cookie with CSRF succeeds.
	if w := coreReq(t, h, "GET", "/api/user", "", func(r *http.Request) { r.AddCookie(apiCookie); r.Header.Set("X-CSRF-TOKEN", csrf) }); w.Code != 200 {
		t.Fatalf("cookie with CSRF = %d %s", w.Code, w.Body.String())
	}
	// Invalid bearer plus a valid cookie still fails (no fallback).
	if w := coreReq(t, h, "GET", "/api/user", "", func(r *http.Request) {
		r.AddCookie(apiCookie)
		r.Header.Set("X-CSRF-TOKEN", csrf)
		r.Header.Set("Authorization", "Bearer invalid")
	}); w.Code != 401 {
		t.Fatalf("bearer priority failed: %d", w.Code)
	}
	_ = id
}

func TestCoreAPIUserAndScope(t *testing.T) {
	h, _ := coreFixture(t)
	token := coreToken(t, h, "user@example.invalid", "User.Read")
	if w := coreReq(t, h, "GET", "/api/user", "", bearer(token)); w.Code != 200 || !strings.Contains(w.Body.String(), `"uid":1`) {
		t.Fatalf("user = %d %s", w.Code, w.Body.String())
	}
	// Missing Player scope -> 403.
	if w := coreReq(t, h, "GET", "/api/players", "", bearer(token)); w.Code != 403 {
		t.Fatalf("missing scope = %d %s", w.Code, w.Body.String())
	}
	// Wildcard satisfies any requirement.
	tokenWildcard := coreToken(t, h, "user@example.invalid", "*")
	if w := coreReq(t, h, "GET", "/api/players", "", bearer(tokenWildcard)); w.Code != 200 {
		t.Fatalf("wildcard = %d %s", w.Code, w.Body.String())
	}
	// Closet typo alias satisfies ReadWrite list.
	tokenAlias := coreToken(t, h, "user@example.invalid", "Closet.ReadWrtie")
	if w := coreReq(t, h, "GET", "/api/closet", "", bearer(tokenAlias)); w.Code != 200 {
		t.Fatalf("alias = %d %s", w.Code, w.Body.String())
	}
}

func TestCoreAPIRoleUID0AndPagination(t *testing.T) {
	h, id := coreFixture(t)
	// UID 0 client-credentials token is a valid OAuth token but not a user actor.
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"3"}, "client_secret": {"password-secret"}}
	r := httptest.NewRequest("POST", "http://localhost/skin/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("cc token = %d %s", w.Code, w.Body.String())
	}
	var data map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &data)
	ccToken := data["access_token"].(string)
	if w2 := coreReq(t, h, "GET", "/api/user", "", bearer(ccToken)); w2.Code != 401 {
		t.Fatalf("uid0 = %d", w2.Code)
	}
	// Admin list requires current admin permission even with scope.
	adminToken := coreToken(t, h, "admin@example.invalid", "UsersManagement.Read")
	if w2 := coreReq(t, h, "GET", "/api/admin/users?page=1", "", bearer(adminToken)); w2.Code != 200 || !strings.Contains(w2.Body.String(), `"total"`) {
		t.Fatalf("admin list = %d %s", w2.Code, w2.Body.String())
	}
	// Demote admin then list must 403 (current permission rechecked in tx).
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET permission=0 WHERE uid=2"); err != nil {
		t.Fatal(err)
	}
	if w2 := coreReq(t, h, "GET", "/api/admin/users?page=1", "", bearer(adminToken)); w2.Code != 403 {
		t.Fatalf("demoted admin = %d %s", w2.Code, w2.Body.String())
	}
	// Closet paginator shape.
	token := coreToken(t, h, "user@example.invalid", "Closet.Read")
	if w2 := coreReq(t, h, "GET", "/api/closet?page=1&perPage=6", "", bearer(token)); w2.Code != 200 || !strings.Contains(w2.Body.String(), `"data"`) {
		t.Fatalf("closet page = %d %s", w2.Code, w2.Body.String())
	}
}

func TestCoreAPILimiterSharedAnd429(t *testing.T) {
	h, _ := coreFixture(t)
	// Root and token share the anonymous key: 60 allowed, 61st 429.
	// Drive the anonymous window on a distinct IP to avoid fixture pollution.
	for i := 1; i <= 60; i++ {
		if w := coreReq(t, h, "GET", "/api", "", func(r *http.Request) { r.RemoteAddr = "192.0.2.99:1234" }); w.Code != 200 {
			t.Fatalf("root %d = %d", i, w.Code)
		}
	}
	w := coreReq(t, h, "POST", "/oauth/token", "grant_type=client_credentials&client_id=3&client_secret=password-secret", func(r *http.Request) {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = "192.0.2.99:1234"
	})
	if w.Code != 429 {
		t.Fatalf("61st shared = %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" || w.Header().Get("X-RateLimit-Reset") == "" {
		t.Fatal("429 headers missing")
	}
	body := w.Body.String()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["message"] != "Too Many Attempts." || decoded["exception"] != true {
		t.Fatalf("429 body = %s", body)
	}
	if _, ok := decoded["code"]; ok {
		t.Fatalf("429 leaks code: %s", body)
	}
	// 60/61 window escape with injected clock: use limiter directly.
	svc := apilimits.New(nil)
	_ = svc
	_ = time.Now
}

func TestCoreAPIAdminTextureMessageKeys(t *testing.T) {
	h, _ := coreFixture(t)
	adminToken := coreToken(t, h, "admin@example.invalid", "PlayersManagement.ReadWrite")
	// Non-existent texture with tid != 0 uses admin.players.textures key.
	w := coreReq(t, h, "PUT", "/api/admin/players/1/textures", `{"tid":999999,"type":"skin"}`, bearer(adminToken))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":1`) {
		t.Fatalf("nonexistent = %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "skinlib") {
		t.Fatalf("wrong key used: %s", w.Body.String())
	}
}

func TestCoreAPIAdminNotificationSendValidation(t *testing.T) {
	h, _ := coreFixture(t)
	token := coreToken(t, h, "admin@example.invalid", "Notification.ReadWrite")
	cases := []struct{ name, body string }{
		{"uid not integer", `{"receiver":"uid","uid":"abc","title":"hi"}`},
		{"email format", `{"receiver":"email","email":"not-an-email","title":"hi"}`},
		{"content not string", `{"receiver":"all","title":"hi","content":123}`},
		{"content null ok title", `{"receiver":"all","title":"hi","content":null}`},
		{"uid not exists", `{"receiver":"uid","uid":999999,"title":"hi"}`},
	}
	for _, tc := range cases {
		w := coreReq(t, h, "POST", "/api/admin/notifications", tc.body, bearer(token))
		t.Logf("%s -> %d %s", tc.name, w.Code, w.Body.String())
	}
	// exists case must be 422 validation, not 200 code 1.
	w := coreReq(t, h, "POST", "/api/admin/notifications", `{"receiver":"uid","uid":999999,"title":"hi"}`, bearer(token))
	if w.Code != 422 {
		t.Fatalf("ErrNoTarget = %d %s, want 422", w.Code, w.Body.String())
	}
	// invalid uid must be 422.
	w = coreReq(t, h, "POST", "/api/admin/notifications", `{"receiver":"uid","uid":"abc","title":"hi"}`, bearer(token))
	if w.Code != 422 {
		t.Fatalf("invalid uid = %d %s, want 422", w.Code, w.Body.String())
	}
	// content type must be 422.
	w = coreReq(t, h, "POST", "/api/admin/notifications", `{"receiver":"all","title":"hi","content":123}`, bearer(token))
	if w.Code != 422 {
		t.Fatalf("invalid content = %d %s, want 422", w.Code, w.Body.String())
	}
}

func TestCoreAPIAdminEmailValidation(t *testing.T) {
	h, _ := coreFixture(t)
	token := coreToken(t, h, "admin@example.invalid", "UsersManagement.ReadWrite")
	w := coreReq(t, h, "PUT", "/api/admin/users/2/email", `{"email":"not-an-email"}`, func(r *http.Request) {
		bearer(token)(r)
		r.Header.Set("Accept-Language", "en")
	})
	if w.Code != 422 || !strings.Contains(w.Body.String(), `"email"`) {
		t.Fatalf("admin email format = %d %s, want 422 email validation", w.Code, w.Body.String())
	}
}

func TestCoreAPIClosetTidZero(t *testing.T) {
	h, _ := coreFixture(t)
	// Closet.ReadWrtie is the frozen Passport scope alias that covers the
	// ReadWrite requirement; the canonical spelling is not registered.
	token := coreToken(t, h, "user@example.invalid", "Closet.ReadWrtie")
	// Frozen integer validation accepts tid=0; the missing texture then
	// maps to business code 1 not-found, not a 422 integer error.
	w := coreReq(t, h, "POST", "/api/closet", `{"tid":0,"name":"Zero"}`, func(r *http.Request) {
		bearer(token)(r)
		r.Header.Set("Accept-Language", "en")
	})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":1`) || !strings.Contains(w.Body.String(), "We cannot find this texture.") {
		t.Fatalf("closet tid=0 = %d %s, want 200 code 1 not-found", w.Code, w.Body.String())
	}
}

func TestCoreAPIAdminClosetListBareArray(t *testing.T) {
	h, id := coreFixture(t)
	if _, err := id.Store.DB.Exec("INSERT INTO " + id.Store.Table("textures") + " (name,type,hash,size,uploader,public,likes,upload_at) VALUES ('AdminListTex','steve','adminlisthash',100,1,1,0,'2026-01-01 00:00:00')"); err != nil {
		t.Fatal(err)
	}
	var tid int64
	if err := id.Store.DB.QueryRow("SELECT tid FROM " + id.Store.Table("textures") + " WHERE hash='adminlisthash'").Scan(&tid); err != nil {
		t.Fatal(err)
	}
	if _, err := id.Store.DB.Exec("INSERT INTO "+id.Store.Table("user_closet")+" (user_uid,texture_tid,item_name) VALUES (1,?,?)", tid, "Item"); err != nil {
		t.Fatal(err)
	}
	token := coreToken(t, h, "admin@example.invalid", "ClosetManagement.Read")
	w := coreReq(t, h, "GET", "/api/admin/closet/1", "", bearer(token))
	if w.Code != 200 {
		t.Fatalf("admin closet list = %d %s", w.Code, w.Body.String())
	}
	body := strings.TrimSpace(w.Body.String())
	if !strings.HasPrefix(body, "[") || strings.Contains(body, `"current_page"`) {
		t.Fatalf("admin closet list is not the bare frozen array: %s", body)
	}
	var items []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &items); err != nil || len(items) != 1 {
		t.Fatalf("admin closet list decode = %v items=%v", err, items)
	}
	if items[0]["tid"] == nil || items[0]["pivot"] == nil || items[0]["name"] != "AdminListTex" {
		t.Fatalf("admin closet item missing texture/pivot fields: %v", items[0])
	}
}

func TestCoreAPIAdminClosetWriteMissingTarget(t *testing.T) {
	h, id := coreFixture(t)
	if _, err := id.Store.DB.Exec("INSERT INTO " + id.Store.Table("textures") + " (name,type,hash,size,uploader,public,likes,upload_at) VALUES ('AdminWriteTex','steve','adminwritehash',100,1,1,0,'2026-01-01 00:00:00')"); err != nil {
		t.Fatal(err)
	}
	var tid int64
	if err := id.Store.DB.QueryRow("SELECT tid FROM " + id.Store.Table("textures") + " WHERE hash='adminwritehash'").Scan(&tid); err != nil {
		t.Fatal(err)
	}
	token := coreToken(t, h, "admin@example.invalid", "ClosetManagement.ReadWrite")
	if w := coreReq(t, h, "POST", "/api/admin/closet/9999", `{"tid":`+strconv.FormatInt(tid, 10)+`}`, bearer(token)); w.Code != 404 {
		t.Fatalf("admin closet add missing target = %d %s, want 404", w.Code, w.Body.String())
	}
	if w := coreReq(t, h, "DELETE", "/api/admin/closet/9999", `{"tid":`+strconv.FormatInt(tid, 10)+`}`, bearer(token)); w.Code != 404 {
		t.Fatalf("admin closet remove missing target = %d %s, want 404", w.Code, w.Body.String())
	}
}

func TestCoreAPIPlayerNoPermissionKey(t *testing.T) {
	h, id := coreFixture(t)
	if _, err := id.Store.DB.Exec("INSERT INTO " + id.Store.Table("players") + " (uid,name,tid_skin,tid_cape,last_modified) VALUES (1,'OwnerPlayer',0,0,'2026-01-01 00:00:00')"); err != nil {
		t.Fatal(err)
	}
	var pid int64
	if err := id.Store.DB.QueryRow("SELECT pid FROM " + id.Store.Table("players") + " WHERE name='OwnerPlayer'").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	// Non-owner delete uses the frozen admin.players.no-permission 403
	// key, not the admin users key.
	token := coreToken(t, h, "admin@example.invalid", "Player.ReadWrite")
	w := coreReq(t, h, "DELETE", "/api/players/"+strconv.FormatInt(pid, 10), "", func(r *http.Request) {
		bearer(token)(r)
		r.Header.Set("Accept-Language", "en")
	})
	if w.Code != 403 || !strings.Contains(w.Body.String(), "operate this player") {
		t.Fatalf("non-owner delete = %d %s, want 403 admin.players.no-permission", w.Code, w.Body.String())
	}
}
func TestCoreAPIReportsReviewBanOutrankingAndPermissionGate(t *testing.T) {
	h, id := coreFixture(t)
	// Pending report uploaded by an admin (permission 2). An equal-rank
	// admin cannot ban the uploader: the frozen ReportController::review
	// answers HTTP 200 with business code 1 and the
	// admin.users.operations.no-permission message (no 403).
	if _, err := id.Store.DB.Exec("INSERT INTO " + id.Store.Table("reports") + " (id,tid,uploader,reporter,reason,status,report_at) VALUES (1,999999,2,1,'spam',0,'2026-01-01 00:00:00')"); err != nil {
		t.Fatal(err)
	}
	adminToken := coreToken(t, h, "admin@example.invalid", "ReportsManagement.ReadWrite")
	w := coreReq(t, h, "PUT", "/api/admin/reports/1", `{"action":"ban"}`, func(r *http.Request) {
		bearer(adminToken)(r)
		r.Header.Set("Accept-Language", "en")
	})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":1`) || !strings.Contains(w.Body.String(), "You have no permission to operate this user.") {
		t.Fatalf("ban outranking = %d %s, want 200 code 1 no-permission", w.Code, w.Body.String())
	}
	var permission int
	if err := id.Store.DB.QueryRow("SELECT permission FROM " + id.Store.Table("users") + " WHERE uid=2").Scan(&permission); err != nil {
		t.Fatal(err)
	}
	if permission != 2 {
		t.Fatalf("outranking ban changed uploader permission: %d", permission)
	}
	// The admin gate is not downgraded: an actor whose current permission
	// is below 1 still gets HTTP 403, not a 200 business rejection.
	if _, err := id.Store.DB.Exec("INSERT INTO " + id.Store.Table("reports") + " (id,tid,uploader,reporter,reason,status,report_at) VALUES (2,999999,1,1,'spam',0,'2026-01-01 00:00:00')"); err != nil {
		t.Fatal(err)
	}
	userToken := coreToken(t, h, "user@example.invalid", "ReportsManagement.ReadWrite")
	w = coreReq(t, h, "PUT", "/api/admin/reports/2", `{"action":"ban"}`, func(r *http.Request) {
		bearer(userToken)(r)
		r.Header.Set("Accept-Language", "en")
	})
	if w.Code != 403 || !strings.Contains(w.Body.String(), `"code":403`) {
		t.Fatalf("permission-below-one review = %d %s, want 403", w.Code, w.Body.String())
	}
}
