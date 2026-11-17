package httpapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"paradise-cosmetics-studio/internal/testsupport"
)

func TestAdminSearchRequestErrors(t *testing.T) {
	h, _ := appFixture(t)
	cookie, _ := credentials(t, h, true)
	for _, endpoint := range []struct{ path, field string }{{"players", "name"}, {"users", "nickname"}, {"reports", "reason"}} {
		for _, query := range []string{"sort:unknown", "fields:unknown", endpoint.field + ":(a or b)", endpoint.field + ".foo:(a or b)"} {
			w := request(t, h, "GET", "/admin/"+endpoint.path+"/list?q="+url.QueryEscape(query), "", "", cookie)
			if w.Code != 422 || !strings.Contains(w.Body.String(), `"errors":{"q"`) {
				t.Errorf("%s %q: %d, %s", endpoint.path, query, w.Code, w.Body.String())
			}
		}
		for _, query := range []string{"unknown:value", endpoint.field + ":(a and)", endpoint.field + ".foo:(a and)"} {
			w := request(t, h, "GET", "/admin/"+endpoint.path+"/list?q="+url.QueryEscape(query), "", "", cookie)
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"data"`) {
				t.Errorf("existing fallback %s %q: %d, %s", endpoint.path, query, w.Code, w.Body.String())
			}
		}
	}
}

func TestPlayerPageRendersFrozenMountPoints(t *testing.T) {
	h, _ := appFixture(t)
	cookie, _ := credentials(t, h, false)
	w := request(t, h, "GET", "/user/player", "", "", cookie)
	if w.Code != 200 {
		t.Fatalf("player page status = %d", w.Code)
	}
	body := w.Body.String()
	for _, text := range []string{`id="players-list"`, `id="previewer"`, `id="modals"`, "Player name may only contains letters", `"route":"user/player"`, `"count":1`, `"cost":100`} {
		if !strings.Contains(body, text) {
			t.Fatalf("player page missing %q", text)
		}
	}
	if strings.Contains(body, `"length":"The player name should be at least :min`) {
		t.Fatal("player length placeholders not resolved")
	}
}

func TestPlayerApiLifecycle(t *testing.T) {
	h, id := appFixture(t)
	cookie, csrf := credentials(t, h, false)
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET score=1000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	w := request(t, h, "POST", "/user/player", `{"name":"HttpPlayer"}`, csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) || !strings.Contains(w.Body.String(), `"name":"HttpPlayer"`) {
		t.Fatalf("add failed status=%d body=%s", w.Code, w.Body.String())
	}
	var pid int64
	if err := id.Store.DB.QueryRow("SELECT pid FROM " + id.Store.Table("players") + " WHERE name='HttpPlayer'").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "GET", "/user/player/list", "", "", cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"pid":`) {
		t.Fatalf("list failed status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "PUT", "/user/player/"+itoa(pid)+"/name", `{"name":"HttpRenamed"}`, csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("rename failed status=%d body=%s", w.Code, w.Body.String())
	}
	// Duplicate names are a frozen validation error (422), not a business code.
	w = request(t, h, "POST", "/user/player", `{"name":"Playerone"}`, csrf, cookie)
	if w.Code != 422 || !strings.Contains(w.Body.String(), `"errors":{"name"`) {
		t.Fatalf("duplicate add status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "POST", "/user/player", `{"name":"ab"}`, csrf, cookie)
	if w.Code != 422 {
		t.Fatalf("short name status=%d body=%s", w.Code, w.Body.String())
	}
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET score=0 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "POST", "/user/player", `{"name":"HttpNoScore"}`, csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":7`) {
		t.Fatalf("lack score status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "DELETE", "/user/player/"+itoa(pid), "", csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) || !strings.Contains(w.Body.String(), "HttpRenamed") {
		t.Fatalf("delete failed status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "DELETE", "/user/player/99999", "", csrf, cookie)
	if w.Code != 404 {
		t.Fatalf("missing player status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestPlayerVerifiedMiddleware(t *testing.T) {
	options := testsupport.InstalledOptions(t)
	options["require_verification"] = "true"
	h, id := appFixtureWithOptions(t, options)
	cookie, _ := credentials(t, h, false)
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET verified=0 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	w := request(t, h, "GET", "/user/player/list", "", "", cookie)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "verify your email") {
		t.Fatalf("verified JSON status=%d body=%s", w.Code, w.Body.String())
	}
	r := newPageRequest(t, h, "GET", "/user/player", "", "", cookie)
	if r.Code != 403 || !strings.Contains(r.Body.String(), "verify your email") {
		t.Fatalf("verified HTML status=%d body=%s", r.Code, r.Body.String())
	}
}

func TestAdminPlayersApi(t *testing.T) {
	h, id := appFixture(t)
	cookie, csrf := credentials(t, h, true)
	w := request(t, h, "GET", "/admin/players", "", "", cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"route":"admin/players"`) {
		t.Fatalf("admin players page status=%d", w.Code)
	}
	var pid int64
	if err := id.Store.DB.QueryRow("SELECT pid FROM " + id.Store.Table("players") + " WHERE name='PlayerOne'").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "GET", "/admin/players/list?q=Player&page=1", "", "", cookie)
	if w.Code != 200 {
		t.Fatalf("admin list status=%d body=%s", w.Code, w.Body.String())
	}
	var page map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"data", "current_page", "last_page", "per_page", "total", "first_page_url", "last_page_url", "path", "links"} {
		if _, ok := page[key]; !ok {
			t.Fatalf("paginator missing %q: %v", key, page)
		}
	}
	// Same-name admin rename is rejected by the frozen unique rule.
	w = request(t, h, "PUT", "/admin/players/"+itoa(pid)+"/name", `{"player_name":"PlayerOne"}`, csrf, cookie)
	if w.Code != 422 || !strings.Contains(w.Body.String(), "player_name") {
		t.Fatalf("admin same-name status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "PUT", "/admin/players/"+itoa(pid)+"/name", `{"player_name":"AdminRenamed"}`, csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("admin rename status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "PUT", "/admin/players/"+itoa(pid)+"/owner", `{"uid":999}`, csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":1`) {
		t.Fatalf("missing owner target status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "PUT", "/admin/players/"+itoa(pid)+"/owner", `{"uid":"not-a-number"}`, csrf, cookie)
	if w.Code != 422 {
		t.Fatalf("non-integer owner status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "PUT", "/admin/players/"+itoa(pid)+"/owner", `{"uid":2}`, csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("transfer status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "DELETE", "/admin/players/"+itoa(pid), "", csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("admin delete status=%d body=%s", w.Code, w.Body.String())
	}
	// Normal users cannot reach the admin player endpoints.
	userCookie, _ := credentials(t, h, false)
	w = request(t, h, "GET", "/admin/players/list", "", "", userCookie)
	if w.Code != 403 {
		t.Fatalf("normal user admin list status=%d", w.Code)
	}
}

func TestAdminPlayerPermissionBoundary(t *testing.T) {
	h, id := appFixture(t)
	cookie, csrf := credentials(t, h, true)
	// Give user 2 (admin) a normal user owner and try to manage another admin's player.
	if _, err := id.Store.DB.Exec("INSERT INTO " + id.Store.Table("users") + " (uid,email,nickname,password,permission,verified,score) VALUES (3,'admin2@example.invalid','Admin2','x',2,1,0)"); err != nil {
		t.Fatal(err)
	}
	if _, err := id.Store.DB.Exec("INSERT INTO " + id.Store.Table("go_auth_versions") + " (user_uid,version) VALUES (3,1)"); err != nil {
		t.Fatal(err)
	}
	result, err := id.Store.DB.Exec("INSERT INTO " + id.Store.Table("players") + " (uid,name,tid_skin,tid_cape,last_modified) VALUES (3,'PeerAdminPlayer',0,0,'2026-01-01 00:00:00')")
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := result.LastInsertId()
	w := request(t, h, "PUT", "/admin/players/"+itoa(pid)+"/name", `{"player_name":"PeerRenamed"}`, csrf, cookie)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "no permission") {
		t.Fatalf("peer admin boundary status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "DELETE", "/admin/players/"+itoa(pid), "", csrf, cookie)
	if w.Code != 403 {
		t.Fatalf("peer admin delete status=%d body=%s", w.Code, w.Body.String())
	}
}

func newPageRequest(t *testing.T, h http.Handler, method, target, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://localhost/skin"+target, strings.NewReader(body))
	r.Header.Set("Accept", "text/html")
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

func itoa(value int64) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}

func TestPlayerTextureSlotsApi(t *testing.T) {
	h, id := appFixture(t)
	cookie, csrf := credentials(t, h, false)
	adminCookie, adminCSRF := credentials(t, h, true)
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET score=100000 WHERE uid IN (1,2)"); err != nil {
		t.Fatal(err)
	}
	adminUp := uploadRequest(t, h, adminCookie, adminCSRF, "SlotCape", "cape", "1", pngBytes(t, 64, 32, 71))
	if adminUp.Code != 200 {
		t.Fatalf("cape upload status=%d body=%s", adminUp.Code, adminUp.Body.String())
	}
	var capeTID, skinTID int64
	id.Store.DB.QueryRow("SELECT tid FROM " + id.Store.Table("textures") + " WHERE name='SlotCape'").Scan(&capeTID)
	// The admin's cape is not in the user's closet: rejected by the closet check.
	var pid int64
	id.Store.DB.QueryRow("SELECT pid FROM " + id.Store.Table("players") + " WHERE name='PlayerOne'").Scan(&pid)
	w := request(t, h, "PUT", "/user/player/"+itoa(pid)+"/textures", `{"cape":`+itoa(capeTID)+`}`, csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":1`) {
		t.Fatalf("non-closet cape status=%d body=%s", w.Code, w.Body.String())
	}
	up := uploadRequest(t, h, cookie, csrf, "SlotSkin", "steve", "1", pngBytes(t, 64, 64, 72))
	if up.Code != 200 {
		t.Fatalf("skin upload status=%d body=%s", up.Code, up.Body.String())
	}
	id.Store.DB.QueryRow("SELECT tid FROM " + id.Store.Table("textures") + " WHERE name='SlotSkin'").Scan(&skinTID)
	w = request(t, h, "PUT", "/user/player/"+itoa(pid)+"/textures", `{"skin":`+itoa(skinTID)+`}`, csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) || !strings.Contains(w.Body.String(), `"tid_skin":`+itoa(skinTID)) {
		t.Fatalf("set skin status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "DELETE", "/user/player/"+itoa(pid)+"/textures?skin=true", "", csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"tid_skin":0`) {
		t.Fatalf("clear skin status=%d body=%s", w.Code, w.Body.String())
	}
	// Admin direct TID assignment and clearing.
	w = request(t, h, "PUT", "/admin/players/"+itoa(pid)+"/textures", `{"tid":`+itoa(skinTID)+`,"type":"skin"}`, adminCSRF, adminCookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("admin set texture status=%d body=%s", w.Code, w.Body.String())
	}
	var skin int64
	id.Store.DB.QueryRow("SELECT tid_skin FROM " + id.Store.Table("players") + " WHERE pid=" + itoa(pid)).Scan(&skin)
	if skin != skinTID {
		t.Fatalf("admin assignment = %d", skin)
	}
	w = request(t, h, "PUT", "/admin/players/"+itoa(pid)+"/textures", `{"tid":0,"type":"skin"}`, adminCSRF, adminCookie)
	if w.Code != 200 {
		t.Fatalf("admin clear texture status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "PUT", "/admin/players/"+itoa(pid)+"/textures", `{"tid":`+itoa(skinTID)+`,"type":"cape"}`, adminCSRF, adminCookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":1`) {
		t.Fatalf("admin wrong slot status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "PUT", "/admin/players/"+itoa(pid)+"/textures", `{"tid":99999,"type":"skin"}`, adminCSRF, adminCookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":1`) {
		t.Fatalf("admin missing texture status=%d body=%s", w.Code, w.Body.String())
	}
}
