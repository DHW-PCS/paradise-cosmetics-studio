package httpapp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClosetPageAndEmptyApi(t *testing.T) {
	h, _ := appFixture(t)
	cookie, _ := credentials(t, h, false)
	w := request(t, h, "GET", "/user/closet", "", "", cookie)
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, `id="closet-list"`) || !strings.Contains(body, `id="email-verification"`) || !strings.Contains(body, `id="previewer"`) {
		t.Fatalf("closet page status=%d body=%.300s", w.Code, body)
	}
	w = request(t, h, "GET", "/user/closet/list?category=skin&page=1&perPage=6", "", "", cookie)
	var page map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil {
		t.Fatalf("closet list status=%d body=%s", w.Code, w.Body.String())
	}
	if page["total"] != float64(0) {
		t.Fatalf("empty closet total %v", page["total"])
	}
	w = request(t, h, "GET", "/user/closet/ids", "", "", cookie)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("closet ids status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestClosetApiLifecycle(t *testing.T) {
	h, id := appFixture(t)
	cookie, csrf := credentials(t, h, false)
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET score=1000 WHERE uid IN (1,2)"); err != nil {
		t.Fatal(err)
	}
	adminCookie, adminCSRF := credentials(t, h, true)
	w := uploadRequest(t, h, adminCookie, adminCSRF, "ClosetTexture", "steve", "1", pngBytes(t, 64, 64, 51))
	if w.Code != 200 {
		t.Fatalf("upload status=%d body=%s", w.Code, w.Body.String())
	}
	var tid int64
	id.Store.DB.QueryRow("SELECT tid FROM " + id.Store.Table("textures") + " WHERE name='ClosetTexture'").Scan(&tid)
	w = request(t, h, "POST", "/user/closet", `{"tid":`+itoa(tid)+`,"name":"MyItem"}`, csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("closet add status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "GET", "/user/closet/list?category=skin&page=1&perPage=6", "", "", cookie)
	if !strings.Contains(w.Body.String(), `"item_name":"MyItem"`) || !strings.Contains(w.Body.String(), `"pivot"`) {
		t.Fatalf("closet list missing pivot: %s", w.Body.String())
	}
	w = request(t, h, "PUT", "/user/closet/"+itoa(tid), `{"name":"RenamedItem"}`, csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("closet rename status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "DELETE", "/user/closet/"+itoa(tid), "", csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("closet remove status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "DELETE", "/user/closet/"+itoa(tid), "", csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":1`) {
		t.Fatalf("repeat remove status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "PUT", "/user/closet/"+itoa(tid), `{"name":""}`, csrf, cookie)
	if w.Code != 422 {
		t.Fatalf("empty item name status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestTextureMutationApi(t *testing.T) {
	h, id := appFixture(t)
	cookie, csrf := credentials(t, h, false)
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET score=1000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	w := uploadRequest(t, h, cookie, csrf, "MutateMe", "steve", "1", pngBytes(t, 64, 64, 52))
	if w.Code != 200 {
		t.Fatalf("upload status=%d body=%s", w.Code, w.Body.String())
	}
	var tid int64
	id.Store.DB.QueryRow("SELECT tid FROM " + id.Store.Table("textures") + " WHERE name='MutateMe'").Scan(&tid)
	w = request(t, h, "PUT", "/texture/"+itoa(tid)+"/name", `{"name":"RenamedTexture"}`, csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("texture rename status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "PUT", "/texture/"+itoa(tid)+"/type", `{"type":"alex"}`, csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("texture type status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "PUT", "/texture/"+itoa(tid)+"/privacy", `{}`, csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) || !strings.Contains(w.Body.String(), "Private") {
		t.Fatalf("texture privacy status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "DELETE", "/texture/"+itoa(tid), "", csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("texture delete status=%d body=%s", w.Code, w.Body.String())
	}
	var count int
	id.Store.DB.QueryRow("SELECT COUNT(*) FROM "+id.Store.Table("textures")+" WHERE tid=?", tid).Scan(&count)
	if count != 0 {
		t.Fatalf("texture row survived delete: %d", count)
	}
	w = request(t, h, "DELETE", "/texture/"+itoa(tid), "", csrf, cookie)
	if w.Code != 404 {
		t.Fatalf("repeat texture delete status=%d", w.Code)
	}
}

func TestAdminClosetApiPermissions(t *testing.T) {
	h, id := appFixture(t)
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET score=1000 WHERE uid IN (1,2)"); err != nil {
		t.Fatal(err)
	}
	userCookie, userCSRF := credentials(t, h, false)
	adminCookie, adminCSRF := credentials(t, h, true)
	w := uploadRequest(t, h, adminCookie, adminCSRF, "AdminClosetTex", "steve", "1", pngBytes(t, 64, 64, 53))
	if w.Code != 200 {
		t.Fatalf("upload status=%d", w.Code)
	}
	var tid int64
	id.Store.DB.QueryRow("SELECT tid FROM " + id.Store.Table("textures") + " WHERE name='AdminClosetTex'").Scan(&tid)
	w = request(t, h, "POST", "/admin/closet/1", `{"tid":`+itoa(tid)+`}`, adminCSRF, adminCookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("admin closet add status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(t, h, "POST", "/admin/closet/1", `{"tid":`+itoa(tid)+`}`, adminCSRF, adminCookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("admin closet add not idempotent: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "DELETE", "/admin/closet/1", `{"tid":`+itoa(tid)+`}`, adminCSRF, adminCookie)
	if w.Code != 200 {
		t.Fatalf("admin closet remove status=%d body=%s", w.Code, w.Body.String())
	}
	// Normal users cannot call the admin endpoints.
	w = request(t, h, "POST", "/admin/closet/2", `{"tid":`+itoa(tid)+`}`, userCSRF, userCookie)
	if w.Code != 403 {
		t.Fatalf("normal user admin closet status=%d", w.Code)
	}
}
