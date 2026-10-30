package httpapp

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blessing-skin-go/internal/identity"
)

func pngBytes(t *testing.T, width, height int, seed byte) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	for x := 0; x < width; x++ {
		for y := 0; y < height; y++ {
			img.SetNRGBA(x, y, color.NRGBA{R: uint8(x), G: uint8(y), B: seed, A: 255})
		}
	}
	var buffer bytes.Buffer
	if err := png.Encode(&buffer, img); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestTextureUploadConfiguredSize(t *testing.T) {
	for _, tc := range []struct {
		name, option    string
		padding, status int
	}{
		{"default", "", 0, 200},
		{"zero", "0", 0, 422},
		{"positive", "1", 0, 200},
		{"over-limit", "1", 2048, 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := map[string]string{}
			if tc.option != "" {
				options["max_upload_file_size"] = tc.option
			}
			h, _ := appFixtureWithOptions(t, options)
			cookie, csrf := credentials(t, h, false)
			payload := append(pngBytes(t, 64, 64, 7), make([]byte, tc.padding)...)
			w := uploadRequest(t, h, cookie, csrf, "Sized", "steve", "1", payload)
			if w.Code != tc.status {
				t.Fatalf("upload status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func uploadRequest(t *testing.T, h http.Handler, cookie *http.Cookie, csrf, name, kind, public string, payload []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	writer.WriteField("name", name)
	writer.WriteField("type", kind)
	writer.WriteField("public", public)
	part, err := writer.CreateFormFile("file", name+".png")
	if err != nil {
		t.Fatal(err)
	}
	part.Write(payload)
	writer.Close()
	r := httptest.NewRequest("POST", "http://localhost/skin/texture", &body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	r.Header.Set("Accept", "application/json")
	r.Header.Set("X-CSRF-TOKEN", csrf)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestSkinlibPagesRender(t *testing.T) {
	h, _ := appFixture(t)
	w := request(t, h, "GET", "/skinlib", "", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "layout-top-nav") || !strings.Contains(w.Body.String(), `"currentUid":null`) {
		t.Fatalf("skinlib index status=%d body=%.200s", w.Code, w.Body.String())
	}
	w = request(t, h, "GET", "/skinlib/list", "", "", nil)
	var page map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil {
		t.Fatalf("skinlib list status=%d body=%s", w.Code, w.Body.String())
	}
	if page["total"] != float64(0) || page["per_page"] != float64(20) {
		t.Fatalf("empty list paginator %v", page)
	}
	cookie, csrf := credentials(t, h, false)
	w = request(t, h, "GET", "/skinlib/upload", "", "", cookie)
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, `id="file-input"`) || !strings.Contains(body, `"scorePublic":1`) || !strings.Contains(body, `"scorePrivate":10`) {
		t.Fatalf("upload page status=%d body=%.300s", w.Code, body)
	}
	w = uploadRequest(t, h, cookie, csrf, "HttpSkin", "steve", "1", pngBytes(t, 64, 64, 7))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("upload status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Data struct {
			TID int64 `json:"tid"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &response)
	w = request(t, h, "GET", "/skinlib/show/"+itoa(response.Data.TID), "", "", cookie)
	body = w.Body.String()
	if w.Code != 200 || !strings.Contains(body, `id="side"`) || !strings.Contains(body, `"nickname":"User"`) || !strings.Contains(body, `"inCloset":true`) {
		t.Fatalf("show page status=%d body=%.400s", w.Code, body)
	}
}

func TestTextureUploadErrors(t *testing.T) {
	h, id := appFixture(t)
	cookie, csrf := credentials(t, h, false)
	w := uploadRequest(t, h, cookie, csrf, "BadPng", "steve", "1", []byte("not a png"))
	if w.Code != 422 || !strings.Contains(w.Body.String(), `"file"`) {
		t.Fatalf("invalid png status=%d body=%s", w.Code, w.Body.String())
	}
	w = uploadRequest(t, h, cookie, csrf, "BadSize", "steve", "1", pngBytes(t, 32, 32, 9))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":1`) || !strings.Contains(w.Body.String(), "width 32") {
		t.Fatalf("invalid dimensions status=%d body=%s", w.Code, w.Body.String())
	}
	w = uploadRequest(t, h, cookie, csrf, "BadType", "pickaxe", "1", pngBytes(t, 64, 64, 11))
	if w.Code != 422 {
		t.Fatalf("invalid type status=%d body=%s", w.Code, w.Body.String())
	}
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET score=0 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	w = uploadRequest(t, h, cookie, csrf, "NoScore", "steve", "1", pngBytes(t, 64, 64, 13))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "score") {
		t.Fatalf("lack score status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestConfiguredPCREHTTP(t *testing.T) {
	options := map[string]string{
		"player_name_rule": "custom", "custom_player_name_regexp": `/^(?=.{3,16}$)Name[A-Z]+$/`,
		"texture_name_regexp": `/^(Skin|Cape)\1$/`,
	}
	h, _ := appFixtureWithOptions(t, options)
	cookie, csrf := credentials(t, h, false)
	for _, name := range []string{"NameABC", "Name123"} {
		w := request(t, h, "POST", "/user/player", `{"name":"`+name+`"}`, csrf, cookie)
		want := 200
		if name == "Name123" {
			want = 422
		}
		if w.Code != want {
			t.Fatalf("player %q: status=%d body=%s", name, w.Code, w.Body.String())
		}
	}
	payload := pngBytes(t, 64, 64, 27)
	w := uploadRequest(t, h, cookie, csrf, "SkinCape", "steve", "1", payload)
	if w.Code != 422 || !strings.Contains(w.Body.String(), `"name"`) {
		t.Fatalf("rejected texture: %d, %s", w.Code, w.Body.String())
	}
	w = uploadRequest(t, h, cookie, csrf, "SkinSkin", "steve", "1", payload)
	var result struct{ Data struct{ TID int64 } }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Data.TID == 0 {
		t.Fatalf("accepted texture: %d, %s", w.Code, w.Body.String())
	}
	for _, name := range []string{"SkinCape", "CapeCape"} {
		w := request(t, h, "PUT", "/texture/"+itoa(result.Data.TID)+"/name", `{"name":"`+name+`"}`, csrf, cookie)
		want := 200
		if name == "SkinCape" {
			want = 422
		}
		if w.Code != want {
			t.Fatalf("rename %q: status=%d body=%s", name, w.Code, w.Body.String())
		}
	}
}

func TestMalformedPCREIsServerError(t *testing.T) {
	h, _ := appFixtureWithOptions(t, map[string]string{"texture_name_regexp": `/[/`})
	cookie, csrf := credentials(t, h, false)
	w := uploadRequest(t, h, cookie, csrf, "SkinSkin", "steve", "1", pngBytes(t, 64, 64, 29))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("invalid configured PCRE: %d, %s", w.Code, w.Body.String())
	}
}

func TestTextureUploadDuplicateAndPrivate(t *testing.T) {
	h, id := appFixture(t)
	cookie, csrf := credentials(t, h, false)
	payload := pngBytes(t, 64, 64, 21)
	w := uploadRequest(t, h, cookie, csrf, "DuplicateOne", "steve", "1", payload)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("first upload status=%d body=%s", w.Code, w.Body.String())
	}
	w = uploadRequest(t, h, cookie, csrf, "DuplicateTwo", "steve", "1", payload)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":2`) || !strings.Contains(w.Body.String(), `"tid"`) {
		t.Fatalf("duplicate upload status=%d body=%s", w.Code, w.Body.String())
	}
	// Private upload uses the private storage rate and removes the award.
	adminCookie, adminCSRF := credentials(t, h, true)
	privatePayload := pngBytes(t, 64, 64, 22)
	before := score(t, id, 1)
	w = uploadRequest(t, h, cookie, csrf, "PrivateSkin", "steve", "0", privatePayload)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("private upload status=%d body=%s", w.Code, w.Body.String())
	}
	after := score(t, id, 1)
	if before-after != 10 {
		t.Fatalf("private upload charged %d, want 10", before-after)
	}
	// Guest cannot read the private texture; the owner and admins can.
	var tid int64
	id.Store.DB.QueryRow("SELECT tid FROM " + id.Store.Table("textures") + " WHERE name='PrivateSkin'").Scan(&tid)
	if w = request(t, h, "GET", "/texture/"+itoa(tid), "", "", nil); w.Code != 403 {
		t.Fatalf("guest private info status=%d", w.Code)
	}
	if w = request(t, h, "GET", "/texture/"+itoa(tid), "", "", cookie); w.Code != 200 {
		t.Fatalf("owner private info status=%d", w.Code)
	}
	if w = request(t, h, "GET", "/texture/"+itoa(tid), "", "", adminCookie); w.Code != 200 {
		t.Fatalf("admin private info status=%d", w.Code)
	}
	_ = adminCSRF
}

func TestSkinlibMissingFileKeepsRow(t *testing.T) {
	h, id, dir := appFixtureWithOptionsAndDir(t, nil)
	cookie, csrf := credentials(t, h, false)
	w := uploadRequest(t, h, cookie, csrf, "MissingFile", "steve", "1", pngBytes(t, 64, 64, 31))
	if w.Code != 200 {
		t.Fatalf("upload status=%d body=%s", w.Code, w.Body.String())
	}
	var tid int64
	var hash string
	id.Store.DB.QueryRow("SELECT tid,hash FROM "+id.Store.Table("textures")+" WHERE name='MissingFile'").Scan(&tid, &hash)
	os.Remove(filepath.Join(dir, hash))
	w = request(t, h, "GET", "/skinlib/show/"+itoa(tid), "", "", nil)
	if w.Code != 404 {
		t.Fatalf("missing file show status=%d body=%s", w.Code, w.Body.String())
	}
	var count int
	id.Store.DB.QueryRow("SELECT COUNT(*) FROM "+id.Store.Table("textures")+" WHERE tid=?", tid).Scan(&count)
	if count != 1 {
		t.Fatalf("read removed business row: %d", count)
	}
}

func score(t *testing.T, id *identity.Service, uid int64) int64 {
	t.Helper()
	var value int64
	if err := id.Store.DB.QueryRow("SELECT score FROM "+id.Store.Table("users")+" WHERE uid=?", uid).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
