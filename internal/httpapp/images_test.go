package httpapp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image/png"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blessing-skin-go/internal/identity"
)

func TestTextureAndProfileEndpoints(t *testing.T) {
	h, id := appFixture(t)
	cookie, csrf := credentials(t, h, false)
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET score=1000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	payload := pngBytes(t, 64, 64, 91)
	w := uploadRequest(t, h, cookie, csrf, "CachedSkin", "steve", "1", payload)
	if w.Code != 200 {
		t.Fatalf("upload status=%d body=%s", w.Code, w.Body.String())
	}
	var tid int64
	var hash string
	id.Store.DB.QueryRow("SELECT tid,hash FROM "+id.Store.Table("textures")+" WHERE name='CachedSkin'").Scan(&tid, &hash)
	// The original bytes are served unchanged with length/content-type.
	w = request(t, h, "GET", "/textures/"+hash, "", "", nil)
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("raw hash status=%d type=%s", w.Code, w.Header().Get("Content-Type"))
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != hash {
		t.Fatalf("uploaded bytes changed: %s vs %s", hex.EncodeToString(sum[:]), hash)
	}
	if w.Body.Len() != len(payload) {
		t.Fatalf("served length %d want %d", w.Body.Len(), len(payload))
	}
	etag := w.Header().Get("ETag")
	if etag == "" || w.Header().Get("Last-Modified") == "" {
		t.Fatal("missing validators")
	}
	w2 := request(t, h, "GET", "/textures/"+hash, "", "", nil)
	if w2.Body.Len() != len(payload) {
		t.Fatal("second read differs")
	}
	cond := httptest.NewRequest("GET", "http://localhost/skin/textures/"+hash, nil)
	cond.Header.Set("If-None-Match", etag)
	condRecorder := httptest.NewRecorder()
	h.ServeHTTP(condRecorder, cond)
	if condRecorder.Code != 304 {
		t.Fatalf("conditional request status=%d", condRecorder.Code)
	}
	// Raw download honours the option.
	w = request(t, h, "GET", "/raw/"+itoa(tid), "", "", nil)
	if w.Code != 200 {
		t.Fatalf("raw tid status=%d", w.Code)
	}
	if _, err := id.Store.DB.Exec("INSERT INTO " + id.Store.Table("options") + " (option_name,option_value) VALUES ('allow_downloading_texture','false')"); err != nil {
		t.Fatal(err)
	}
	// Profile JSON with the model/hash shape.
	w = request(t, h, "GET", "/PlayerOne.json", "", "", nil)
	if w.Code != 200 {
		t.Fatalf("profile status=%d body=%s", w.Code, w.Body.String())
	}
	var profile map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &profile); err != nil || profile["username"] != "PlayerOne" {
		t.Fatalf("profile %v err=%v", profile, err)
	}
	if w.Header().Get("Last-Modified") == "" {
		t.Fatal("profile missing Last-Modified")
	}
}

func TestAvatarAndPreviewEndpoints(t *testing.T) {
	h, id := appFixture(t)
	cookie, csrf := credentials(t, h, false)
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET score=1000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	up := uploadRequest(t, h, cookie, csrf, "AvatarSkin", "steve", "1", pngBytes(t, 64, 64, 92))
	if up.Code != 200 {
		t.Fatalf("upload status=%d", up.Code)
	}
	var tid int64
	id.Store.DB.QueryRow("SELECT tid FROM " + id.Store.Table("textures") + " WHERE name='AvatarSkin'").Scan(&tid)
	w := request(t, h, "GET", "/preview/"+itoa(tid), "", "", nil)
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/webp" {
		t.Fatalf("default preview status=%d type=%s", w.Code, w.Header().Get("Content-Type"))
	}
	w = request(t, h, "GET", "/preview/"+itoa(tid)+"?png", "", "", nil)
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("png preview status=%d type=%s", w.Code, w.Header().Get("Content-Type"))
	}
	w = request(t, h, "GET", "/preview/999999", "", "", nil)
	if w.Code != 404 {
		t.Fatalf("missing preview status=%d", w.Code)
	}
	w = request(t, h, "GET", "/avatar/"+itoa(tid)+"?png&size=45", "", "", nil)
	if w.Code != 200 {
		t.Fatalf("avatar tid status=%d", w.Code)
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(w.Body.Bytes()))
	if err != nil || cfg.Width != 45 || cfg.Height != 45 {
		t.Fatalf("avatar dimensions=%+v err=%v", cfg, err)
	}
	// Default avatar for unknown user and the 422 cape case.
	w = request(t, h, "GET", "/avatar/user/99999?size=45", "", "", nil)
	if w.Code != 200 {
		t.Fatalf("default avatar status=%d", w.Code)
	}
	capeUp := uploadRequest(t, h, cookie, csrf, "AvatarCape", "cape", "1", pngBytes(t, 64, 32, 93))
	if capeUp.Code != 200 {
		t.Fatalf("cape upload status=%d body=%s", capeUp.Code, capeUp.Body.String())
	}
	var capeTID int64
	if err := id.Store.DB.QueryRow("SELECT tid FROM " + id.Store.Table("textures") + " WHERE name='AvatarCape'").Scan(&capeTID); err != nil {
		t.Fatalf("cape row: %v body=%s", err, capeUp.Body.String())
	}
	w = request(t, h, "GET", "/avatar/"+itoa(capeTID), "", "", nil)
	if w.Code != 422 {
		t.Fatalf("cape avatar status=%d", w.Code)
	}
	// Player avatar without a profile is 404; with a skin it renders.
	w = request(t, h, "GET", "/avatar/player/NoSuchPlayer", "", "", nil)
	if w.Code != 404 {
		t.Fatalf("missing player avatar status=%d", w.Code)
	}
	id.Store.DB.Exec("UPDATE "+id.Store.Table("players")+" SET tid_skin=? WHERE name='PlayerOne'", tid)
	w = request(t, h, "GET", "/avatar/player/PlayerOne?3d", "", "", nil)
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/webp" {
		t.Fatalf("player avatar status=%d type=%s", w.Code, w.Header().Get("Content-Type"))
	}
}

func TestBannedPlayerProfile(t *testing.T) {
	h, id := appFixture(t)
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET permission=-1 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	w := request(t, h, "GET", "/PlayerOne.json", "", "", nil)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "banned") {
		t.Fatalf("banned profile status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestImageDatabaseFailures(t *testing.T) {
	h, id := appFixture(t)
	for _, query := range []string{
		"UPDATE " + id.Store.Table("users") + " SET avatar=1 WHERE uid=1",
		"UPDATE " + id.Store.Table("players") + " SET tid_skin=1 WHERE name='PlayerOne'",
		"DROP TABLE " + id.Store.Table("textures"),
	} {
		if _, err := id.Store.DB.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range []string{"/avatar/1", "/avatar/hash/broken", "/avatar/user/1", "/avatar/player/PlayerOne", "/preview/1", "/raw/1"} {
		t.Run(target, func(t *testing.T) {
			w := request(t, h, "GET", target, "", "", nil)
			if w.Code != 503 {
				t.Fatalf("DB failure status=%d body=%.200s", w.Code, w.Body.String())
			}
		})
	}
}

func TestImageFileFailuresAndMissing(t *testing.T) {
	h, id, dir := appFixtureWithOptionsAndDir(t, nil)
	result, err := id.Store.DB.Exec("INSERT INTO " + id.Store.Table("textures") + " (name,type,hash,size,uploader,public) VALUES ('BrokenFile','steve','broken',1,1,1)")
	if err != nil {
		t.Fatal(err)
	}
	tid, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "broken")
	if err := os.Symlink("broken", path); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		target string
		status int
	}{
		{"/avatar/" + itoa(tid), 200},
		{"/avatar/hash/broken", 200},
		{"/preview/" + itoa(tid), 404},
		{"/textures/broken", 404},
		{"/raw/" + itoa(tid), 404},
		{"/skinlib/show/" + itoa(tid), 404},
	}
	for _, tc := range cases {
		w := request(t, h, "GET", tc.target, "", "", nil)
		if w.Code != 503 {
			t.Fatalf("%s: file failure status=%d", tc.target, w.Code)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		w := request(t, h, "GET", tc.target, "", "", nil)
		if w.Code != tc.status {
			t.Fatalf("%s: missing file status=%d want %d", tc.target, w.Code, tc.status)
		}
	}
}

func TestConditionalRequestsAndDerivedValidators(t *testing.T) {
	h, id := appFixture(t)
	cookie, csrf := credentials(t, h, false)
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET score=1000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	w := uploadRequest(t, h, cookie, csrf, "Validator", "steve", "1", pngBytes(t, 64, 64, 95))
	if w.Code != 200 {
		t.Fatalf("upload status=%d", w.Code)
	}
	var tid int64
	id.Store.DB.QueryRow("SELECT tid FROM " + id.Store.Table("textures") + " WHERE name='Validator'").Scan(&tid)
	for _, target := range []string{"/preview/" + itoa(tid), "/avatar/" + itoa(tid), "/textures/" + hashOf(t, id, tid)} {
		first := request(t, h, "GET", target, "", "", nil)
		if first.Code != 200 || first.Header().Get("ETag") == "" {
			t.Fatalf("%s first status=%d etag=%q", target, first.Code, first.Header().Get("ETag"))
		}
		if target != "/textures/"+hashOf(t, id, tid) && first.Header().Get("Last-Modified") == "" {
			t.Fatalf("%s missing Last-Modified", target)
		}
		head := httptest.NewRequest("HEAD", "http://localhost/skin"+target, nil)
		headRecorder := httptest.NewRecorder()
		h.ServeHTTP(headRecorder, head)
		if headRecorder.Code != 200 || headRecorder.Body.Len() != 0 {
			t.Fatalf("%s HEAD status=%d body=%d", target, headRecorder.Code, headRecorder.Body.Len())
		}
		conditional := httptest.NewRequest("GET", "http://localhost/skin"+target, nil)
		conditional.Header.Set("If-None-Match", first.Header().Get("ETag"))
		recorder := httptest.NewRecorder()
		h.ServeHTTP(recorder, conditional)
		if recorder.Code != 304 {
			t.Fatalf("%s etag conditional status=%d", target, recorder.Code)
		}
		if modified := first.Header().Get("Last-Modified"); modified != "" {
			ims := httptest.NewRequest("GET", "http://localhost/skin"+target, nil)
			ims.Header.Set("If-Modified-Since", modified)
			imsRecorder := httptest.NewRecorder()
			h.ServeHTTP(imsRecorder, ims)
			if imsRecorder.Code != 304 {
				t.Fatalf("%s ims conditional status=%d", target, imsRecorder.Code)
			}
		}
	}
	// Disabling downloads keeps the frozen 403 for the raw endpoint.
	if _, err := id.Store.DB.Exec("INSERT INTO " + id.Store.Table("options") + " (option_name,option_value) VALUES ('allow_downloading_texture','false')"); err != nil {
		t.Fatal(err)
	}
	if w = request(t, h, "GET", "/raw/"+itoa(tid), "", "", nil); w.Code != 403 {
		t.Fatalf("raw disabled status=%d", w.Code)
	}
}

func hashOf(t *testing.T, id *identity.Service, tid int64) string {
	t.Helper()
	var hash string
	if err := id.Store.DB.QueryRow("SELECT hash FROM "+id.Store.Table("textures")+" WHERE tid=?", tid).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	return hash
}

// TestDerivedImageCapsClamp covers user decision 4B: over-limit derived sizes are
// clamped to the evidence-backed cap and still return an image.
func TestDerivedImageCapsClamp(t *testing.T) {
	h, id := appFixture(t)
	cookie, csrf := credentials(t, h, false)
	up := uploadRequest(t, h, cookie, csrf, "ClampSkin", "steve", "1", pngBytes(t, 64, 64, 77))
	if up.Code != 200 {
		t.Fatalf("upload status=%d body=%s", up.Code, up.Body.String())
	}
	var tid int64
	id.Store.DB.QueryRow("SELECT tid FROM " + id.Store.Table("textures") + " WHERE name='ClampSkin'").Scan(&tid)
	for _, capSize := range []int{maxAvatarSize, maxPreviewHeight} {
		if capSize != 512 {
			t.Fatalf("evidence-backed cap changed to %d", capSize)
		}
	}
	// A request far above the cap must still return an image, clamped.
	w := request(t, h, "GET", "/avatar/"+itoa(tid)+"?size=4000", "", "", nil)
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "image/") {
		t.Fatalf("oversized avatar status=%d type=%s", w.Code, w.Header().Get("Content-Type"))
	}
	w = request(t, h, "GET", "/preview/"+itoa(tid)+"?height=4000", "", "", nil)
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "image/") {
		t.Fatalf("oversized preview status=%d type=%s", w.Code, w.Header().Get("Content-Type"))
	}
}
