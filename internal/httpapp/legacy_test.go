package httpapp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blessing-skin-go/internal/config"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/oauthserver"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/testsupport"
	"blessing-skin-go/internal/yggdrasil"
)

// legacySetModuleState rewrites the two authoritative module-state rows
// the same way the existing module tests do.
func legacySetModuleState(t *testing.T, id *identity.Service, enabled, installed string) {
	t.Helper()
	for name, value := range map[string]string{
		"plugins_enabled":         enabled,
		"go_module_installations": installed,
	} {
		if _, err := id.Store.DB.Exec("UPDATE "+id.Store.Table("options")+" SET option_value=? WHERE option_name=?", value, name); err != nil {
			t.Fatal(err)
		}
	}
}

func legacyEnable(t *testing.T, id *identity.Service) {
	t.Helper()
	legacySetModuleState(t, id, `[{"name":"legacy-api","version":"1.1.3"}]`, `[{"name":"legacy-api","version":"1.1.3"}]`)
}

// legacyTexture inserts a texture row and, unless writeFile is false,
// stores the payload at the hash path under the fixture texture dir.
func legacyTexture(t *testing.T, id *identity.Service, dir, name, kind string, payload []byte, public int, writeFile bool) (int64, string) {
	t.Helper()
	sum := sha256.Sum256(payload)
	hash := hex.EncodeToString(sum[:])
	if _, err := id.Store.DB.Exec("INSERT INTO "+id.Store.Table("textures")+" (name,type,hash,size,uploader,public,likes,upload_at) VALUES (?,?,?,?,?,?,0,'2020-01-01 00:00:00')", name, kind, hash, len(payload), 1, public); err != nil {
		t.Fatal(err)
	}
	var tid int64
	if err := id.Store.DB.QueryRow("SELECT tid FROM "+id.Store.Table("textures")+" WHERE hash=? ORDER BY tid DESC LIMIT 1", hash).Scan(&tid); err != nil {
		t.Fatal(err)
	}
	if writeFile {
		if err := os.WriteFile(filepath.Join(dir, hash), payload, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return tid, hash
}

func legacyEquip(t *testing.T, id *identity.Service, skinTID, capeTID int64) {
	t.Helper()
	if _, err := id.Store.DB.Exec("UPDATE "+id.Store.Table("players")+" SET tid_skin=?,tid_cape=? WHERE pid=1", skinTID, capeTID); err != nil {
		t.Fatal(err)
	}
}

func legacyDo(t *testing.T, h http.Handler, method, rawURL string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, rawURL, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func legacyGet(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	return legacyDo(t, h, "GET", "http://localhost/skin"+target, nil)
}

func legacyWantNoCookie(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if got := w.Header().Get("Set-Cookie"); got != "" {
		t.Fatalf("legacy response wrote a cookie: %q", got)
	}
	if cookies := w.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("legacy response wrote %d cookies", len(cookies))
	}
}

func legacyWantETag(t *testing.T, w *httptest.ResponseRecorder, payload []byte) string {
	t.Helper()
	sum := sha256.Sum256(payload)
	want := `"` + hex.EncodeToString(sum[:]) + `"`
	if got := w.Header().Get("ETag"); got != want {
		t.Fatalf("ETag=%q want %q", got, want)
	}
	return want
}

func legacyWantPNG(t *testing.T, w *httptest.ResponseRecorder, payload []byte) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "image/png" {
		t.Fatalf("Content-Type=%q want image/png", got)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("Cache-Control=%q want no-cache", got)
	}
	if !bytes.Equal(w.Body.Bytes(), payload) {
		t.Fatalf("body is not the original bytes (%d bytes)", w.Body.Len())
	}
	legacyWantETag(t, w, payload)
	legacyWantNoCookie(t, w)
}

func TestLegacyPNGOriginalBytesPrivateAndDownloadSwitch(t *testing.T) {
	h, id, dir := appFixtureWithOptionsAndDir(t, map[string]string{"allow_downloading_texture": "false"})
	legacyEnable(t, id)
	skin := pngBytes(t, 64, 64, 101)
	cape := pngBytes(t, 64, 32, 102)
	skinTID, _ := legacyTexture(t, id, dir, "LegacyPrivateSkin", "steve", skin, 0, true)
	capeTID, _ := legacyTexture(t, id, dir, "LegacyPrivateCape", "cape", cape, 0, true)
	legacyEquip(t, id, skinTID, capeTID)

	legacyWantPNG(t, legacyGet(t, h, "/skin/PlayerOne.png"), skin)
	legacyWantPNG(t, legacyGet(t, h, "/cape/PlayerOne.png"), cape)

	// HEAD carries the same validators with no body and no cookie.
	w := legacyDo(t, h, "HEAD", "http://localhost/skin/skin/PlayerOne.png", nil)
	if w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("HEAD status=%d body=%d", w.Code, w.Body.Len())
	}
	if got := w.Header().Get("Content-Length"); got != itoa(int64(len(skin))) {
		t.Fatalf("HEAD Content-Length=%q want %d", got, len(skin))
	}
	legacyWantETag(t, w, skin)
	if got := w.Header().Get("Content-Type"); got != "image/png" {
		t.Fatalf("HEAD Content-Type=%q", got)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("HEAD Cache-Control=%q", got)
	}
	legacyWantNoCookie(t, w)
}

func TestLegacyPNGNotFoundStates(t *testing.T) {
	h, id, dir := appFixtureWithOptionsAndDir(t, nil)
	legacyEnable(t, id)
	skin := pngBytes(t, 64, 64, 103)
	skinTID, _ := legacyTexture(t, id, dir, "LegacySkin404", "steve", skin, 1, true)
	legacyEquip(t, id, skinTID, -1)

	for _, target := range []string{
		"/skin/MissingPlayer.png", // missing player
		"/cape/PlayerOne.png",     // cleared cape slot
		"/skin/PlayerOne",         // missing .png suffix
		"/skin/PlayerOne.jpg",     // wrong suffix
		"/skin/PlayerOne.PNG",     // suffix is case-sensitive
		"/skin/.png",              // empty name after the suffix
		"/skin/PlayerOne.png.png", // only one suffix is cut; the remainder names no player
		"/cape/MissingPlayer.png",
	} {
		if w := legacyGet(t, h, target); w.Code != http.StatusNotFound {
			t.Fatalf("%s status=%d want 404", target, w.Code)
		}
	}

	// Texture row missing.
	legacyEquip(t, id, 424242, -1)
	if w := legacyGet(t, h, "/skin/PlayerOne.png"); w.Code != http.StatusNotFound {
		t.Fatalf("missing texture status=%d want 404", w.Code)
	}

	// Texture file missing (row present, no bytes on disk).
	ghostTID, _ := legacyTexture(t, id, dir, "LegacyGhostSkin", "steve", pngBytes(t, 64, 64, 104), 1, false)
	legacyEquip(t, id, ghostTID, -1)
	if w := legacyGet(t, h, "/skin/PlayerOne.png"); w.Code != http.StatusNotFound {
		t.Fatalf("missing file status=%d want 404", w.Code)
	}

	// Restoring the equipped texture serves again.
	legacyEquip(t, id, skinTID, -1)
	legacyWantPNG(t, legacyGet(t, h, "/skin/PlayerOne.png"), skin)
}

func TestLegacyPNGForbiddenAndBanPriority(t *testing.T) {
	h, id, dir := appFixtureWithOptionsAndDir(t, nil)
	legacyEnable(t, id)
	skin := pngBytes(t, 64, 64, 105)
	cape := pngBytes(t, 64, 32, 106)
	skinTID, _ := legacyTexture(t, id, dir, "LegacyBanSkin", "steve", skin, 1, true)
	capeTID, _ := legacyTexture(t, id, dir, "LegacyBanCape", "cape", cape, 1, true)
	legacyEquip(t, id, skinTID, capeTID)
	legacyWantPNG(t, legacyGet(t, h, "/skin/PlayerOne.png"), skin)

	setPermission := func(permission int) {
		t.Helper()
		if _, err := id.Store.DB.Exec("UPDATE "+id.Store.Table("users")+" SET permission=? WHERE uid=1", permission); err != nil {
			t.Fatal(err)
		}
	}
	setPermission(-1)
	for _, target := range []string{"/skin/PlayerOne.png", "/cape/PlayerOne.png"} {
		if w := legacyGet(t, h, target); w.Code != http.StatusForbidden {
			t.Fatalf("banned %s status=%d want 403", target, w.Code)
		}
	}
	// Ban resolves before the missing-texture outcome: cleared and dangling
	// slots stay 403 while the owner is banned.
	legacyEquip(t, id, -1, 424242)
	if w := legacyGet(t, h, "/skin/PlayerOne.png"); w.Code != http.StatusForbidden {
		t.Fatalf("banned cleared slot status=%d want 403", w.Code)
	}
	if w := legacyGet(t, h, "/cape/PlayerOne.png"); w.Code != http.StatusForbidden {
		t.Fatalf("banned missing texture status=%d want 403", w.Code)
	}
	// Any negative permission is banned, not only -1.
	setPermission(-5)
	legacyEquip(t, id, skinTID, capeTID)
	if w := legacyGet(t, h, "/skin/PlayerOne.png"); w.Code != http.StatusForbidden {
		t.Fatalf("permission -5 status=%d want 403", w.Code)
	}
	setPermission(0)
	legacyWantPNG(t, legacyGet(t, h, "/skin/PlayerOne.png"), skin)
}

func TestLegacyPNGPlayerNameCase(t *testing.T) {
	h, id, dir := appFixtureWithOptionsAndDir(t, nil)
	legacyEnable(t, id)
	skin := pngBytes(t, 64, 64, 107)
	skinTID, _ := legacyTexture(t, id, dir, "LegacyCaseSkin", "steve", skin, 1, true)
	legacyEquip(t, id, skinTID, -1)
	// The handler keeps the requested case; the database collation decides
	// the match, so every case variant of the stored name resolves.
	for _, name := range []string{"PlayerOne", "playerone", "PLAYERONE", "pLaYeRoNe"} {
		legacyWantPNG(t, legacyGet(t, h, "/skin/"+name+".png"), skin)
	}
}

func TestLegacyPNGModuleGate(t *testing.T) {
	h, id, dir := appFixtureWithOptionsAndDir(t, nil)
	skin := pngBytes(t, 64, 64, 108)
	skinTID, _ := legacyTexture(t, id, dir, "LegacyGateSkin", "steve", skin, 1, true)
	legacyEquip(t, id, skinTID, -1)

	enabled := `[{"name":"legacy-api","version":"1.1.3"}]`
	installed := `[{"name":"legacy-api","version":"1.1.3"}]`
	cases := []struct {
		name               string
		enabled, installed string
		want               int
	}{
		{"not installed, not enabled", "", "[]", http.StatusNotFound},
		{"installed, not enabled", "", installed, http.StatusNotFound},
		{"not installed, enabled", enabled, "[]", http.StatusNotFound},
		{"installed and enabled", enabled, installed, http.StatusOK},
		{"disabled again", "", installed, http.StatusNotFound},
		{"uninstalled again", "", "[]", http.StatusNotFound},
	}
	for _, tc := range cases {
		legacySetModuleState(t, id, tc.enabled, tc.installed)
		w := legacyGet(t, h, "/skin/PlayerOne.png")
		if w.Code != tc.want {
			t.Fatalf("%s status=%d want %d", tc.name, w.Code, tc.want)
		}
		if tc.want == http.StatusOK {
			legacyWantPNG(t, w, skin)
		}
	}
}

func TestLegacyPNGModuleStateError(t *testing.T) {
	h, id, dir := appFixtureWithOptionsAndDir(t, nil)
	legacyEnable(t, id)
	skin := pngBytes(t, 64, 64, 109)
	skinTID, _ := legacyTexture(t, id, dir, "LegacyErrSkin", "steve", skin, 1, true)
	legacyEquip(t, id, skinTID, -1)
	legacyWantPNG(t, legacyGet(t, h, "/skin/PlayerOne.png"), skin)

	// A corrupt enabled list is a state fault (503), not a disabled module.
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("options") + " SET option_value='{' WHERE option_name='plugins_enabled'"); err != nil {
		t.Fatal(err)
	}
	if w := legacyGet(t, h, "/skin/PlayerOne.png"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("corrupt enabled status=%d want 503", w.Code)
	}
	legacyEnable(t, id)
	// A corrupt installation list is likewise a state fault.
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("options") + " SET option_value='{' WHERE option_name='go_module_installations'"); err != nil {
		t.Fatal(err)
	}
	if w := legacyGet(t, h, "/skin/PlayerOne.png"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("corrupt installed status=%d want 503", w.Code)
	}
	legacyEnable(t, id)
	legacyWantPNG(t, legacyGet(t, h, "/skin/PlayerOne.png"), skin)
}

func TestLegacyPNGETagInvalidation(t *testing.T) {
	h, id, dir := appFixtureWithOptionsAndDir(t, nil)
	legacyEnable(t, id)
	skinA := pngBytes(t, 64, 64, 110)
	skinB := pngBytes(t, 64, 64, 111)
	tidA, _ := legacyTexture(t, id, dir, "LegacyETagA", "steve", skinA, 1, true)
	tidB, hashB := legacyTexture(t, id, dir, "LegacyETagB", "steve", skinB, 1, true)
	legacyEquip(t, id, tidA, -1)
	conditional := func(etag string) *httptest.ResponseRecorder {
		return legacyDo(t, h, "GET", "http://localhost/skin/skin/PlayerOne.png", map[string]string{"If-None-Match": etag})
	}

	w := legacyGet(t, h, "/skin/PlayerOne.png")
	legacyWantPNG(t, w, skinA)
	etagA := legacyWantETag(t, w, skinA)
	if w := conditional(etagA); w.Code != http.StatusNotModified || w.Body.Len() != 0 {
		t.Fatalf("same-state conditional status=%d body=%d want 304 empty", w.Code, w.Body.Len())
	}

	// Re-skinning changes the payload and the ETag; the old validator no
	// longer matches.
	legacyEquip(t, id, tidB, -1)
	w = legacyGet(t, h, "/skin/PlayerOne.png")
	legacyWantPNG(t, w, skinB)
	etagB := legacyWantETag(t, w, skinB)
	if etagB == etagA {
		t.Fatal("ETag unchanged after re-skin")
	}
	if w := conditional(etagA); w.Code != http.StatusOK {
		t.Fatalf("stale conditional status=%d want 200", w.Code)
	}
	if w := conditional(etagB); w.Code != http.StatusNotModified {
		t.Fatalf("new conditional status=%d want 304", w.Code)
	}

	// Clearing the slot withdraws the asset entirely.
	legacyEquip(t, id, -1, -1)
	if w := legacyGet(t, h, "/skin/PlayerOne.png"); w.Code != http.StatusNotFound {
		t.Fatalf("cleared slot status=%d want 404", w.Code)
	}
	if w := conditional(etagB); w.Code != http.StatusNotFound {
		t.Fatalf("cleared slot conditional status=%d want 404", w.Code)
	}
	legacyEquip(t, id, tidB, -1)
	legacyWantPNG(t, legacyGet(t, h, "/skin/PlayerOne.png"), skinB)

	// Deleting the texture row withdraws the asset.
	if _, err := id.Store.DB.Exec("DELETE FROM "+id.Store.Table("textures")+" WHERE tid=?", tidB); err != nil {
		t.Fatal(err)
	}
	if w := conditional(etagB); w.Code != http.StatusNotFound {
		t.Fatalf("deleted texture conditional status=%d want 404", w.Code)
	}
	if _, err := id.Store.DB.Exec("INSERT INTO "+id.Store.Table("textures")+" (tid,name,type,hash,size,uploader,public,likes,upload_at) VALUES (?,?,?,?,?,?,?,?,?)", tidB, "LegacyETagB", "steve", hashB, len(skinB), 1, 1, 0, "2020-01-01 00:00:00"); err != nil {
		t.Fatal(err)
	}
	legacyWantPNG(t, legacyGet(t, h, "/skin/PlayerOne.png"), skinB)

	// Deleting the file withdraws the asset.
	if err := os.Remove(filepath.Join(dir, hashB)); err != nil {
		t.Fatal(err)
	}
	if w := conditional(etagB); w.Code != http.StatusNotFound {
		t.Fatalf("deleted file conditional status=%d want 404", w.Code)
	}
	if err := os.WriteFile(filepath.Join(dir, hashB), skinB, 0o600); err != nil {
		t.Fatal(err)
	}
	legacyWantPNG(t, legacyGet(t, h, "/skin/PlayerOne.png"), skinB)

	// Deleting the player withdraws the asset.
	if _, err := id.Store.DB.Exec("DELETE FROM " + id.Store.Table("players") + " WHERE pid=1"); err != nil {
		t.Fatal(err)
	}
	if w := conditional(etagB); w.Code != http.StatusNotFound {
		t.Fatalf("deleted player conditional status=%d want 404", w.Code)
	}
	if _, err := id.Store.DB.Exec("INSERT INTO "+id.Store.Table("players")+" (pid,uid,name,tid_skin,tid_cape) VALUES (1,1,'PlayerOne',?,?)", tidB, -1); err != nil {
		t.Fatal(err)
	}
	legacyWantPNG(t, legacyGet(t, h, "/skin/PlayerOne.png"), skinB)

	// Banning the owner withdraws the asset.
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET permission=-1 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	if w := conditional(etagB); w.Code != http.StatusForbidden {
		t.Fatalf("banned conditional status=%d want 403", w.Code)
	}
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET permission=0 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	legacyWantPNG(t, legacyGet(t, h, "/skin/PlayerOne.png"), skinB)
}

func legacyRootFixture(t *testing.T) (http.Handler, *identity.Service, string) {
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
	texturesDir := t.TempDir()
	view := &site.Service{Store: store, Identity: id, Location: time.UTC, Modules: testsupport.Modules(store, id)}
	handler, err := New(config.Config{BaseURL: "http://localhost", Locale: "zh_CN", FallbackLocale: "en", RememberLifetime: 400 * 24 * time.Hour, TexturesDir: texturesDir}, id, view, oauth, yggdrasil.New(store, id, nil, []byte("synthetic-yggdrasil-hs256-key-32b"), false, id.Now), "m4-05-test")
	if err != nil {
		t.Fatal(err)
	}
	return handler, id, texturesDir
}

func TestLegacyPNGDeploymentPrefixAndJSONRoutes(t *testing.T) {
	// Subpath deployment: BaseURL carries the /skin prefix.
	h, id, dir := appFixtureWithOptionsAndDir(t, nil)
	legacyEnable(t, id)
	skin := pngBytes(t, 64, 64, 112)
	skinTID, _ := legacyTexture(t, id, dir, "LegacyPrefixSkin", "steve", skin, 1, true)
	legacyEquip(t, id, skinTID, -1)
	legacyWantPNG(t, legacyGet(t, h, "/skin/PlayerOne.png"), skin)
	// Existing JSON routes are untouched.
	w := legacyDo(t, h, "GET", "http://localhost/skin/PlayerOne.json", map[string]string{"Accept": "application/json"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"username":"PlayerOne"`) {
		t.Fatalf("profile JSON status=%d body=%s", w.Code, w.Body.String())
	}
	w = legacyDo(t, h, "GET", "http://localhost/skin/skinlib/list", map[string]string{"Accept": "application/json"})
	if w.Code != http.StatusOK {
		t.Fatalf("skinlib list status=%d body=%s", w.Code, w.Body.String())
	}

	// Root deployment: BaseURL has no path prefix; the route itself is
	// /skin/{player} at the host root.
	root, rootID, rootDir := legacyRootFixture(t)
	legacyEnable(t, rootID)
	rootSkin := pngBytes(t, 64, 64, 113)
	rootTID, _ := legacyTexture(t, rootID, rootDir, "LegacyRootSkin", "steve", rootSkin, 1, true)
	legacyEquip(t, rootID, rootTID, -1)
	legacyWantPNG(t, legacyDo(t, root, "GET", "http://localhost/skin/PlayerOne.png", nil), rootSkin)
	w = legacyDo(t, root, "GET", "http://localhost/PlayerOne.json", map[string]string{"Accept": "application/json"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"username":"PlayerOne"`) {
		t.Fatalf("root profile JSON status=%d body=%s", w.Code, w.Body.String())
	}
}
