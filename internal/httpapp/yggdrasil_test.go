package httpapp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"image"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/config"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/oauthserver"
	"paradise-cosmetics-studio/internal/players"
	"paradise-cosmetics-studio/internal/site"
	"paradise-cosmetics-studio/internal/testsupport"
	"paradise-cosmetics-studio/internal/yggdrasil"
)

// yggEnable installs and enables the module and seeds the protocol
// options, returning the 4096-bit private key PEM.
func yggEnable(t *testing.T, id *identity.Service) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	// The seeded PlayerOne needs a current UUID binding, mirroring the
	// yggdrasil package fixture.
	uuidVal := players.UUID3("PlayerOne")
	if _, err := id.Store.DB.Exec("INSERT INTO "+id.Store.Table("uuid")+" (name,uuid) VALUES (?,?)", "PlayerOne", uuidVal); err != nil {
		t.Fatal(err)
	}
	var uuidRowID int64
	if err := id.Store.DB.QueryRow("SELECT id FROM "+id.Store.Table("uuid")+" WHERE name=? ORDER BY id LIMIT 1", "PlayerOne").Scan(&uuidRowID); err != nil {
		t.Fatal(err)
	}
	if _, err := id.Store.DB.Exec("INSERT INTO "+id.Store.Table("go_uuid_bindings")+" (pid,uuid_row_id,uuid,version) VALUES (1,?,?,1)", uuidRowID, uuidVal); err != nil {
		t.Fatal(err)
	}
	// The fixture already owns the two module-state rows; update them
	// instead of inserting ambiguous duplicates.
	for name, value := range map[string]string{
		"plugins_enabled":         `[{"name":"yggdrasil-api","version":"5.2.1"}]`,
		"go_module_installations": `[{"name":"yggdrasil-api","version":"5.2.1"}]`,
	} {
		if _, err := id.Store.DB.Exec("UPDATE "+id.Store.Table("options")+" SET option_value=? WHERE option_name=?", value, name); err != nil {
			t.Fatal(err)
		}
	}
	for name, value := range map[string]string{
		"ygg_private_key":        pemText,
		"ygg_token_expire_1":     "3600",
		"ygg_token_expire_2":     "86400",
		"ygg_tokens_limit":       "10",
		"ygg_search_profile_max": "5",
		"site_url":               "http://localhost/skin",
		"ygg_skin_domain":        "extra.example.invalid",
	} {
		if _, err := id.Store.DB.Exec("INSERT INTO "+id.Store.Table("options")+" (option_name,option_value) VALUES (?,?)", name, value); err != nil {
			t.Fatal(err)
		}
	}
	return pemText
}

func yggJSON(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://localhost/skin"+target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func yggAuthenticateToken(t *testing.T, h http.Handler) string {
	t.Helper()
	w := yggJSON(t, h, "POST", "/api/yggdrasil/authserver/authenticate", `{"username":"user@example.invalid","password":"original-password","clientToken":"client-1"}`)
	if w.Code != 200 {
		t.Fatalf("authenticate status=%d body=%s", w.Code, w.Body.String())
	}
	var res struct {
		AccessToken string `json:"accessToken"`
		ClientToken string `json:"clientToken"`
		Profiles    []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"availableProfiles"`
		Selected *struct {
			ID string `json:"id"`
		} `json:"selectedProfile"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.AccessToken == "" || len(res.Profiles) != 1 || res.Profiles[0].Name != "PlayerOne" || res.Selected == nil {
		t.Fatalf("authenticate body=%s", w.Body.String())
	}
	return res.AccessToken
}

func TestYggdrasilHelloAndModuleGate(t *testing.T) {
	h, id := appFixture(t)
	// Unregistered module: 404 protocol shape.
	if w := yggJSON(t, h, "GET", "/api/yggdrasil", ""); w.Code != 404 || !strings.Contains(w.Body.String(), "NotFoundException") {
		t.Fatalf("disabled hello status=%d body=%s", w.Code, w.Body.String())
	}
	yggEnable(t, id)
	if w := yggJSON(t, h, "GET", "/api/yggdrasil", ""); w.Code != 200 {
		t.Fatalf("hello status=%d body=%s", w.Code, w.Body.String())
	} else {
		body := w.Body.String()
		for _, text := range []string{`"implementationName":"Yggdrasil API for Paradise Cosmetics Studio"`, `"implementationVersion":"m4-05-test"`, `"feature.non_email_login":true`, "extra.example.invalid", "/auth/register", "localhost"} {
			if !strings.Contains(body, text) {
				t.Fatalf("hello missing %q in %s", text, body)
			}
		}
		if !strings.Contains(body, "-----BEGIN PUBLIC KEY-----") {
			t.Fatalf("hello missing PEM public key in %s", body)
		}
	}
	// Public keys stay off by default in the fixture config.
	if w := yggJSON(t, h, "GET", "/api/yggdrasil/minecraftservices/publickeys", ""); w.Code != 404 {
		t.Fatalf("publickeys default status=%d", w.Code)
	}
	// Bad private key: hello keeps the approved 400.
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("options") + " SET option_value='garbage' WHERE option_name='ygg_private_key'"); err != nil {
		t.Fatal(err)
	}
	if w := yggJSON(t, h, "GET", "/api/yggdrasil", ""); w.Code != 400 || !strings.Contains(w.Body.String(), "IllegalArgumentException") {
		t.Fatalf("bad key hello status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestYggdrasilAuthSessionAndProfileFlow(t *testing.T) {
	h, id := appFixture(t)
	yggEnable(t, id)
	token := yggAuthenticateToken(t, h)
	// Non-JSON authenticate keeps the 200 error object.
	r := httptest.NewRequest("POST", "http://localhost/skin/api/yggdrasil/authserver/authenticate", strings.NewReader("username=x"))
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Unsupported Media Type") {
		t.Fatalf("content-type status=%d body=%s", w.Code, w.Body.String())
	}
	// Validate and refresh.
	if w := yggJSON(t, h, "POST", "/api/yggdrasil/authserver/validate", `{"accessToken":"`+token+`","clientToken":"client-1"}`); w.Code != 204 || w.Body.Len() != 0 {
		t.Fatalf("validate status=%d body=%s", w.Code, w.Body.String())
	}
	{
		w := yggJSON(t, h, "POST", "/api/yggdrasil/authserver/refresh", `{"accessToken":"`+token+`","clientToken":"client-1"}`)
		if w.Code != 200 {
			t.Fatalf("refresh status=%d body=%s", w.Code, w.Body.String())
		}
		var refreshed struct {
			AccessToken string `json:"accessToken"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &refreshed); err != nil || refreshed.AccessToken == "" {
			t.Fatalf("refresh body=%s err=%v", w.Body.String(), err)
		}
		// Refresh rotates the token; the old one no longer joins.
		token = refreshed.AccessToken
	}
	uuidHex := players.UUID3("PlayerOne")
	dashed := yggdrasil.MustDashed(uuidHex)
	// Join then hasJoined returns the signed profile.
	if w := yggJSON(t, h, "POST", "/api/yggdrasil/sessionserver/session/minecraft/join", `{"accessToken":"`+token+`","selectedProfile":"`+dashed+`","serverId":"srv-1"}`); w.Code != 204 {
		t.Fatalf("join status=%d body=%s", w.Code, w.Body.String())
	}
	if w := yggJSON(t, h, "GET", "/api/yggdrasil/sessionserver/session/minecraft/hasJoined?username=PlayerOne&serverId=srv-1", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"signature":"`) {
		t.Fatalf("hasJoined status=%d body=%s", w.Code, w.Body.String())
	}
	// Profile unsigned by default, signed only with unsigned=false.
	if w := yggJSON(t, h, "GET", "/api/yggdrasil/sessionserver/session/minecraft/profile/"+dashed, ""); w.Code != 200 || strings.Contains(w.Body.String(), `"signature":"`) {
		t.Fatalf("profile unsigned status=%d body=%s", w.Code, w.Body.String())
	}
	if w := yggJSON(t, h, "GET", "/api/yggdrasil/sessionserver/session/minecraft/profile/"+dashed+"?unsigned=false", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"signature":"`) {
		t.Fatalf("profile signed status=%d body=%s", w.Code, w.Body.String())
	}
	if w := yggJSON(t, h, "GET", "/api/yggdrasil/sessionserver/session/minecraft/profile/00000000000000000000000000000000", ""); w.Code != 204 {
		t.Fatalf("missing profile status=%d", w.Code)
	}
	// Search endpoints.
	if w := yggJSON(t, h, "POST", "/api/yggdrasil/api/profiles/minecraft", `["PlayerOne","Missing"]`); w.Code != 200 || !strings.Contains(w.Body.String(), "PlayerOne") {
		t.Fatalf("search multiple status=%d body=%s", w.Code, w.Body.String())
	}
	if w := yggJSON(t, h, "GET", "/api/yggdrasil/api/users/profiles/minecraft/PlayerOne", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"name":"PlayerOne"`) {
		t.Fatalf("search single status=%d body=%s", w.Code, w.Body.String())
	}
	if w := yggJSON(t, h, "GET", "/api/yggdrasil/api/users/profiles/minecraft/Missing", ""); w.Code != 204 {
		t.Fatalf("search missing status=%d", w.Code)
	}
	// Invalidate is idempotent.
	if w := yggJSON(t, h, "POST", "/api/yggdrasil/authserver/invalidate", `{"accessToken":"unknown"}`); w.Code != 204 {
		t.Fatalf("invalidate status=%d", w.Code)
	}
}

func TestYggdrasilUploadAndReset(t *testing.T) {
	h, id := appFixture(t)
	yggEnable(t, id)
	token := yggAuthenticateToken(t, h)
	uuidHex := players.UUID3("PlayerOne")
	dashed := yggdrasil.MustDashed(uuidHex)
	img := image.NewRGBA(image.Rect(0, 0, 64, 32))
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "NewSkin.png")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("PUT", "http://localhost/skin/api/yggdrasil/api/user/profile/"+dashed+"/skin", &body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("upload status=%d body=%s", w.Code, w.Body.String())
	}
	// The texture is equipped as the player's skin.
	var tid int64
	if err := id.Store.DB.QueryRow("SELECT tid_skin FROM " + id.Store.Table("players") + " WHERE name='PlayerOne'").Scan(&tid); err != nil || tid <= 0 {
		t.Fatalf("skin not equipped tid=%d err=%v", tid, err)
	}
	// Missing bearer is the legacy 401.
	r = httptest.NewRequest("DELETE", "http://localhost/skin/api/yggdrasil/api/user/profile/"+dashed+"/skin", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 || !strings.Contains(w.Body.String(), "UnauthorizedException") {
		t.Fatalf("reset without bearer status=%d body=%s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest("DELETE", "http://localhost/skin/api/yggdrasil/api/user/profile/"+dashed+"/skin", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("reset status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestYggdrasilAdminPagesAndHeader(t *testing.T) {
	h, id := appFixture(t)
	admin, csrf := credentials(t, h, true)
	yggEnable(t, id)
	// ALI off by default: no header anywhere.
	if w := yggJSON(t, h, "GET", "/api/yggdrasil", ""); w.Header().Get("X-Authlib-Injector-API-Location") != "" {
		t.Fatal("ALI header present while option off")
	}
	if _, err := id.Store.DB.Exec("INSERT INTO " + id.Store.Table("options") + " (option_name,option_value) VALUES ('ygg_enable_ali','true'),('ygg_show_config_section','true')"); err != nil {
		t.Fatal(err)
	}
	if w := yggJSON(t, h, "GET", "/api/yggdrasil", ""); w.Header().Get("X-Authlib-Injector-API-Location") != "http://localhost/skin/api/yggdrasil" {
		t.Fatalf("ALI header missing: %q", w.Header().Get("X-Authlib-Injector-API-Location"))
	}
	if w := request(t, h, "GET", "/user", "", "", admin); w.Header().Get("X-Authlib-Injector-API-Location") == "" || !strings.Contains(w.Body.String(), "ygg-dnd-button") {
		t.Fatalf("user page ALI/dnd missing status=%d", w.Code)
	}
	// Config page renders and saves the common form.
	if w := request(t, h, "GET", "/admin/plugins/config/yggdrasil-api", "", "", admin); w.Code != 200 || !strings.Contains(w.Body.String(), "Yggdrasil API Configuration") {
		t.Fatalf("config page status=%d", w.Code)
	}
	w := postForm(t, h, "/admin/plugins/config/yggdrasil-api", "option=common&ygg_uuid_algorithm=v4&ygg_token_expire_1=100&ygg_token_expire_2=200&ygg_tokens_limit=3&ygg_rate_limit=0&ygg_skin_domain=&ygg_search_profile_max=5&ygg_show_config_section=true&ygg_enable_ali=true", admin, csrf)
	if w.Code != 302 {
		t.Fatalf("config save status=%d", w.Code)
	}
	var value string
	if err := id.Store.DB.QueryRow("SELECT option_value FROM " + id.Store.Table("options") + " WHERE option_name='ygg_uuid_algorithm'").Scan(&value); err != nil || value != "v4" {
		t.Fatalf("saved algorithm %q err=%v", value, err)
	}
	// Generate returns a candidate key without saving it.
	before := ""
	_ = id.Store.DB.QueryRow("SELECT option_value FROM " + id.Store.Table("options") + " WHERE option_name='ygg_private_key'").Scan(&before)
	w = request(t, h, "POST", "/admin/plugins/config/yggdrasil-api/generate", "", csrf, admin)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("generate status=%d body=%s", w.Code, w.Body.String())
	}
	var generated struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &generated); err != nil || generated.Key == "" || generated.Key == before {
		t.Fatalf("generated key not a fresh candidate: %v", err)
	}
	after := ""
	if err := id.Store.DB.QueryRow("SELECT option_value FROM " + id.Store.Table("options") + " WHERE option_name='ygg_private_key'").Scan(&after); err != nil || after != before {
		t.Fatalf("generate saved the key: err=%v", err)
	}
	// Log page shows desensitized parameters only.
	if _, err := id.Store.DB.Exec("INSERT INTO " + id.Store.Table("ygg_log") + " (action,user_id,player_id,parameters,ip,time) VALUES ('authenticate',1,1,'{\"selectedProfile\":\"x\",\"accessToken\":\"secret-token\"}','127.0.0.1','2026-11-04 10:00:00')"); err != nil {
		t.Fatal(err)
	}
	if w := request(t, h, "GET", "/admin/yggdrasil-log", "", "", admin); w.Code != 200 || strings.Contains(w.Body.String(), "secret-token") || !strings.Contains(w.Body.String(), "selectedProfile") {
		t.Fatalf("log page status=%d body=%s", w.Code, w.Body.String())
	}
	// Public key base64 decodes to DER bytes.
	block, _ := pem.Decode([]byte(before))
	if block == nil {
		_ = base64.StdEncoding
		t.Fatal("seeded key is not PEM")
	}
}

func TestYggdrasilPublicKeysEnabled(t *testing.T) {
	handler, id := yggEnabledFixture(t)
	yggEnable(t, id)
	w := yggJSON(t, handler, "GET", "/api/yggdrasil/minecraftservices/publickeys", "")
	if w.Code != 200 {
		t.Fatalf("publickeys status=%d body=%s", w.Code, w.Body.String())
	}
	var res struct {
		ProfileKeys []struct {
			PublicKey string `json:"publicKey"`
		} `json:"profilePropertyKeys"`
		CertKeys []struct {
			PublicKey string `json:"publicKey"`
		} `json:"playerCertificateKeys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil || len(res.ProfileKeys) != 1 || res.ProfileKeys[0].PublicKey == "" {
		t.Fatalf("publickeys body=%s err=%v", w.Body.String(), err)
	}
	if res.ProfileKeys[0].PublicKey != res.CertKeys[0].PublicKey {
		t.Fatal("property and certificate keys differ")
	}
	if _, err := base64.StdEncoding.DecodeString(res.ProfileKeys[0].PublicKey); err != nil {
		t.Fatalf("public key is not base64 DER: %v", err)
	}
	// Disabled module answers 404 even with the env switch on.
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("options") + " SET option_value='[]' WHERE option_name='plugins_enabled'"); err != nil {
		t.Fatal(err)
	}
	if w := yggJSON(t, handler, "GET", "/api/yggdrasil/minecraftservices/publickeys", ""); w.Code != 404 {
		t.Fatalf("publickeys disabled status=%d", w.Code)
	}
}

// yggEnabledFixture mirrors appFixtureWithOptionsAndDir with the
// publickeys environment switch on.
func yggEnabledFixture(t *testing.T) (http.Handler, *identity.Service) {
	t.Helper()
	store, id := testsupport.Database(t, "ygg-keys-")
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
	view := &site.Service{Store: store, Identity: id, Location: time.UTC, Modules: testsupport.Modules(store, id)}
	handler, err := New(config.Config{BaseURL: "http://localhost/skin", Locale: "zh_CN", FallbackLocale: "en", RememberLifetime: 400 * 24 * time.Hour, TexturesDir: t.TempDir(), YggdrasilPublicKeysEnabled: true}, id, view, oauth, yggdrasil.New(store, id, nil, []byte("synthetic-yggdrasil-hs256-key-32b"), false, id.Now), "m4-05-test")
	if err != nil {
		t.Fatal(err)
	}
	return handler, id
}
