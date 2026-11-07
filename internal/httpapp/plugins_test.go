package httpapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"strings"
	"testing"
	"time"

	"blessing-skin-go/internal/config"
	"blessing-skin-go/internal/oauthserver"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/testsupport"
	"blessing-skin-go/internal/yggdrasil"
)

// The manage page renders the frozen admin layout with the plugin route.
func TestAdminPluginManagePageLayout(t *testing.T) {
	h, _ := appFixture(t)
	cookie, _ := credentials(t, h, true)
	w := request(t, h, "GET", "/admin/plugins/manage", "", "", cookie)
	if w.Code != 200 {
		t.Fatalf("manage page layout status=%d", w.Code)
	}
	body := w.Body.String()
	// The frozen menu item and page title resolve through the original text.
	if !strings.Contains(body, "Plugins") {
		t.Fatal("plugin manage title missing")
	}
}

func TestAdminPluginDataAndActions(t *testing.T) {
	h, id := appFixture(t)
	admin, csrf := credentials(t, h, true)
	member, _ := credentials(t, h, false)

	// Only registered modules appear, in the original directory order.
	if _, err := id.Store.DB.Exec("UPDATE "+id.Store.Table("options")+" SET option_value=? WHERE option_name='go_module_installations'", `[{"name":"legacy-api","version":"1.1.3"},{"name":"yggdrasil-api","version":"5.2.1"}]`); err != nil {
		t.Fatal(err)
	}
	w := request(t, h, "GET", "/admin/plugins/data", "", "", admin)
	if w.Code != 200 {
		t.Fatalf("plugin data status=%d", w.Code)
	}
	body := w.Body.String()
	for _, text := range []string{`"name":"legacy-api"`, `"title":"Legacy Skin Loading"`, `"name":"yggdrasil-api"`, `"title":"Yggdrasil API"`, `"version":"5.2.1"`, `"enabled":false`, `"config":true`, `"readme":true`, `"faType":"fas"`, `"bg":"purple"`} {
		if !strings.Contains(body, text) {
			t.Fatalf("plugin data field got lost: %s body=%s", text, body)
		}
	}
	// Visitors and members stay away from the admin dispatch.
	w = request(t, h, "GET", "/admin/plugins/data", "", "", nil)
	if w.Code != 401 {
		t.Fatalf("guest plugin data status=%d", w.Code)
	}
	w = request(t, h, "GET", "/admin/plugins/data", "", "", member)
	if w.Code != 403 {
		t.Fatalf("member plugin data status=%d", w.Code)
	}
	// Enable succeeds for a registered module and appends the frozen version.
	w = request(t, h, "POST", "/admin/plugins/manage", `{"action":"enable","name":"legacy-api"}`, csrf, admin)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("enable response status=%d body=%s", w.Code, w.Body.String())
	}
	var enabled string
	if err := id.Store.DB.QueryRow("SELECT option_value FROM " + id.Store.Table("options") + " WHERE option_name='plugins_enabled'").Scan(&enabled); err != nil || enabled != `[{"name":"legacy-api","version":"1.1.3"}]` {
		t.Fatalf("enable state err=%v value=%s", err, enabled)
	}
	// enable + CSRF failures and not-found responses keep original shapes.
	w = request(t, h, "POST", "/admin/plugins/manage", `{"action":"enable","name":"legacy-api"}`, "", admin)
	if w.Code != 419 {
		t.Fatalf("missing CSRF status=%d", w.Code)
	}
	w = request(t, h, "POST", "/admin/plugins/manage", `{"action":"enable","name":"invitation-codes"}`, csrf, admin)
	if !strings.Contains(w.Body.String(), `"code":1`) || !strings.Contains(w.Body.String(), "No such plugin") {
		t.Fatalf("unregistered enable not refused: %s", w.Body.String())
	}
	w = request(t, h, "POST", "/admin/plugins/manage", `{"action":"rename","name":"legacy-api"}`, csrf, admin)
	if !strings.Contains(w.Body.String(), "Invalid action") {
		t.Fatalf("invalid action response: %s", w.Body.String())
	}
	// Disable keeps an idempotent success and preserves foreign entries.
	if _, err := id.Store.DB.Exec("UPDATE "+id.Store.Table("options")+" SET option_value=? WHERE option_name='plugins_enabled'", `["disable-registration",{"name":"legacy-api","version":"1.1.3"}]`); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "POST", "/admin/plugins/manage", `{"action":"disable","name":"legacy-api"}`, csrf, admin)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("disable response: %s", w.Body.String())
	}
	if err := id.Store.DB.QueryRow("SELECT option_value FROM " + id.Store.Table("options") + " WHERE option_name='plugins_enabled'").Scan(&enabled); err != nil || enabled != `["disable-registration"]` {
		t.Fatalf("disable state err=%v value=%s", err, enabled)
	}
	// Uninstall removes registration and enablement in one action.
	if _, err := id.Store.DB.Exec("UPDATE "+id.Store.Table("options")+" SET option_value=? WHERE option_name='plugins_enabled'", `[{"name":"legacy-api","version":"1.1.3"}]`); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "POST", "/admin/plugins/manage", `{"action":"delete","name":"legacy-api"}`, csrf, admin)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("uninstall response: %s", w.Body.String())
	}
	var installed string
	if err := id.Store.DB.QueryRow("SELECT option_value FROM " + id.Store.Table("options") + " WHERE option_name='go_module_installations'").Scan(&installed); err != nil || installed != `[{"name":"yggdrasil-api","version":"5.2.1"}]` {
		t.Fatalf("uninstall registration err=%v value=%s", err, installed)
	}
	w = request(t, h, "GET", "/admin/plugins/data", "", "", admin)
	if strings.Contains(w.Body.String(), `"name":"legacy-api"`) {
		t.Fatalf("uninstalled module still listed: %s", w.Body.String())
	}
	// The core dispatch contacts answer with the original abort messages.
	w = request(t, h, "GET", "/admin/plugins/config/yggdrasil-api", "", "", admin)
	if w.Code != 404 || !strings.Contains(w.Body.String(), "configuration page.") {
		t.Fatalf("config dispatch status=%d", w.Code)
	}
	// The readme dispatch renders the frozen module README through the same
	// admin page shape; the module card declares readme=true (B5-F1).
	w = request(t, h, "GET", "/admin/plugins/readme/yggdrasil-api", "", "", admin)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Yggdrasil API") || !strings.Contains(w.Body.String(), "authlib-injector") {
		t.Fatalf("readme dispatch status=%d", w.Code)
	}
	// Modules without a readme keep the original abort notice.
	w = request(t, h, "GET", "/admin/plugins/readme/legacy-api", "", "", admin)
	if w.Code != 404 || !strings.Contains(w.Body.String(), "readme file.") {
		t.Fatalf("readme dispatch status=%d", w.Code)
	}
}

// An owner's enable readiness check surfaces as the original unsatisfied
// response with its translated reason list; the module writes roll back.
func TestAdminPluginEnableCheckRespondsOriginalArray(t *testing.T) {
	store, id := testsupport.Database(t, "plugins-check-")
	man := testsupport.Modules(store, id)
	if err := man.RegisterCheck("legacy-api", func(context.Context, *sql.Tx) ([]string, error) {
		return []string{"legacy reintroduced reason"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec("UPDATE "+store.Table("options")+" SET option_value=? WHERE option_name='go_module_installations'", `[{"name":"legacy-api","version":"1.1.3"}]`); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oauth, err := oauthserver.New(oauthserver.Config{Store: store, Identity: id, PrivateKey: key, Secret: []byte("synthetic-m2-secret-at-least-32-bytes"), Issuer: "http://localhost/skin", Scopes: oauthserver.DefaultScopes, AccessLifetime: time.Hour, RefreshLifetime: 24 * time.Hour, CodeLifetime: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(config.Config{BaseURL: "http://localhost/skin", Locale: "zh_CN", FallbackLocale: "en", RememberLifetime: 400 * 24 * time.Hour, TexturesDir: t.TempDir()}, id, &site.Service{Store: store, Identity: id, Location: time.UTC, Modules: man}, oauth, yggdrasil.New(store, id, nil, []byte("synthetic-yggdrasil-hs256-key-32b"), false, id.Now), "m4-05-test")
	if err != nil {
		t.Fatal(err)
	}
	admin, csrf := credentials(t, handler, true)
	w := request(t, handler, "POST", "/admin/plugins/manage", `{"action":"enable","name":"legacy-api"}`, csrf, admin)
	if w.Code != 200 {
		t.Fatalf("enable check response status=%d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"code":1`) || !strings.Contains(body, `"data":{"reason":["legacy reintroduced reason"]}`) {
		t.Fatalf("enable check response lost the array shape: %s", body)
	}
	var value string
	if err := store.DB.QueryRow("SELECT option_value FROM " + store.Table("options") + " WHERE option_name='plugins_enabled'").Scan(&value); err != nil || value != "" {
		t.Fatalf("refused enable committed state: %v %q", err, value)
	}
}
