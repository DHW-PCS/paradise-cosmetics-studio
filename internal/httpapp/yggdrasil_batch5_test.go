package httpapp

import (
	"encoding/json"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"paradise-cosmetics-studio/internal/routes"
)

// TestYggdrasilCatalogMatchesLegacyRoutes pins the catalog entries
// against the legacy plugin routes.php (14 protocol routes under
// /api/yggdrasil, both search paths carrying the minecraft segment)
// plus the two admin routes from bootstrap.php. The third admin route
// (plugin config page) is the generic /admin/plugins/config/{name}
// catalog entry served by the core plugin dispatcher.
func TestYggdrasilCatalogMatchesLegacyRoutes(t *testing.T) {
	var got []string
	for _, r := range routes.Catalog {
		if strings.HasPrefix(r.Name, "ygg.") || r.Name == "admin.yggdrasil-log" || r.Name == "admin.plugins.config.yggdrasil-api.generate" {
			for _, method := range strings.Split(r.Method, "|") {
				got = append(got, method+" "+r.Path)
			}
		}
	}
	sort.Strings(got)
	want := []string{
		"DELETE /api/yggdrasil",
		"DELETE /api/yggdrasil/api/user/profile/{uuid}/{type}",
		"GET /admin/yggdrasil-log",
		"GET /api/yggdrasil",
		"GET /api/yggdrasil/api/users/profiles/minecraft/{username}",
		"GET /api/yggdrasil/minecraftservices/publickeys",
		"GET /api/yggdrasil/sessionserver/session/minecraft/hasJoined",
		"GET /api/yggdrasil/sessionserver/session/minecraft/profile/{uuid}",
		"HEAD /admin/yggdrasil-log",
		"HEAD /api/yggdrasil",
		"HEAD /api/yggdrasil/api/users/profiles/minecraft/{username}",
		"HEAD /api/yggdrasil/minecraftservices/publickeys",
		"HEAD /api/yggdrasil/sessionserver/session/minecraft/hasJoined",
		"HEAD /api/yggdrasil/sessionserver/session/minecraft/profile/{uuid}",
		"OPTIONS /api/yggdrasil",
		"PATCH /api/yggdrasil",
		"POST /admin/plugins/config/yggdrasil-api/generate",
		"POST /api/yggdrasil",
		"POST /api/yggdrasil/api/profiles/minecraft",
		"POST /api/yggdrasil/authserver/authenticate",
		"POST /api/yggdrasil/authserver/invalidate",
		"POST /api/yggdrasil/authserver/refresh",
		"POST /api/yggdrasil/authserver/signout",
		"POST /api/yggdrasil/authserver/validate",
		"POST /api/yggdrasil/sessionserver/session/minecraft/join",
		"PUT /api/yggdrasil",
		"PUT /api/yggdrasil/api/user/profile/{uuid}/{type}",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("catalog Yggdrasil routes differ from legacy routes.php\n got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestYggdrasilHTTPContractEdges covers the wire-level edges the
// service tests cannot see: ANY hello methods, empty search arrays,
// the protocol error object shape, a second non-JSON middleware
// sample, and the installed-but-not-enabled module gate.
func TestYggdrasilHTTPContractEdges(t *testing.T) {
	h, id := appFixture(t)
	yggEnable(t, id)
	// hello is ANY: non-GET verbs answer the same metadata document.
	for _, method := range []string{"PUT", "DELETE", "OPTIONS"} {
		w := yggJSON(t, h, method, "/api/yggdrasil", "")
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"implementationVersion":"m4-05-test"`) {
			t.Fatalf("hello %s status=%d body=%s", method, w.Code, w.Body.String())
		}
	}
	// Empty name arrays serialize as [] (never null or 204).
	for _, body := range []string{`[]`, ``} {
		w := yggJSON(t, h, "POST", "/api/yggdrasil/api/profiles/minecraft", body)
		if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
			t.Fatalf("empty search body=%q status=%d resp=%s", body, w.Code, w.Body.String())
		}
	}
	// Protocol errors carry the frozen {error,errorMessage} object.
	w := yggJSON(t, h, "POST", "/api/yggdrasil/authserver/authenticate", `{"username":"user@example.invalid","password":"wrong-password"}`)
	if w.Code != 403 {
		t.Fatalf("bad password status=%d body=%s", w.Code, w.Body.String())
	}
	var errObj map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &errObj); err != nil {
		t.Fatal(err)
	}
	if errObj["error"] != "ForbiddenOperationException" || errObj["errorMessage"] == "" {
		t.Fatalf("error object = %+v", errObj)
	}
	// Non-JSON validate keeps the 200 Unsupported Media Type object.
	r := httptest.NewRequest("POST", "http://localhost/skin/api/yggdrasil/authserver/validate", strings.NewReader("accessToken=x"))
	r.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Unsupported Media Type") {
		t.Fatalf("non-JSON validate status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// TestYggdrasilPublicKeysInstalledOnlyGate checks that an installed
// but not enabled module does not serve either the publickeys entry
// or the metadata entry, even with the environment switch on.
func TestYggdrasilPublicKeysInstalledOnlyGate(t *testing.T) {
	handler, id := yggEnabledFixture(t)
	yggEnable(t, id)
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("options") + " SET option_value='[]' WHERE option_name='go_module_installations'"); err != nil {
		t.Fatal(err)
	}
	if w := yggJSON(t, handler, "GET", "/api/yggdrasil/minecraftservices/publickeys", ""); w.Code != 404 {
		t.Fatalf("installed-only publickeys status=%d body=%s", w.Code, w.Body.String())
	}
	if w := yggJSON(t, handler, "GET", "/api/yggdrasil", ""); w.Code != 404 {
		t.Fatalf("installed-only hello status=%d body=%s", w.Code, w.Body.String())
	}
}
