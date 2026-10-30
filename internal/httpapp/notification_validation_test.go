package httpapp

import (
	"database/sql"
	"net/http/httptest"
	"strings"
	"testing"

	"blessing-skin-go/internal/config"
	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/web"
)

func TestAdminNotificationDatabaseFailure(t *testing.T) {
	assets, err := web.Load()
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("mysql", "")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	// A closed sql.DB returns a real query error without an external database.
	a := &App{cfg: config.Config{FallbackLocale: "en"}, assets: assets, site: &site.Service{Store: &database.Store{DB: db}}}
	b := &identity.BrowserSession{CSRF: "test-csrf"}
	for _, tc := range []struct{ name, body, contentType, accept string }{
		{"uid-json", `{"receiver":"uid","uid":1,"title":"Notice"}`, "application/json", "application/json"},
		{"email-json", `{"receiver":"email","email":"user@example.invalid","title":"Notice"}`, "application/json", "application/json"},
		{"uid-form", "receiver=uid&uid=1&title=Notice", "application/x-www-form-urlencoded", "text/html"},
		{"email-form", "receiver=email&email=user%40example.invalid&title=Notice", "application/x-www-form-urlencoded", "text/html"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://localhost/skin/admin/notifications/send", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.contentType)
			r.Header.Set("Accept", tc.accept)
			r.Header.Set("X-CSRF-TOKEN", b.CSRF)
			w := httptest.NewRecorder()
			a.adminSendNotification(w, r, b)
			if w.Code != 503 || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), `"errors"`) {
				t.Fatalf("DB failure misclassified: %d %s", w.Code, w.Body.String())
			}
		})
	}
}
