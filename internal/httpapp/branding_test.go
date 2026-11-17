package httpapp

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/config"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/web"
)

func TestProductCookieNames(t *testing.T) {
	a := &App{cfg: config.Config{SecureCookie: true}, basePath: "/skin"}
	for _, oldName := range []string{"bs_go_session", "bs_go_remember", "BS_SESSION", "bs_remember"} {
		r := httptest.NewRequest("GET", "https://localhost/skin/user", nil)
		r.AddCookie(&http.Cookie{Name: oldName, Value: "previous-token"})
		if b, err := a.current(r); b != nil || !errors.Is(err, identity.ErrSession) {
			t.Fatalf("old cookie %s accepted: %v", oldName, err)
		}
	}
	r := httptest.NewRequest("GET", "https://localhost/skin/api/user", nil)
	r.AddCookie(&http.Cookie{Name: "bs_go_api", Value: "previous-api-token"})
	if b, err := a.ResolveAPICookie(r); b != nil || !errors.Is(err, identity.ErrSession) {
		t.Fatalf("old API cookie accepted: %v", err)
	}
	w := httptest.NewRecorder()
	a.cookie(w, sessionCookie, "session-token", time.Time{})
	a.cookie(w, rememberCookie, "remember-token", time.Now().Add(time.Hour))
	a.cookie(w, apiCookieName, "api-token", time.Now().Add(time.Hour))
	cookies := w.Result().Cookies()
	if len(cookies) != 3 || cookies[0].Name != "pcs_session" || cookies[1].Name != "pcs_remember" || cookies[2].Name != "pcs_api" {
		t.Fatalf("cookies = %v", cookies)
	}
	for _, c := range cookies {
		if c.Path != "/skin/" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
			t.Errorf("cookie attributes changed: %v", c)
		}
	}
}

func TestProductFooterChoicesAndGlobals(t *testing.T) {
	assets, err := web.Load()
	if err != nil {
		t.Fatal(err)
	}
	for style := 0; style < 7; style++ {
		var body bytes.Buffer
		if err := assets.Templates.ExecuteTemplate(&body, "copyright", map[string]any{"CopyrightStyle": style}); err != nil {
			t.Fatal(err)
		}
		want := copyrightChoice(map[string]any{"copyright_prefer": style})
		if !strings.Contains(body.String(), want) || !strings.Contains(want, "Paradise Cosmetics Studio") || strings.Contains(body.String(), "Blessing") || strings.Contains(body.String(), "href=") {
			t.Errorf("footer %d = %s; API copyright = %s", style, body.String(), want)
		}
	}
	var head bytes.Buffer
	if err := assets.Templates.ExecuteTemplate(&head, "head", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(head.String(), `id="pcs-globals"`) || strings.Contains(head.String(), "blessing-globals") {
		t.Fatalf("head globals = %s", head.String())
	}
	if !strings.HasPrefix(string(assets.ReadmeYggdrasilAPI), "# Yggdrasil API for Paradise Cosmetics Studio\n") {
		t.Fatal("readme product identity missing")
	}
}
