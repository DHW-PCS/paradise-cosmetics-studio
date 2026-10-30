package httpapp

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCanonicalLocale(t *testing.T) {
	for _, tc := range []struct {
		input, want string
		ok          bool
	}{
		{"zh_CN", "zh_CN", true},
		{"zh_TW", "zh_TW", true},
		{"en", "en", true},
		{"es_ES", "es_ES", true},
		{"ru_RU", "ru_RU", true},
		{"zh_HANS_CN", "zh_CN", true},
		{"en_US", "en", true},
		{"ru", "ru_RU", true},
		{" ru ", "ru_RU", true},
		{"", "", false},
		{"  ", "", false},
		{"x", "", false},
		{"de_DE", "", false},
		{"ja_JP", "", false},
		{"zh_CN.name", "", false},
		{"zh_Hans_CN", "", false},
		{"overrides", "", false},
		{strings.Repeat("x", 64), "", false},
	} {
		got, ok := canonicalLocale(tc.input)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("canonicalLocale(%q) = %q, %v; want %q, %v", tc.input, got, ok, tc.want, tc.ok)
		}
	}
}

// htmlRequest keeps the browser-style Accept header so page templates are
// rendered and their lang attribute can be asserted.
func htmlRequest(t *testing.T, h http.Handler, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", "http://localhost/skin"+target, nil)
	r.Header.Set("Accept", "text/html")
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestLocalePreferenceWritesAreValidated(t *testing.T) {
	h, id := appFixture(t)
	cookie, _ := credentials(t, h, false)
	admin, _ := credentials(t, h, true)

	read := func(uid int) (string, bool) {
		t.Helper()
		var value sql.NullString
		if err := id.Store.DB.QueryRow("SELECT locale FROM "+id.Store.Table("users")+" WHERE uid=?", uid).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value.String, value.Valid
	}
	assertLocale := func(uid int, want string, wantValid bool) {
		t.Helper()
		value, valid := read(uid)
		if value != want || valid != wantValid {
			t.Fatalf("uid %d locale = %q, %v; want %q, %v", uid, value, valid, want, wantValid)
		}
	}

	w := htmlRequest(t, h, "/user?lang=ru", cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `lang="ru-RU"`) {
		t.Fatalf("alias ru was not normalized: status=%d", w.Code)
	}
	assertLocale(1, "ru_RU", true)

	w = htmlRequest(t, h, "/user", cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `lang="ru-RU"`) {
		t.Fatalf("stored canonical locale was not applied: status=%d", w.Code)
	}

	for _, tc := range []struct{ query, want string }{
		{"zh_HANS_CN", "zh_CN"},
		{"en_US", "en"},
	} {
		w = htmlRequest(t, h, "/user?lang="+tc.query, cookie)
		if w.Code != 200 {
			t.Fatalf("%s: status=%d", tc.query, w.Code)
		}
		assertLocale(1, tc.want, true)
	}

	// Unconfigured, malformed and oversized values are ignored without
	// changing the stored preference or failing the page.
	for _, query := range []string{"de_DE", "zh_CN.name", "x", strings.Repeat("x", 64)} {
		w = htmlRequest(t, h, "/user?lang="+query, cookie)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `lang="en"`) {
			t.Fatalf("%s: invalid preference was not ignored: status=%d", query, w.Code)
		}
		assertLocale(1, "en", true)
	}

	// An empty value clears the nullable preference.
	w = htmlRequest(t, h, "/user?lang=", cookie)
	if w.Code != 200 {
		t.Fatalf("empty preference: status=%d", w.Code)
	}
	assertLocale(1, "", false)

	// The administrator path has the same non-fatal behaviour.
	w = htmlRequest(t, h, "/admin?lang=x", admin)
	if w.Code != 200 {
		t.Fatalf("admin invalid preference: status=%d", w.Code)
	}
	assertLocale(2, "", false)
}

func TestBodyLanguagePersistsCanonicalAndRejectsInvalid(t *testing.T) {
	h, id := appFixture(t)
	cookie, csrf := credentials(t, h, false)

	read := func() (string, bool) {
		t.Helper()
		var value sql.NullString
		if err := id.Store.DB.QueryRow("SELECT locale FROM " + id.Store.Table("users") + " WHERE uid=1").Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value.String, value.Valid
	}
	assertLocale := func(want string, wantValid bool) {
		t.Helper()
		value, valid := read()
		if value != want || valid != wantValid {
			t.Fatalf("locale = %q, %v; want %q, %v", value, valid, want, wantValid)
		}
	}

	w := request(t, h, "PUT", "/user/dark-mode?lang=zh_CN", `{"lang":"ru"}`, csrf, cookie)
	if w.Code != 204 {
		t.Fatalf("body language update failed: %d", w.Code)
	}
	assertLocale("ru_RU", true)

	// The body takes precedence over the query and invalid input is ignored.
	w = request(t, h, "PUT", "/user/dark-mode?lang=zh_CN", `{"lang":"de_DE"}`, csrf, cookie)
	if w.Code != 204 {
		t.Fatalf("invalid body language failed: %d", w.Code)
	}
	assertLocale("ru_RU", true)

	// An empty body value clears the nullable preference.
	w = request(t, h, "PUT", "/user/dark-mode?lang=zh_TW", `{"lang":""}`, csrf, cookie)
	if w.Code != 204 {
		t.Fatalf("empty body language failed: %d", w.Code)
	}
	assertLocale("", false)

	// With no body value the query is used and normalized.
	w = request(t, h, "PUT", "/user/dark-mode?lang=zh_TW", `{}`, csrf, cookie)
	if w.Code != 204 {
		t.Fatalf("query language update failed: %d", w.Code)
	}
	assertLocale("zh_TW", true)

	w = request(t, h, "PUT", "/user/dark-mode?lang=en", `{}`, "invalid", cookie)
	if w.Code != 419 {
		t.Fatalf("invalid CSRF accepted: %d", w.Code)
	}
	assertLocale("zh_TW", true)
}

func TestStoredLocaleIsNormalizedOrIgnored(t *testing.T) {
	h, id := appFixture(t)
	cookie, _ := credentials(t, h, false)

	update := func(value string) {
		t.Helper()
		if _, err := id.Store.DB.Exec("UPDATE "+id.Store.Table("users")+" SET locale=? WHERE uid=1", value); err != nil {
			t.Fatal(err)
		}
	}
	assertPageLang := func(w *httptest.ResponseRecorder, want string) {
		t.Helper()
		if w.Code != 200 || !strings.Contains(w.Body.String(), `lang="`+want+`"`) {
			t.Fatalf("page lang: status=%d want=%s", w.Code, want)
		}
	}

	update("ru")
	assertPageLang(htmlRequest(t, h, "/user", cookie), "ru-RU")

	// A stored value outside the configured locales is ignored, not fatal.
	update("de_DE")
	assertPageLang(htmlRequest(t, h, "/user", cookie), "en")

	// Ignoring the stored value falls through to the locale cookie.
	assertPageLang(htmlRequest(t, h, "/user", cookie, &http.Cookie{Name: "locale", Value: "zh_TW"}), "zh-TW")

	update(strings.Repeat("x", 64))
	assertPageLang(htmlRequest(t, h, "/user", cookie), "en")
}
