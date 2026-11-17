package httpapp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"paradise-cosmetics-studio/internal/oauthserver"
)

// M4-07 fix-batch focused regressions (compile + no-DB template check
// here; DB-backed rename check runs under the next batch's real-DB pass).
//
// F4/F13: the consent page must carry the shared auth layout head/foot
// (stylesheet, meta.js, CSRF meta, foot scripts) and the current locale,
// not bare HTML with lang="en".
func TestM407ConsentTemplateSharedHeadFootAndLocale(t *testing.T) {
	var body bytes.Buffer
	view := consentView{
		ClientName:   "reference-client",
		CSRF:         "synthetic-csrf",
		AuthToken:    "synthetic-pending",
		BaseURL:      "http://localhost/skin",
		SiteName:     "Example",
		Title:        "Authorization",
		Introduction: "intro",
		Permissions:  "Permissions",
		Approve:      "Authorize",
		Cancel:       "Cancel",
		Language:     "zh-CN",
		ThemeColor:   "#007bff",
		Favicon:      "http://localhost/skin/favicon.ico",
		CSS:          []string{"http://localhost/skin/app/style.7eb5d06.css"},
		MetaJS:       []string{"http://localhost/skin/app/meta.bbc5028.js"},
		AppJS:        []string{"http://localhost/skin/app/app.be534b0.js"},
		Globals:      map[string]any{"locale": "zh_CN"},
		Extra:        map[string]any{"tooManyFails": false},
		Scopes:       []oauthserver.ScopeDisplay{{Name: "User.Read", Description: "desc"}},
	}
	if err := consentTemplate.ExecuteTemplate(&body, "authorize", view); err != nil {
		t.Fatal(err)
	}
	text := body.String()
	for _, want := range []string{
		`lang="zh-CN"`,
		`name="csrf-token" content="synthetic-csrf"`,
		`rel="stylesheet" href="http://localhost/skin/app/style.7eb5d06.css"`,
		`<script src="http://localhost/skin/app/meta.bbc5028.js"></script>`,
		`<script src="http://localhost/skin/app/app.be534b0.js"></script>`,
		`id="pcs-globals"`,
		`id="pcs-extra"`,
		"login-box",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("consent page missing %q", want)
		}
	}
	if strings.Contains(text, `lang="en"`) {
		t.Errorf("consent page still hard-codes lang=en")
	}
}

// F16: the player rename success message must substitute the actual old
// and new names (frozen :old/:new placeholders), never leak them raw.
func TestM407CoreAPIPlayerRenameMessageSubstituted(t *testing.T) {
	h, _ := coreFixture(t)
	token := coreToken(t, h, "user@example.invalid", "*")
	w := coreReq(t, h, "PUT", "/api/players/1/name", `{"name":"M407Renamed"}`, bearer(token))
	if w.Code != http.StatusOK {
		t.Fatalf("rename status=%d body=%s", w.Code, w.Body.String())
	}
	var data struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil || data.Code != 0 {
		t.Fatalf("rename body=%s err=%v", w.Body.String(), err)
	}
	if strings.Contains(data.Message, ":old") || strings.Contains(data.Message, ":new") {
		t.Fatalf("rename message leaks placeholders: %q", data.Message)
	}
	if !strings.Contains(data.Message, "PlayerOne") || !strings.Contains(data.Message, "M407Renamed") {
		t.Fatalf("rename message missing old/new names: %q", data.Message)
	}
}
