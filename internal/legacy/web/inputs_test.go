package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"paradise-cosmetics-studio/internal/legacy/users"
)

// TestPHPTrimDefaultSet pins the exact PHP trim() default character set:
// 0x20, 0x09, 0x0A, 0x0D, 0x00 and 0x0B are removed from both ends, while
// U+00A0, U+3000 and U+000C are ordinary characters for PHP and must stay.
func TestPHPTrimDefaultSet(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"ascii-space", " \t\n\r\vvalue \t\n\r\v", "value"},
		{"nul", "\x00value\x00", "value"},
		{"nbsp", "\u00A0value\u00A0", "\u00A0value\u00A0"},
		{"ideographic-space", "\u3000value\u3000", "\u3000value\u3000"},
		{"form-feed", "\fvalue\f", "\fvalue\f"},
		{"interior", " a\x00b ", "a\x00b"},
		{"only-trim-chars", " \t\n\r\x00\v", ""},
		{"trailing-mixed", "value \x00", "value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := trimPHPDefault(tc.in); got != tc.want {
				t.Fatalf("trimPHPDefault(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestInputStringTrimsFormAndJSON runs the same matrix through both request
// parsers so the helper cannot be wired into only one chain.
func TestInputStringTrimsFormAndJSON(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"ascii-space", " value ", "value"},
		{"nul", "\x00value\x00", "value"},
		{"nbsp", "\u00A0value", "\u00A0value"},
		{"ideographic-space", "\u3000value", "\u3000value"},
		{"form-feed", "\fvalue", "\fvalue"},
		{"interior", " a\x00b ", "a\x00b"},
		{"only-trim-chars", " \t\n\r\x00\v", ""},
	}
	for _, mode := range []string{"form", "json"} {
		for _, tc := range cases {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				var r *http.Request
				if mode == "form" {
					form := url.Values{}
					form.Set("value", tc.in)
					r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else {
					payload, err := json.Marshal(map[string]string{"value": tc.in})
					if err != nil {
						t.Fatal(err)
					}
					r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(payload)))
					r.Header.Set("Content-Type", "application/json")
				}
				if got := inputString(r, "value"); got != tc.want {
					t.Fatalf("inputString(%s) = %q, want %q", mode, got, tc.want)
				}
			})
		}
	}
}

// TestEmptyJSONBodyDetectionIsUnchanged guards the "empty JSON body" branch from
// the trim fix: a body of only spaces is still treated as an empty object.
func TestEmptyJSONBodyDetectionIsUnchanged(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(" \n\t "))
	r.Header.Set("Content-Type", "application/json")
	if got := inputString(r, "missing"); got != "" {
		t.Fatalf("inputString on an empty JSON body = %q", got)
	}
}

// TestLoginChainUsesPHPTrim is the end-to-end R08 matrix over a real account
// database: the same payload is sent as form data and as JSON, and the login
// result must match the frozen PHP semantics in both directions. Accounts whose
// stored password legitimately starts with U+00A0 or U+000C prove that PHP's
// retained characters keep working, while the plain account proves that Go must
// not silently accept inputs PHP rejects.
func TestLoginChainUsesPHPTrim(t *testing.T) {
	env := newLiveEnv(t)
	env.seedUser(t, "trim@example.invalid", "Abcdef", "", users.Normal)
	env.seedUser(t, "trim-nbsp@example.invalid", "\u00A0Abcdef", "", users.Normal)
	env.seedUser(t, "trim-ff@example.invalid", "\u000CAbcdef", "", users.Normal)

	type testCase struct {
		name           string
		identification string
		password       string
		wantCode       int
		wantError      string
	}
	cases := []testCase{
		{name: "plain", identification: "trim@example.invalid", password: "Abcdef", wantCode: 0},
		{
			name: "ascii-padding-trimmed", identification: "trim@example.invalid",
			password: " \t\n\r\vAbcdef \t\n\r\v", wantCode: 0,
		},
		{
			name: "nul-padding-trimmed", identification: "trim@example.invalid",
			password: "\x00Abcdef\x00", wantCode: 0,
		},
		{
			name: "nbsp-retained-rejects-plain-account", identification: "trim@example.invalid",
			password: "\u00A0Abcdef", wantCode: 1,
		},
		{
			name: "ideographic-space-retained-rejects-plain-account", identification: "trim@example.invalid",
			password: "\u3000Abcdef", wantCode: 1,
		},
		{
			name: "form-feed-retained-rejects-plain-account", identification: "trim@example.invalid",
			password: "\u000CAbcdef", wantCode: 1,
		},
		{
			name: "nbsp-password-still-works", identification: "trim-nbsp@example.invalid",
			password: "\u00A0Abcdef", wantCode: 0,
		},
		{
			name: "form-feed-password-still-works", identification: "trim-ff@example.invalid",
			password: "\u000CAbcdef", wantCode: 0,
		},
		{
			name: "interior-nul-unchanged", identification: "trim@example.invalid",
			password: "Abc\x00def", wantCode: 1,
		},
		{
			name: "only-trim-chars-is-empty", identification: "trim@example.invalid",
			password: "\x00\t \u000B", wantError: "The password field is required.",
		},
		{
			name: "trimmed-too-short", identification: "trim@example.invalid",
			password: "\x00Ab \t", wantError: "The password must be at least 6 characters.",
		},
		{
			name: "identification-ascii-padding", identification: " \ttrim@example.invalid\r\n",
			password: "Abcdef", wantCode: 0,
		},
		{
			name: "identification-nbsp-retained", identification: "\u00A0trim@example.invalid",
			password: "Abcdef", wantCode: 2,
		},
		{
			name: "identification-ideographic-retained", identification: "\u3000trim@example.invalid",
			password: "Abcdef", wantCode: 2,
		},
		{
			name: "identification-form-feed-retained", identification: "\u000Ctrim@example.invalid",
			password: "Abcdef", wantCode: 2,
		},
		{
			name: "identification-only-trim-chars-is-empty", identification: " \x00\t",
			password: "Abcdef", wantError: "The email or player name field is required.",
		},
	}

	for _, mode := range []string{"form", "json"} {
		for _, tc := range cases {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				device := newBrowser(t, env)
				device.openLogin()
				var response *httptest.ResponseRecorder
				switch mode {
				case "form":
					form := url.Values{}
					form.Set("identification", tc.identification)
					form.Set("password", tc.password)
					response = device.do(http.MethodPost, "/auth/login", form.Encode(),
						"application/x-www-form-urlencoded", "application/json")
				case "json":
					payload, err := json.Marshal(map[string]string{
						"identification": tc.identification,
						"password":       tc.password,
					})
					if err != nil {
						t.Fatal(err)
					}
					response = device.do(http.MethodPost, "/auth/login", string(payload),
						"application/json", "application/json")
				}

				if tc.wantError != "" {
					if response.Code != http.StatusUnprocessableEntity {
						t.Fatalf("status = %d, want 422 (body %s)", response.Code, response.Body.String())
					}
					body := decodeLegacyBody(t, response)
					field := "password"
					if tc.identification == " \x00\t" {
						field = "identification"
					}
					messages := body.Errors[field]
					if len(messages) == 0 || messages[0] != tc.wantError {
						t.Fatalf("%s errors = %v, want %q", field, messages, tc.wantError)
					}
					return
				}
				if response.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200 (body %s)", response.Code, response.Body.String())
				}
				body := decodeLegacyBody(t, response)
				if body.Code != tc.wantCode {
					t.Fatalf("login code = %d (%s), want %d", body.Code, body.Message, tc.wantCode)
				}
			})
		}
	}
}
