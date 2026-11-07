package httpapp

import (
	"strings"
	"testing"
)

// Wiring smoke for M4-03 slices B/C1: the handlers exist only if the
// composition root registers them, so each case goes through the router
// with a real browser session (appFixture now migrates consents/api_digest).
func TestM403WiredRoutes(t *testing.T) {
	h, _ := appFixture(t)
	cookie, csrf := credentials(t, h, false)

	if w := request(t, h, "GET", "/oauth/clients", "", "", cookie); w.Code != 200 {
		t.Fatalf("clients status=%d body=%s", w.Code, w.Body.String())
	}
	if w := request(t, h, "GET", "/oauth/scopes", "", "", cookie); w.Code != 200 || !strings.Contains(w.Body.String(), "User.Read") {
		t.Fatalf("scopes status=%d body=%s", w.Code, w.Body.String())
	}
	if w := request(t, h, "GET", "/oauth/personal-access-tokens", "", "", cookie); w.Code != 200 {
		t.Fatalf("pat list status=%d", w.Code)
	}
	if w := request(t, h, "GET", "/oauth/tokens", "", "", cookie); w.Code != 200 {
		t.Fatalf("tokens status=%d", w.Code)
	}
	if w := request(t, h, "GET", "/user/oauth/manage", "", "", cookie); w.Code != 200 {
		t.Fatalf("manage status=%d", w.Code)
	}
	if w := request(t, h, "POST", "/oauth/token/refresh", `{}`, csrf, cookie); w.Code != 200 || !strings.Contains(w.Body.String(), "Refreshed.") {
		t.Fatalf("token refresh status=%d body=%s", w.Code, w.Body.String())
	}
	// Authorize without client params must not issue a code; with a clean
	// client it stages a pending consent page.
	w := request(t, h, "GET", "/oauth/authorize?client_id=1&redirect_uri=https://client.example.invalid/callback&response_type=code&scope=User.Read&state=0123456789abcdef0123456789abcdef", "", "", cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "auth_token") {
		t.Fatalf("authorize status=%d body=%.200s", w.Code, w.Body.String())
	}
}
