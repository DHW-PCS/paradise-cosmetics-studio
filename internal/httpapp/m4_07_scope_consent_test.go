package httpapp

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// M4-07 prepare: scope maintenance x consent/refresh combined gap.
//
// Existing coverage (reuse, not rerun as formal acceptance here):
//   - TestOAuthScopeMaintenanceEntries: CRUD statuses (201/200/204/404/422/409).
//   - TestOAuthScopePublicationReachesIssuance: create -> password grant ->
//     delete -> invalid_scope.
//   - TestConsentHandlersStageApproveDeny / TestPendingConsent*: stage,
//     approve, single-consume, deny, stale checks.
//
// F2 correction: a scope description update while consent is pending does
// NOT silently approve. The approved stale semantics (oauthserver
// consent.go, ErrConsentStale) require a fresh authorization page, so the
// first approve after the update must be 409; only the restaged page
// approves. Refresh of an issued grant is not display-bound and must keep
// working after a further scope update. Delete-while-pending uses client
// 2, which has no grant for this scope, because client 1 would be
// auto-approved (302) on its second GET and could never stage.
func TestM407ScopeUpdateConsentRefresh(t *testing.T) {
	h, _ := appFixture(t)
	adminCookie, adminCSRF := credentials(t, h, true)
	userCookie, userCSRF := credentials(t, h, false)

	// Create a custom scope through the maintenance entry.
	w := request(t, h, "POST", "/admin/oauth/scopes", `{"name":"m407.read","description":"M407 detail"}`, adminCSRF, adminCookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("create scope status=%d body=%s", w.Code, w.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.ID < 1 {
		t.Fatalf("create body=%s err=%v", w.Body.String(), err)
	}
	scopeID := strconv.FormatInt(created.ID, 10)

	stage := func(clientID, redirect string) string {
		target := "/oauth/authorize?client_id=" + clientID + "&redirect_uri=" + redirect + "&response_type=code&scope=m407.read&state=0123456789abcdef0123456789abcdef"
		w := request(t, h, "GET", target, "", "", userCookie)
		if w.Code != http.StatusOK {
			t.Fatalf("authorize stage (client %s) status=%d body=%.200s", clientID, w.Code, w.Body.String())
		}
		body := w.Body.String()
		marker := `name="auth_token" value="`
		idx := strings.Index(body, marker)
		if idx < 0 {
			t.Fatalf("stage body missing auth_token: %.200s", body)
		}
		rest := body[idx+len(marker):]
		end := strings.Index(rest, `"`)
		if end < 0 || rest[:end] == "" {
			t.Fatalf("stage body malformed: %.200s", body)
		}
		return rest[:end]
	}

	// Stage, then update the scope description while pending.
	authToken := stage("1", "https://client.example.invalid/callback")

	w = request(t, h, "PUT", "/admin/oauth/scopes/"+scopeID, `{"name":"m407.read","description":"M407 changed"}`, adminCSRF, adminCookie)
	if w.Code != http.StatusOK {
		t.Fatalf("update scope status=%d body=%s", w.Code, w.Body.String())
	}

	// Approve of the stale page must be rejected with 409, not redirected.
	w = request(t, h, "POST", "/oauth/authorize", `{"auth_token":"`+authToken+`"}`, userCSRF, userCookie)
	if w.Code != http.StatusConflict {
		t.Fatalf("approve of stale consent status=%d body=%s (want 409)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "consent display changed") {
		t.Fatalf("stale approve body=%s (want consent-display-changed error)", w.Body.String())
	}

	// Restage shows the new display; approving it issues a code.
	authToken = stage("1", "https://client.example.invalid/callback")
	w = request(t, h, "POST", "/oauth/authorize", `{"auth_token":"`+authToken+`"}`, userCSRF, userCookie)
	if w.Code != http.StatusFound {
		t.Fatalf("approve after restage status=%d body=%s", w.Code, w.Body.String())
	}
	location := w.Header().Get("Location")
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("redirect has no code: %q", location)
	}

	// Exchange code for a grant.
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"1"}, "client_secret": {"client-secret"}, "redirect_uri": {"https://client.example.invalid/callback"}, "code": {code}}
	w = requestJSONForm(t, h, "POST", "/oauth/token", form.Encode())
	if w.Code != http.StatusOK {
		t.Fatalf("code exchange status=%d body=%s", w.Code, w.Body.String())
	}
	var grant map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &grant); err != nil {
		t.Fatalf("exchange body=%s err=%v", w.Body.String(), err)
	}
	refreshToken, _ := grant["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatalf("exchange missing refresh_token: %v", grant)
	}

	// A further scope update must not break refresh of the issued grant.
	w = request(t, h, "PUT", "/admin/oauth/scopes/"+scopeID, `{"name":"m407.read","description":"M407 changed again"}`, adminCSRF, adminCookie)
	if w.Code != http.StatusOK {
		t.Fatalf("second update scope status=%d body=%s", w.Code, w.Body.String())
	}
	form = url.Values{"grant_type": {"refresh_token"}, "client_id": {"1"}, "client_secret": {"client-secret"}, "refresh_token": {refreshToken}}
	w = requestJSONForm(t, h, "POST", "/oauth/token", form.Encode())
	if w.Code != http.StatusOK {
		t.Fatalf("refresh after scope update status=%d body=%s", w.Code, w.Body.String())
	}

	// Delete the scope while a fresh pending consent (client 2, no prior
	// grant) is staged; approve must fail, never redirect with a code.
	authToken2 := stage("2", "https://other.example.invalid/callback")
	w = request(t, h, "DELETE", "/admin/oauth/scopes/"+scopeID, `{}`, adminCSRF, adminCookie)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete scope status=%d", w.Code)
	}
	w = request(t, h, "POST", "/oauth/authorize", `{"auth_token":"`+authToken2+`"}`, userCSRF, userCookie)
	if w.Code == http.StatusFound {
		t.Fatalf("approve after scope delete redirected: %q", w.Header().Get("Location"))
	}
	if w.Code == http.StatusOK {
		t.Fatalf("approve after scope delete returned consent page: %.200s", w.Body.String())
	}
	if w.Code != http.StatusBadRequest && w.Code != http.StatusConflict {
		t.Fatalf("approve after scope delete status=%d body=%s", w.Code, w.Body.String())
	}
}
