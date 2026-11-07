// M4-08 slice: independent OAuth 2.0 reference client acceptance, test-only.
//
// This file is the consumer side of the M4-08 OAuth contract. It drives the
// real Go App over HTTP only: a real browser login (JSON credential call with
// the CSRF header), the authorization page HTML (parsed with golang.org/x/net/
// html), the consent approve/deny forms (urlencoded form POST), a genuine
// loopback callback listener at 127.0.0.1:0, the protocol token endpoint, and
// the frozen Passport management paths for refresh rotation and revocation.
//
// Protocol oracles (source links):
//   - RFC 6749 §4.1 (authorization code grant), §4.1.2 (single consumption:
//     "The authorization server MUST deny a code presented more than once"),
//     §4.1.3 (token request), §5.1 (successful token response),
//     §6 (refreshing an access token), §3.2.1 (client authentication).
//     https://www.rfc-editor.org/rfc/rfc6749
//   - RFC 7636 §4.1/§4.2 (PKCE S256 challenge; verifier bounds),
//     §4.6 (verifier verification failure). https://www.rfc-editor.org/rfc/rfc7636
//   - Frozen Go contract used for exact statuses: internal/oauthserver/server.go
//     (token endpoint), internal/oauthserver/consent.go (approve/deny single
//     consumption, state preservation), internal/httpapp/consent.go
//     (consent handlers and error mapping), internal/httpapp/passport.go
//     (Passport management list/revoke 200/204), internal/oauthserver/
//     passport.go (ListTokens/RevokeToken), internal/oauthserver/clients.go
//     (client row shape; public = empty secret).
//   - Engine behavior observed through the frozen contract (authelia.com/
//     provider/oauth2 v0.3.3): unknown client -> 401 invalid_client, wrong
//     secret -> 401 invalid_client, redirect mismatch or replay ->
//     400 invalid_grant, PKCE verifier mismatch -> 400 invalid_grant,
//     expired code/refresh -> 400 invalid_grant.
//
// Arrangement/control uses the synthetic database (seeding client rows with
// the loopback callback URL, verifying preserved config after auth-reset).
// The flows themselves never call Go service/serializer/UUID/sign methods and
// never use the product fixtures' parser; only the shared m408NewFixture
// builds the App/database.
//
// These tests need M2_TEST_DSN (loopback MariaDB) and skip when it is absent;
// a skip is not a pass. No real client software (HMCL/injector/Velocity/
// MultiLogin/Minecraft/Fabric) is involved.
package httpapp

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/html"

	"blessing-skin-go/internal/maintenance"
	"blessing-skin-go/internal/oauthserver"
)

const (
	m408ConfidentialID     = int64(42001)
	m408PublicID           = int64(42002)
	m408ConfidentialSecret = "m408-confidential-secret"
)

// m408ClientID renders a seeded client id for query/form fields.
func m408ClientID(id int64) string { return fmt.Sprintf("%d", id) }

// m408BasePaths returns the two deployments the acceptance contract covers:
// root and the /skin subpath. The callback URL is absolute so it is the same
// for both; the browser session cookie path is deployment-bound.
func m408BasePaths() []struct{ name, path string } {
	return []struct{ name, path string }{{"root", ""}, {"subpath", "/skin"}}
}

// m408RefClient is the reference OAuth client. It owns a cookie jar, follows
// redirects (recording each hop via the tamper hook for qualification) and
// never calls into product code.
type m408RefClient struct {
	base   string
	http   *http.Client
	tamper func(*url.URL)
}

// m408NewRefClient builds the client with a fresh cookie jar. The redirect
// policy applies the optional tamper hook to every followed URL; a hook error
// aborts the flow.
func m408NewRefClient(t *testing.T, base string) *m408RefClient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &m408RefClient{base: base}
	c.http = &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("m408: too many redirects")
			}
			if c.tamper != nil {
				c.tamper(req.URL)
			}
			return nil
		},
	}
	return c
}

// m408Do performs one real HTTP request against the deployment and returns
// the final response (after redirects) and its body. mutate lets the caller
// set headers such as the CSRF header or a Bearer token.
func (c *m408RefClient) m408Do(t *testing.T, method, path string, body io.Reader, contentType string, mutate func(*http.Request)) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if mutate != nil {
		mutate(req)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatalf("m408: %s request failed", method)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(data)
}

// m408CSRF extracts the page CSRF token from <meta name="csrf-token"> using
// golang.org/x/net/html (independent of the product's template strings).
func m408CSRF(t *testing.T, page string) string {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(page))
	if err != nil {
		t.Fatalf("m408: html parse: %v", err)
	}
	found := ""
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "meta" {
			name, content := "", ""
			for _, a := range n.Attr {
				switch a.Key {
				case "name":
					name = a.Val
				case "content":
					content = a.Val
				}
			}
			if name == "csrf-token" && content != "" {
				found = content
			}
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(doc)
	if found == "" {
		t.Fatal("m408: csrf-token meta not found")
	}
	return found
}

// m408ConsentForm is one <form> extracted from the authorization page.
type m408ConsentForm struct {
	Action string
	Fields map[string]string
}

// m408FormFields extracts every consent <form> and its hidden inputs from the
// authorization page HTML. The approve and deny forms share the _token and
// auth_token fields and differ only in action.
func m408FormFields(t *testing.T, page string) map[string]m408ConsentForm {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(page))
	if err != nil {
		t.Fatalf("m408: html parse: %v", err)
	}
	out := map[string]m408ConsentForm{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			action := ""
			for _, a := range n.Attr {
				if a.Key == "action" {
					action = a.Val
				}
			}
			form := m408ConsentForm{Action: action, Fields: map[string]string{}}
			var collect func(*html.Node)
			collect = func(x *html.Node) {
				for ch := x.FirstChild; ch != nil; ch = ch.NextSibling {
					if ch.Type == html.ElementNode {
						if ch.Data == "input" {
							name, value := "", ""
							for _, a := range ch.Attr {
								switch a.Key {
								case "name":
									name = a.Val
								case "value":
									value = a.Val
								}
							}
							if name != "" {
								form.Fields[name] = value
							}
						}
						collect(ch)
					}
				}
			}
			collect(n)
			out[action] = form
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(doc)
	if len(out) == 0 {
		t.Fatal("m408: no consent forms found")
	}
	return out
}

// m408Callback is the loopback callback listener. It records only the query
// values (code/state/error) of every hit; never the body, credentials or
// full URLs.
type m408Callback struct {
	mu   sync.Mutex
	hits []url.Values
}

func (cb *m408Callback) last() (url.Values, bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if len(cb.hits) == 0 {
		return nil, false
	}
	return cb.hits[len(cb.hits)-1], true
}

// m408Loopback starts a real loopback HTTP listener and returns its base URL
// plus the recorder. This is the RFC 8252-style native redirect target.
func m408Loopback(t *testing.T) (string, *m408Callback) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cb := &m408Callback{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cb.mu.Lock()
		cb.hits = append(cb.hits, r.URL.Query())
		cb.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})
	return "http://" + ln.Addr().String(), cb
}

// m408ValidateCallback is the reference client's callback verifier: it
// rejects an error response and any state that differs from what the client
// sent (tampered callback qualification). It returns the code when valid.
func m408ValidateCallback(hit url.Values, wantState string) (code, errText string, ok bool) {
	if errText = hit.Get("error"); errText != "" {
		return "", errText, false
	}
	if wantState != "" && hit.Get("state") != wantState {
		return "", "", false
	}
	code = hit.Get("code")
	return code, "", code != ""
}

// m408SeedClient arranges one user-owned client row with the callback URL as
// the redirect. An empty secret makes the row public (storage.GetClient).
func m408SeedClient(t *testing.T, f *m408Fixture, id int64, name string, secret any, callback string) {
	t.Helper()
	_, err := f.Identity.Store.DB.Exec(
		"INSERT INTO "+f.Identity.Store.Table("oauth_clients")+" (id,user_id,name,secret,redirect) VALUES (?,1,?,?,?)",
		id, name, secret, callback+"/callback")
	if err != nil {
		t.Fatalf("m408: seed client %d: %v", id, err)
	}
}

// m408Login performs the real browser login with the original password and
// returns the authenticated CSRF token from a subsequent page load.
func (c *m408RefClient) m408Login(t *testing.T) string {
	t.Helper()
	_, page := c.m408Do(t, "GET", "/auth/login", nil, "", nil)
	csrf := m408CSRF(t, page)
	body := `{"identification":"user@example.invalid","password":"original-password"}`
	resp, loginBody := c.m408Do(t, "POST", "/auth/login", strings.NewReader(body), "application/json", func(r *http.Request) {
		r.Header.Set("X-CSRF-TOKEN", csrf)
	})
	if resp.StatusCode != http.StatusOK || !strings.Contains(loginBody, `"code":0`) {
		t.Fatalf("m408: login status=%d", resp.StatusCode)
	}
	_, userPage := c.m408Do(t, "GET", "/user", nil, "", nil)
	return m408CSRF(t, userPage)
}

// m408Stage GETs the authorization page and asserts its status. A 200 page
// carries the consent forms; error statuses (400/401) are JSON.
func (c *m408RefClient) m408Stage(t *testing.T, q url.Values, want int) string {
	t.Helper()
	resp, page := c.m408Do(t, "GET", "/oauth/authorize?"+q.Encode(), nil, "", nil)
	if resp.StatusCode != want {
		t.Fatalf("m408: stage status=%d want=%d", resp.StatusCode, want)
	}
	return page
}

// m408ConsentSubmit posts one consent form (approve or deny) with the fields
// parsed from the page and follows the redirect to the loopback callback.
func (c *m408RefClient) m408ConsentSubmit(t *testing.T, page, target string) {
	t.Helper()
	forms := m408FormFields(t, page)
	action := ""
	for a := range forms {
		if a == target || strings.HasSuffix(a, target) {
			action = a
		}
	}
	if action == "" {
		t.Fatalf("m408: consent form %s missing", target)
	}
	vals := url.Values{}
	for k, v := range forms[action].Fields {
		vals.Set(k, v)
	}
	resp, _ := c.m408Do(t, "POST", target, strings.NewReader(vals.Encode()), "application/x-www-form-urlencoded", nil)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		t.Fatalf("m408: consent submit status=%d", resp.StatusCode)
	}
}

// m408AuthorizeApprove runs the full authorization-code step: stage, approve,
// validate the callback state, and return the code.
func (c *m408RefClient) m408AuthorizeApprove(t *testing.T, cb *m408Callback, q url.Values) string {
	t.Helper()
	page := c.m408Stage(t, q, http.StatusOK)
	c.m408ConsentSubmit(t, page, "/oauth/authorize")
	hit, ok := cb.last()
	if !ok {
		t.Fatal("m408: loopback callback not reached")
	}
	code, errText, stateOK := m408ValidateCallback(hit, q.Get("state"))
	if errText != "" {
		t.Fatalf("m408: callback error=%s", errText)
	}
	if !stateOK {
		t.Fatal("m408: callback state mismatch")
	}
	if code == "" {
		t.Fatal("m408: callback has no code")
	}
	return code
}

// m408Deny runs the denial step and asserts the callback carries
// error=access_denied with the original state preserved.
func (c *m408RefClient) m408Deny(t *testing.T, cb *m408Callback, q url.Values) string {
	t.Helper()
	page := c.m408Stage(t, q, http.StatusOK)
	c.m408ConsentSubmit(t, page, "/oauth/authorize/deny")
	hit, ok := cb.last()
	if !ok {
		t.Fatal("m408: loopback callback not reached on deny")
	}
	if hit.Get("error") != "access_denied" {
		t.Fatalf("m408: deny error=%s", hit.Get("error"))
	}
	if state := q.Get("state"); state != "" && hit.Get("state") != state {
		t.Fatal("m408: deny did not preserve state")
	}
	if hit.Get("code") != "" {
		t.Fatal("m408: deny returned a code")
	}
	return page
}

// m408TokenSet holds one issued token pair.
type m408TokenSet struct {
	Access, Refresh string
}

// m408Exchange posts the token endpoint and returns the status plus the JSON
// payload. The form is built by the caller (client id/secret, code or
// refresh token, verifier, redirect).
func (c *m408RefClient) m408Exchange(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, body := c.m408Do(t, "POST", "/oauth/token", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", nil)
	var out map[string]any
	_ = json.Unmarshal([]byte(body), &out)
	if resp.StatusCode == http.StatusOK {
		access, _ := out["access_token"].(string)
		refresh, _ := out["refresh_token"].(string)
		expires, expiresPresent := out["expires_in"].(float64)
		if access == "" || refresh == "" || out["token_type"] != "bearer" || !expiresPresent || expires < 0 {
			t.Fatal("m408: token response shape invalid")
		}
	}
	return resp.StatusCode, out
}

func m408AssertGrantError(t *testing.T, status int, payload map[string]any, errCode string) {
	t.Helper()
	wantStatus := http.StatusBadRequest
	if errCode == "invalid_client" {
		wantStatus = http.StatusUnauthorized
	}
	if status != wantStatus {
		t.Fatalf("m408: status=%d want=%d", status, wantStatus)
	}
	if got, _ := payload["error"].(string); got != errCode {
		t.Fatalf("m408: error=%q want %q (status=%d)", got, errCode, status)
	}
}

// m408PKCE builds an RFC 7636 S256 verifier/challenge pair.
func m408PKCE(t *testing.T) (verifier, challenge string) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

// m408AuthorizeQuery is the standard authorize query for a client.
func m408AuthorizeQuery(clientID, redirect, scope, state string) url.Values {
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirect},
		"scope":         {scope},
	}
	if state != "" {
		q.Set("state", state)
	}
	return q
}

func m408ConfidentialForm(clientID, redirect, code, refresh, secret string) url.Values {
	form := url.Values{
		"client_id": {clientID},
	}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	if redirect != "" {
		form.Set("redirect_uri", redirect)
	}
	if code != "" {
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
	} else {
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", refresh)
	}
	return form
}

// TestM408ConfidentialCodeFlowRootAndSubpath drives the complete confidential
// client authorization-code flow on root and subpath deployments: login,
// stage, approve, callback state echo, exchange, API use, and code replay
// rejection (RFC 6749 §4.1.2).
func TestM408ConfidentialCodeFlowRootAndSubpath(t *testing.T) {
	for _, dp := range m408BasePaths() {
		t.Run(dp.name, func(t *testing.T) {
			cbURL, cb := m408Loopback(t)

			f := m408NewFixture(t, dp.path, nil)
			m408SeedClient(t, f, m408ConfidentialID, "m408-confidential", m408ConfidentialSecret, cbURL)
			c := m408NewRefClient(t, f.Endpoint.BaseURL)
			_ = c.m408Login(t)

			state := "st-confidential"
			q := m408AuthorizeQuery(m408ClientID(m408ConfidentialID), cbURL+"/callback", "User.Read", state)
			code := c.m408AuthorizeApprove(t, cb, q)
			form := m408ConfidentialForm(m408ClientID(m408ConfidentialID), cbURL+"/callback", code, "", m408ConfidentialSecret)
			status, payload := c.m408Exchange(t, form)
			if status != http.StatusOK {
				t.Fatalf("m408: exchange status=%d", status)
			}
			access, _ := payload["access_token"].(string)
			refresh, _ := payload["refresh_token"].(string)
			if access == "" || refresh == "" {
				t.Fatal("m408: exchange missing tokens")
			}
			if got, _ := payload["token_type"].(string); got != "bearer" {
				t.Fatalf("m408: token_type=%q", got)
			}
			if got := c.m408API(t, access, "/api/user"); got != http.StatusOK {
				t.Fatalf("m408: api/user status=%d", got)
			}
			// Replaying the same code is invalid_grant and must not issue.
			status, payload = c.m408Exchange(t, form)
			m408AssertGrantError(t, status, payload, "invalid_grant")
		})
	}
}

// m408API calls a core API with a Bearer token and returns the status.
func (c *m408RefClient) m408API(t *testing.T, token, path string) int {
	t.Helper()
	resp, _ := c.m408Do(t, "GET", path, nil, "", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+token)
	})
	return resp.StatusCode
}

// TestM408PublicClientS256Flow covers the public client on both deployments:
// PKCE S256 challenge/verifier exchange and the enforcement that a public
// client must include code_challenge (RFC 7636 §4.1; server config
// EnforcePKCEForPublicClients).
func TestM408PublicClientS256Flow(t *testing.T) {
	for _, dp := range m408BasePaths() {
		t.Run(dp.name, func(t *testing.T) {
			cbURL, cb := m408Loopback(t)

			f := m408NewFixture(t, dp.path, nil)
			m408SeedClient(t, f, m408PublicID, "m408-public", "", cbURL)
			c := m408NewRefClient(t, f.Endpoint.BaseURL)
			_ = c.m408Login(t)

			verifier, challenge := m408PKCE(t)
			q := m408AuthorizeQuery(m408ClientID(m408PublicID), cbURL+"/callback", "User.Read", "st-public-012345")
			q.Set("code_challenge", challenge)
			q.Set("code_challenge_method", "S256")
			code := c.m408AuthorizeApprove(t, cb, q)

			form := url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {fmt.Sprintf("%d", m408PublicID)},
				"code":          {code},
				"redirect_uri":  {cbURL + "/callback"},
				"code_verifier": {verifier},
			}
			status, payload := c.m408Exchange(t, form)
			if status != http.StatusOK {
				t.Fatalf("m408: public exchange status=%d", status)
			}
			access, _ := payload["access_token"].(string)
			if access == "" {
				t.Fatal("m408: public exchange missing access_token")
			}
			if got := c.m408API(t, access, "/api/user"); got != http.StatusOK {
				t.Fatalf("m408: api/user status=%d", got)
			}

			// Public client without code_challenge must be refused at
			// approve (enforce PKCE).
			qNo := m408AuthorizeQuery(m408ClientID(m408PublicID), cbURL+"/callback", "Player.Read", "st-public-nochallenge")
			page := c.m408Stage(t, qNo, http.StatusOK)
			forms := m408FormFields(t, page)
			vals := url.Values{}
			for a, formRow := range forms {
				if strings.HasSuffix(a, "/oauth/authorize") {
					for k, v := range formRow.Fields {
						vals.Set(k, v)
					}
				}
			}
			resp, body := c.m408Do(t, "POST", "/oauth/authorize", strings.NewReader(vals.Encode()), "application/x-www-form-urlencoded", nil)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("m408: public approve without challenge status=%d", resp.StatusCode)
			}
			if !strings.Contains(body, "code_challenge") {
				t.Fatal("m408: missing PKCE challenge error")
			}
		})
	}
}

// TestM408DenyPreservesState covers deny: the loopback receives
// error=access_denied with the state preserved, no code is issued, and the
// consumed pending consent cannot be approved afterwards.
func TestM408DenyPreservesState(t *testing.T) {
	cbURL, cb := m408Loopback(t)

	f := m408NewFixture(t, "", nil)
	m408SeedClient(t, f, m408ConfidentialID, "m408-confidential", m408ConfidentialSecret, cbURL)
	c := m408NewRefClient(t, f.Endpoint.BaseURL)
	_ = c.m408Login(t)

	state := "st-deny-012345"
	q := m408AuthorizeQuery(m408ClientID(m408ConfidentialID), cbURL+"/callback", "Player.Read", state)
	page := c.m408Deny(t, cb, q)

	// The consumed auth_token must not approve afterwards (single
	// consumption; pending row deleted).
	forms := m408FormFields(t, page)
	vals := url.Values{}
	var authToken string
	for a, formRow := range forms {
		if strings.HasSuffix(a, "/oauth/authorize") {
			for k, v := range formRow.Fields {
				vals.Set(k, v)
				if k == "auth_token" {
					authToken = v
				}
			}
		}
	}
	if authToken == "" {
		t.Fatal("m408: auth_token missing")
	}
	resp, _ := c.m408Do(t, "POST", "/oauth/authorize", strings.NewReader(vals.Encode()), "application/x-www-form-urlencoded", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("m408: replay approve after deny status=%d", resp.StatusCode)
	}
}

// TestM408BadVerifierRejected covers PKCE verifier verification failure
// (RFC 7636 §4.6): the exchange answers 400 invalid_grant.
func TestM408BadVerifierRejected(t *testing.T) {
	cbURL, cb := m408Loopback(t)

	f := m408NewFixture(t, "", nil)
	m408SeedClient(t, f, m408PublicID, "m408-public", "", cbURL)
	c := m408NewRefClient(t, f.Endpoint.BaseURL)
	_ = c.m408Login(t)

	_, challenge := m408PKCE(t)
	q := m408AuthorizeQuery(m408ClientID(m408PublicID), cbURL+"/callback", "User.Read", "st-verifier")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	code := c.m408AuthorizeApprove(t, cb, q)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {fmt.Sprintf("%d", m408PublicID)},
		"code":          {code},
		"redirect_uri":  {cbURL + "/callback"},
		"code_verifier": {"wrong-verifier-value-that-is-long-enough-for-pkce-even-though-it-does-not-match"},
	}
	status, payload := c.m408Exchange(t, form)
	m408AssertGrantError(t, status, payload, "invalid_grant")
}

// TestM408BadRedirectAndClientRejected covers token-endpoint validation: a
// redirect_uri that differs from the authorization request, an unknown
// client id, and a wrong client secret all fail with the frozen statuses.
func TestM408BadRedirectAndClientRejected(t *testing.T) {
	cbURL, cb := m408Loopback(t)

	f := m408NewFixture(t, "", nil)
	m408SeedClient(t, f, m408ConfidentialID, "m408-confidential", m408ConfidentialSecret, cbURL)
	c := m408NewRefClient(t, f.Endpoint.BaseURL)
	_ = c.m408Login(t)

	q := m408AuthorizeQuery(m408ClientID(m408ConfidentialID), cbURL+"/callback", "User.Read", "st-bad-012345")
	code := c.m408AuthorizeApprove(t, cb, q)

	// Mismatched redirect_uri -> 400 invalid_grant.
	form := m408ConfidentialForm(m408ClientID(m408ConfidentialID), cbURL+"/other", code, "", m408ConfidentialSecret)
	status, payload := c.m408Exchange(t, form)
	m408AssertGrantError(t, status, payload, "invalid_grant")

	// Unknown client id -> 401 invalid_client.
	form = m408ConfidentialForm("999999", cbURL+"/callback", code, "", m408ConfidentialSecret)
	status, payload = c.m408Exchange(t, form)
	m408AssertGrantError(t, status, payload, "invalid_client")

	// Wrong client secret -> 401 invalid_client.
	form = m408ConfidentialForm(m408ClientID(m408ConfidentialID), cbURL+"/callback", code, "", "wrong-secret")
	status, payload = c.m408Exchange(t, form)
	m408AssertGrantError(t, status, payload, "invalid_client")
}

// TestM408ScopeAPIGating covers the frozen Passport scope list and API scope
// gating: a token grants exactly the requested scopes (Player.Read-only token
// passes /api/players but is refused by /api/user; adding User.Read passes
// both), and an unknown scope is rejected at the authorization page.
func TestM408ScopeAPIGating(t *testing.T) {
	cbURL, cb := m408Loopback(t)

	f := m408NewFixture(t, "", nil)
	m408SeedClient(t, f, m408ConfidentialID, "m408-confidential", m408ConfidentialSecret, cbURL)
	c := m408NewRefClient(t, f.Endpoint.BaseURL)
	c.m408Login(t)

	// Frozen Passport /oauth/scopes list (user session).
	resp, body := c.m408Do(t, "GET", "/oauth/scopes", nil, "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("m408: scopes status=%d", resp.StatusCode)
	}
	for _, scope := range []string{"User.Read", "Closet.ReadWrtie", "Player.Read"} {
		if !strings.Contains(body, `"id":"`+scope+`"`) {
			t.Fatalf("m408: scopes missing %s", scope)
		}
	}

	grant := func(scope string) (string, string) {
		q := m408AuthorizeQuery(m408ClientID(m408ConfidentialID), cbURL+"/callback", scope, "st-scope")
		code := c.m408AuthorizeApprove(t, cb, q)
		form := m408ConfidentialForm(m408ClientID(m408ConfidentialID), cbURL+"/callback", code, "", m408ConfidentialSecret)
		status, payload := c.m408Exchange(t, form)
		if status != http.StatusOK {
			t.Fatalf("m408: grant exchange status=%d", status)
		}
		access, _ := payload["access_token"].(string)
		return access, scope
	}

	// Token with only Player.Read.
	playerOnly, _ := grant("Player.Read")
	if got := c.m408API(t, playerOnly, "/api/players"); got != http.StatusOK {
		t.Fatalf("m408: api/players status=%d", got)
	}
	if got := c.m408API(t, playerOnly, "/api/user"); got != http.StatusForbidden {
		t.Fatalf("m408: api/user (Player.Read only) status=%d", got)
	}
	// Token with User.Read + Player.Read.
	both, _ := grant("User.Read Player.Read")
	if got := c.m408API(t, both, "/api/user"); got != http.StatusOK {
		t.Fatalf("m408: api/user status=%d", got)
	}
	if got := c.m408API(t, both, "/api/players"); got != http.StatusOK {
		t.Fatalf("m408: api/players status=%d", got)
	}

	// Unknown scope -> 400 at the authorization page (frozen JSON error).
	q := m408AuthorizeQuery(m408ClientID(m408ConfidentialID), cbURL+"/callback", "Not.A.Real.Scope", "")
	page := c.m408Stage(t, q, http.StatusBadRequest)
	if !strings.Contains(page, "scope") {
		t.Fatal("m408: missing unknown-scope error")
	}

}

// TestM408RefreshRotationAndPassportRevoke covers refresh token rotation
// (RFC 6749 §6) and revocation through the frozen Passport management path
// (GET /oauth/tokens, DELETE /oauth/tokens/{token_id}): after revocation the
// access token dies at the API and the refresh token dies at the endpoint.
func TestM408RefreshRotationAndPassportRevoke(t *testing.T) {
	cbURL, cb := m408Loopback(t)

	f := m408NewFixture(t, "", nil)
	m408SeedClient(t, f, m408ConfidentialID, "m408-confidential", m408ConfidentialSecret, cbURL)
	c := m408NewRefClient(t, f.Endpoint.BaseURL)
	csrf := c.m408Login(t)

	q := m408AuthorizeQuery(m408ClientID(m408ConfidentialID), cbURL+"/callback", "User.Read", "st-refresh")
	code := c.m408AuthorizeApprove(t, cb, q)
	form := m408ConfidentialForm(m408ClientID(m408ConfidentialID), cbURL+"/callback", code, "", m408ConfidentialSecret)
	status, payload := c.m408Exchange(t, form)
	if status != http.StatusOK {
		t.Fatalf("m408: exchange status=%d", status)
	}
	first := m408TokenSet{}
	first.Access, _ = payload["access_token"].(string)
	first.Refresh, _ = payload["refresh_token"].(string)

	// Rotation: second refresh returns fresh tokens and kills the first
	// refresh token.
	form.Set("grant_type", "refresh_token")
	form.Del("code")
	form.Del("redirect_uri")
	form.Set("refresh_token", first.Refresh)
	status, payload = c.m408Exchange(t, form)
	if status != http.StatusOK {
		t.Fatalf("m408: refresh status=%d", status)
	}
	second := m408TokenSet{}
	second.Access, _ = payload["access_token"].(string)
	second.Refresh, _ = payload["refresh_token"].(string)
	if second.Access == "" || second.Refresh == "" || second.Access == first.Access || second.Refresh == first.Refresh {
		t.Fatal("m408: refresh did not rotate tokens")
	}
	// The rotated token works until revoke or replay of an older token.
	form.Set("refresh_token", second.Refresh)
	status, payload = c.m408Exchange(t, form)
	if status != http.StatusOK {
		t.Fatalf("m408: second refresh status=%d", status)
	}
	third := m408TokenSet{}
	third.Access, _ = payload["access_token"].(string)
	third.Refresh, _ = payload["refresh_token"].(string)

	// Passport management: list the user's grants and revoke this one.
	rows := c.m408ListTokens(t)
	var grantID string
	for _, row := range rows {
		if id, _ := row["client_id"].(string); id == m408ClientID(m408ConfidentialID) {
			grantID, _ = row["id"].(string)
		}
	}
	if grantID == "" {
		t.Fatal("m408: grant not listed in /oauth/tokens")
	}
	if status := c.m408RevokeToken(t, csrf, grantID); status != http.StatusNoContent {
		t.Fatalf("m408: revoke status=%d", status)
	}
	// Access token dies at the API; refresh dies at the endpoint.
	if got := c.m408API(t, third.Access, "/api/user"); got != http.StatusUnauthorized {
		t.Fatalf("m408: revoked access status=%d", got)
	}
	form.Set("refresh_token", third.Refresh)
	status, payload = c.m408Exchange(t, form)
	m408AssertGrantError(t, status, payload, "invalid_grant")
}

// m408ListTokens reads the frozen Passport token list as the browser user.
func (c *m408RefClient) m408ListTokens(t *testing.T) []map[string]any {
	t.Helper()
	resp, body := c.m408Do(t, "GET", "/oauth/tokens", nil, "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("m408: token list status=%d", resp.StatusCode)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		t.Fatalf("m408: token list decode: %v", err)
	}
	return rows
}

// m408RevokeToken deletes one grant through the frozen Passport path.
func (c *m408RefClient) m408RevokeToken(t *testing.T, csrf, id string) int {
	t.Helper()
	resp, _ := c.m408Do(t, "DELETE", "/oauth/tokens/"+id, strings.NewReader(`{}`), "application/json", func(r *http.Request) {
		r.Header.Set("X-CSRF-TOKEN", csrf)
	})
	return resp.StatusCode
}

// TestM408ResetReauthKeepsClientConfig covers atomic auth-reset: previously
// issued OAuth credentials are rejected at the API and refresh endpoints, the
// original password logs in again, the client rows (secret/redirect) are
// preserved, and a fresh flow works afterwards.
func TestM408ResetReauthKeepsClientConfig(t *testing.T) {
	cbURL, cb := m408Loopback(t)

	f := m408NewFixture(t, "", nil)
	m408SeedClient(t, f, m408ConfidentialID, "m408-confidential", m408ConfidentialSecret, cbURL)
	c := m408NewRefClient(t, f.Endpoint.BaseURL)
	_ = c.m408Login(t)

	q := m408AuthorizeQuery(m408ClientID(m408ConfidentialID), cbURL+"/callback", "User.Read", "st-reset")
	code := c.m408AuthorizeApprove(t, cb, q)
	form := m408ConfidentialForm(m408ClientID(m408ConfidentialID), cbURL+"/callback", code, "", m408ConfidentialSecret)
	status, payload := c.m408Exchange(t, form)
	if status != http.StatusOK {
		t.Fatalf("m408: exchange status=%d", status)
	}
	access, _ := payload["access_token"].(string)
	refresh, _ := payload["refresh_token"].(string)

	if err := maintenance.ResetAuthentication(t.Context(), f.Identity.Store); err != nil {
		t.Fatalf("m408: ResetAuthentication: %v", err)
	}

	// Old credentials are dead.
	if got := c.m408API(t, access, "/api/user"); got != http.StatusUnauthorized {
		t.Fatalf("m408: access after reset status=%d", got)
	}
	form.Set("grant_type", "refresh_token")
	form.Del("code")
	form.Del("redirect_uri")
	form.Set("refresh_token", refresh)
	var payload2 map[string]any
	status, payload2 = c.m408Exchange(t, form)
	m408AssertGrantError(t, status, payload2, "invalid_grant")

	// Client config is preserved (secret/redirect unchanged).
	var secret sql.NullString
	var redirect string
	err := f.Identity.Store.DB.QueryRow("SELECT secret,redirect FROM "+f.Identity.Store.Table("oauth_clients")+" WHERE id=?", m408ConfidentialID).Scan(&secret, &redirect)
	if err != nil {
		t.Fatalf("m408: client row read: %v", err)
	}
	if !secret.Valid || secret.String != m408ConfidentialSecret || redirect != cbURL+"/callback" {
		t.Fatal("m408: client config changed by reset")
	}

	// Reauthentication with the original password works and a fresh flow
	// succeeds.
	_ = c.m408Login(t)
	q2 := m408AuthorizeQuery(m408ClientID(m408ConfidentialID), cbURL+"/callback", "User.Read", "st-reset-2")
	code2 := c.m408AuthorizeApprove(t, cb, q2)
	form2 := m408ConfidentialForm(m408ClientID(m408ConfidentialID), cbURL+"/callback", code2, "", m408ConfidentialSecret)
	status, payload = c.m408Exchange(t, form2)
	if status != http.StatusOK {
		t.Fatalf("m408: post-reset exchange status=%d", status)
	}
	newAccess, _ := payload["access_token"].(string)
	if got := c.m408API(t, newAccess, "/api/user"); got != http.StatusOK {
		t.Fatalf("m408: post-reset api/user status=%d", got)
	}
}

// TestM408ExpiredCodeRejected uses the frozen short-lifetime precedent
// (CodeLifetime = 1ns truncates to the current second, so the code is already
// expired at exchange) and asserts 400 invalid_grant.
func TestM408ExpiredCodeRejected(t *testing.T) {
	cbURL, cb := m408Loopback(t)
	f := m408NewFixture(t, "", func(c *oauthserver.Config) {
		c.CodeLifetime = time.Nanosecond
	})
	m408SeedClient(t, f, m408ConfidentialID, "m408-confidential", m408ConfidentialSecret, cbURL)
	c := m408NewRefClient(t, f.Endpoint.BaseURL)
	_ = c.m408Login(t)

	q := m408AuthorizeQuery(m408ClientID(m408ConfidentialID), cbURL+"/callback", "User.Read", "st-exp-code")
	code := c.m408AuthorizeApprove(t, cb, q)
	// Let real time pass beyond the truncated lifetime.
	time.Sleep(10 * time.Millisecond)
	form := m408ConfidentialForm(m408ClientID(m408ConfidentialID), cbURL+"/callback", code, "", m408ConfidentialSecret)
	status, payload := c.m408Exchange(t, form)
	m408AssertGrantError(t, status, payload, "invalid_grant")
}

// TestM408ExpiredRefreshRejected uses the short refresh lifetime and asserts
// that an immediately expired refresh token answers 400 invalid_grant.
func TestM408ExpiredRefreshRejected(t *testing.T) {
	cbURL, cb := m408Loopback(t)
	f := m408NewFixture(t, "", func(c *oauthserver.Config) {
		c.RefreshLifetime = time.Nanosecond
	})
	m408SeedClient(t, f, m408ConfidentialID, "m408-confidential", m408ConfidentialSecret, cbURL)
	c := m408NewRefClient(t, f.Endpoint.BaseURL)
	_ = c.m408Login(t)

	q := m408AuthorizeQuery(m408ClientID(m408ConfidentialID), cbURL+"/callback", "User.Read", "st-exp-refresh")
	code := c.m408AuthorizeApprove(t, cb, q)
	form := m408ConfidentialForm(m408ClientID(m408ConfidentialID), cbURL+"/callback", code, "", m408ConfidentialSecret)
	status, payload := c.m408Exchange(t, form)
	if status != http.StatusOK {
		t.Fatalf("m408: exchange status=%d", status)
	}
	refresh, _ := payload["refresh_token"].(string)
	time.Sleep(10 * time.Millisecond)
	form.Set("grant_type", "refresh_token")
	form.Del("code")
	form.Del("redirect_uri")
	form.Set("refresh_token", refresh)
	status, payload = c.m408Exchange(t, form)
	m408AssertGrantError(t, status, payload, "invalid_grant")
}

// TestM408ClientRejectsTamperedCallbackState qualifies the reference client
// itself: when an attacker rewrites the state in the callback redirect, the
// client must refuse the code before any token exchange. The tamper hook
// simulates the attacker inside the harness's own redirect handling.
func TestM408ClientRejectsTamperedCallbackState(t *testing.T) {
	cbURL, cb := m408Loopback(t)

	f := m408NewFixture(t, "", nil)
	m408SeedClient(t, f, m408ConfidentialID, "m408-confidential", m408ConfidentialSecret, cbURL)
	c := m408NewRefClient(t, f.Endpoint.BaseURL)
	_ = c.m408Login(t)

	state := "st-attacker-bound"
	q := m408AuthorizeQuery(m408ClientID(m408ConfidentialID), cbURL+"/callback", "User.Read", state)
	page := c.m408Stage(t, q, http.StatusOK)

	c.tamper = func(u *url.URL) {
		query := u.Query()
		query.Set("state", "attacker-controlled-state")
		u.RawQuery = query.Encode()
	}
	c.m408ConsentSubmit(t, page, "/oauth/authorize")
	hit, ok := cb.last()
	if !ok {
		t.Fatal("m408: callback not reached")
	}
	code, _, stateOK := m408ValidateCallback(hit, state)
	if stateOK {
		t.Fatal("m408: tampered callback state accepted")
	}
	if code != "" {
		t.Fatal("m408: tampered callback still carried a code")
	}
	if hit.Get("state") == state {
		t.Fatal("m408: tamper hook did not alter the callback state")
	}
}

// TestM408RefreshReplayRevokesFamily checks the pinned provider's replay
// semantics separately from the Passport revoke flow: a consumed refresh
// token revokes its grant, including the latest access/refresh pair.
func TestM408RefreshReplayRevokesFamily(t *testing.T) {
	cbURL, cb := m408Loopback(t)
	f := m408NewFixture(t, "", nil)
	m408SeedClient(t, f, m408ConfidentialID, "m408-replay", m408ConfidentialSecret, cbURL)
	c := m408NewRefClient(t, f.Endpoint.BaseURL)
	c.m408Login(t)
	q := m408AuthorizeQuery(m408ClientID(m408ConfidentialID), cbURL+"/callback", "User.Read", "st-refresh-replay")
	code := c.m408AuthorizeApprove(t, cb, q)
	form := m408ConfidentialForm(m408ClientID(m408ConfidentialID), cbURL+"/callback", code, "", m408ConfidentialSecret)
	status, payload := c.m408Exchange(t, form)
	if status != 200 {
		t.Fatal("initial exchange failed")
	}
	old, _ := payload["refresh_token"].(string)
	if old == "" {
		t.Fatal("initial refresh missing")
	}
	form.Set("grant_type", "refresh_token")
	form.Del("code")
	form.Del("redirect_uri")
	form.Set("refresh_token", old)
	status, payload = c.m408Exchange(t, form)
	if status != 200 {
		t.Fatal("rotation failed")
	}
	latest, _ := payload["refresh_token"].(string)
	access, _ := payload["access_token"].(string)
	if latest == "" || latest == old || access == "" || c.m408API(t, access, "/api/user") != 200 {
		t.Fatal("rotated credential not usable")
	}
	status, payload = c.m408Exchange(t, form)
	m408AssertGrantError(t, status, payload, "invalid_grant")
	if c.m408API(t, access, "/api/user") != 401 {
		t.Fatal("replayed grant access survived")
	}
	form.Set("refresh_token", latest)
	status, payload = c.m408Exchange(t, form)
	m408AssertGrantError(t, status, payload, "invalid_grant")
}

// TestM408ExpiredAccessRejected uses the same existing short-lifetime
// fixture pattern, without adding a production clock API.
func TestM408ExpiredAccessRejected(t *testing.T) {
	cbURL, cb := m408Loopback(t)
	f := m408NewFixture(t, "", func(c *oauthserver.Config) { c.AccessLifetime = time.Nanosecond })
	m408SeedClient(t, f, m408ConfidentialID, "m408-expired-access", m408ConfidentialSecret, cbURL)
	c := m408NewRefClient(t, f.Endpoint.BaseURL)
	c.m408Login(t)
	q := m408AuthorizeQuery(m408ClientID(m408ConfidentialID), cbURL+"/callback", "User.Read", "st-expired-access")
	code := c.m408AuthorizeApprove(t, cb, q)
	form := m408ConfidentialForm(m408ClientID(m408ConfidentialID), cbURL+"/callback", code, "", m408ConfidentialSecret)
	started := time.Now().Unix()
	status, payload := c.m408Exchange(t, form)
	if status != 200 {
		t.Fatal("expired-access fixture exchange failed")
	}
	access, _ := payload["access_token"].(string)
	// The pinned JWT validator compares integer Unix seconds inclusively.
	// Read exp independently and cross the next whole-second boundary.
	parts := strings.Split(access, ".")
	if len(parts) != 3 {
		t.Fatal("short-lifetime access is not a JWT")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err != nil || json.Unmarshal(body, &claims) != nil || claims.Exp < started || claims.Exp > time.Now().Unix() || payload["expires_in"] != float64(0) {
		t.Fatal("short-lifetime access fixture expiry mismatch")
	}
	time.Sleep(time.Until(time.Unix(claims.Exp+1, 0)))
	if c.m408API(t, access, "/api/user") != 401 {
		t.Fatal("expired access accepted")
	}
}
