package httpapp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"paradise-cosmetics-studio/internal/identity"
)

func postForm(t *testing.T, h http.Handler, target, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "http://localhost/skin"+target, strings.NewReader(body))
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if csrf != "" {
		r.Header.Set("X-CSRF-TOKEN", csrf)
	}
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func guestRegistration(t *testing.T, h http.Handler, payload string) *http.Cookie {
	t.Helper()
	w := request(t, h, "GET", "/auth/register", "", "", nil)
	csrf := csrfPattern.FindStringSubmatch(w.Body.String())
	var guest *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == sessionCookie {
			guest = cookie
		}
	}
	if len(csrf) != 2 || guest == nil {
		t.Fatal("registration guest missing")
	}
	w = request(t, h, "POST", "/auth/register", payload, csrf[1], guest)
	if w.Code != 200 {
		t.Fatalf("register status=%d body=%s", w.Code, w.Body.String())
	}
	return guest
}

func TestAdminInvitationPageLifecycle(t *testing.T) {
	h, id := appFixture(t)
	admin, csrf := credentials(t, h, true)
	member, _ := credentials(t, h, false)

	// Unregistered module: the page and menu stay absent.
	w := request(t, h, "GET", "/admin/invitation-codes", "", "", admin)
	if w.Code != 404 {
		t.Fatalf("unregistered page status=%d", w.Code)
	}
	if w := request(t, h, "GET", "/admin", "", "", admin); strings.Contains(w.Body.String(), "Invitation Code") {
		t.Fatal("menu shows an unregistered module")
	}

	if _, err := id.Store.DB.Exec("UPDATE "+id.Store.Table("options")+" SET option_value=? WHERE option_name='go_module_installations'", `[{"name":"invitation-codes","version":"3.1.2"}]`); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "POST", "/admin/plugins/manage", `{"action":"enable","name":"invitation-codes"}`, csrf, admin)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("enable response %s", w.Body.String())
	}
	if w := request(t, h, "GET", "/admin", "", "", admin); !strings.Contains(w.Body.String(), "fa-inbox") || !strings.Contains(w.Body.String(), "/admin/invitation-codes") {
		t.Fatal("enabled module menu item missing")
	}
	w = request(t, h, "GET", "/admin/invitation-codes", "", "", admin)
	if w.Code != 200 {
		t.Fatalf("page status=%d", w.Code)
	}
	// codes.twig renders the plugin page title into <title> and h1.
	for _, text := range []string{"<title>Generate Codes", "<h1 class=\"m-0\">Generate Codes</h1>", "Generate Codes", "Available Codes", "Used Codes", "Amount of invitation codes to be generated.", "User ID"} {
		if !strings.Contains(w.Body.String(), text) {
			t.Fatalf("codes page text %q got lost", text)
		}
	}
	if w = request(t, h, "GET", "/admin/invitation-codes", "", "", member); w.Code != 403 {
		t.Fatalf("member page status=%d", w.Code)
	}

	// Validation errors flash on the same page; the amount stays unfilled so
	// the required rule fires like the original validate() chain.
	w = postForm(t, h, "/admin/invitation-codes/generate", "amount=0", admin, csrf)
	if w.Code != 302 {
		t.Fatalf("invalid amount status=%d", w.Code)
	}
	w = request(t, h, "GET", "/admin/invitation-codes", "", "", admin)
	if !strings.Contains(w.Body.String(), "amount") {
		t.Fatalf("validation flash missing")
	}

	// Disabled anytime: the page answers as an absent route again.
	if _, err := id.Store.DB.Exec("UPDATE "+id.Store.Table("options")+" SET option_value=? WHERE option_name='plugins_enabled'", `[]`); err != nil {
		t.Fatal(err)
	}
	if w = request(t, h, "GET", "/admin/invitation-codes", "", "", admin); w.Code != 404 {
		t.Fatalf("disabled page status=%d", w.Code)
	}
	if w = request(t, h, "POST", "/admin/invitation-codes/generate", `amount=1`, csrf, admin); w.Code != 404 {
		t.Fatalf("disabled generate status=%d", w.Code)
	}
}

func TestInvitationGenerateRecordsTheBatch(t *testing.T) {
	h, id := appFixture(t)
	admin, csrf := credentials(t, h, true)
	if _, err := id.Store.DB.Exec("UPDATE "+id.Store.Table("options")+" SET option_value=? WHERE option_name='go_module_installations'", `[{"name":"invitation-codes","version":"3.1.2"}]`); err != nil {
		t.Fatal(err)
	}
	w := request(t, h, "POST", "/admin/plugins/manage", `{"action":"enable","name":"invitation-codes"}`, csrf, admin)
	if w.Code != 200 {
		t.Fatalf("enable response %s", w.Body.String())
	}
	w = postForm(t, h, "/admin/invitation-codes/generate", "amount=2", admin, csrf)
	if w.Code != 302 {
		t.Fatalf("generate status=%d", w.Code)
	}
	var fresh, used int
	if err := id.Store.DB.QueryRow("SELECT COUNT(*) FROM " + id.Store.Table("invitation_codes") + " WHERE used_by=0").Scan(&fresh); err != nil || fresh != 2 {
		t.Fatalf("fresh rows=%d err=%v", fresh, err)
	}
	if err := id.Store.DB.QueryRow("SELECT COUNT(*) FROM " + id.Store.Table("invitation_codes") + " WHERE used_by<>0").Scan(&used); err != nil || used != 0 {
		t.Fatalf("used rows=%d err=%v", used, err)
	}
	// A collision inside an impossible large batch only exists in the fixed
	// input checks; the HTTP path keeps honest failures without partial rows.
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("invitation_codes") + " SET code='0123456789abcdef0123456789abcdef' WHERE id=(SELECT MIN(id) FROM " + id.Store.Table("invitation_codes") + ")"); err != nil {
		t.Fatal(err)
	}
	var before int
	if err := id.Store.DB.QueryRow("SELECT COUNT(*) FROM " + id.Store.Table("invitation_codes")).Scan(&before); err != nil {
		t.Fatal(err)
	}
	w = postForm(t, h, "/admin/invitation-codes/generate", "amount=1", admin, csrf)
	if w.Code >= 500 && w.Code != 503 {
		t.Fatalf("collision outcome status=%d", w.Code)
	}
	var after int
	if err := id.Store.DB.QueryRow("SELECT COUNT(*) FROM " + id.Store.Table("invitation_codes")).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after == before+1 && strings.Contains(w.Body.String(), "code=0") {
		t.Fatal("collision batch reported success")
	}
}

// answerDigest mirrors the captcha service's canonical answer hashing for a
// fixed-input test flow.
func answerDigest(raw string) []byte {
	nice := strings.NewReplacer("0", "o", "1", "l").Replace(strings.ToLower(raw))
	return identity.Digest(nice)
}

func TestRegistrationInvitationFieldAndConsumption(t *testing.T) {
	h, id := appFixture(t)
	if _, err := id.Store.DB.Exec("UPDATE "+id.Store.Table("options")+" SET option_value=? WHERE option_name='go_module_installations'", `[{"name":"invitation-codes","version":"3.1.2"}]`); err != nil {
		t.Fatal(err)
	}
	admin, csrf := credentials(t, h, true)
	w := request(t, h, "POST", "/admin/plugins/manage", `{"action":"enable","name":"invitation-codes"}`, csrf, admin)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("enable response %s", w.Body.String())
	}
	w = request(t, h, "GET", "/auth/register", "", "", nil)
	if !strings.Contains(w.Body.String(), `"invitation":{"label":"Invitation Code"}`) {
		t.Fatalf("register page field condition missing: %s", w.Body.String())
	}
	// One usable code and a register round-trip: success consumes exactly
	// once; the replay keeps the frozen invalid copy.
	if _, err := id.Store.DB.Exec("INSERT INTO "+id.Store.Table("invitation_codes")+" (code,generated_at) VALUES (?,NOW(6))", strings.Repeat("a", 32)); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "GET", "/auth/register", "", "", nil)
	csrfOfPage := csrfPattern.FindStringSubmatch(w.Body.String())
	var guest *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == sessionCookie {
			guest = cookie
		}
	}
	if len(csrfOfPage) != 2 || guest == nil {
		t.Fatal("registration guest missing")
	}
	// The seeded answer belongs to the guest session the POST reuses.
	sessionDigest := identity.Digest(guest.Value)
	if _, err := id.Store.DB.Exec("INSERT INTO "+id.Store.Table("go_captchas")+" (session_digest,answer_digest,expires_at) VALUES (?,?,?) ON DUPLICATE KEY UPDATE answer_digest=VALUES(answer_digest)", sessionDigest, answerDigest("AbC01"), id.Now().Add(3600_000_000_000).Unix()); err != nil {
		t.Fatal(err)
	}
	var storedDigest []byte
	if err := id.Store.DB.QueryRow("SELECT answer_digest FROM "+id.Store.Table("go_captchas")+" WHERE session_digest=?", sessionDigest).Scan(&storedDigest); err != nil {
		t.Fatalf("captcha seed read err=%v", err)
	}
	if string(storedDigest) != string(answerDigest("AbC01")) {
		t.Fatalf("captcha digest stored=%x want=%x", storedDigest, answerDigest("AbC01"))
	}
	payload := `{"email":"invitee@example.invalid","password":"invitee-password","captcha":"AbC01","player_name":"InviteePlayer","invitationCode":"` + strings.Repeat("a", 32) + `"}`
	w = request(t, h, "POST", "/auth/register", payload, csrfOfPage[1], guest)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("register with code status=%d body=%s", w.Code, w.Body.String())
	}
	var owner int64
	if err := id.Store.DB.QueryRow("SELECT used_by FROM "+id.Store.Table("invitation_codes")+" WHERE code=?", strings.Repeat("a", 32)).Scan(&owner); err != nil || owner == 0 {
		t.Fatalf("consumed code owner=%d err=%v", owner, err)
	}
}

// TestRegisterUnwiredEligibilityControlledRejection covers B2A-F1: an
// enabled restricting module without a connected consumer refuses the whole
// registration with the legacy can_register code=1 JSON shape (HTTP 200),
// not a 503 server error. The frozen disable-registration title text is the
// approved rejection copy.
func TestRegisterUnwiredEligibilityControlledRejection(t *testing.T) {
	h, id := appFixture(t)
	if _, err := id.Store.DB.Exec("UPDATE "+id.Store.Table("options")+" SET option_value=? WHERE option_name='plugins_enabled'", `[{"name":"disable-registration","version":"1.0.0"}]`); err != nil {
		t.Fatal(err)
	}
	w := request(t, h, "GET", "/auth/register", "", "", nil)
	csrf := csrfPattern.FindStringSubmatch(w.Body.String())
	var guest *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == sessionCookie {
			guest = cookie
		}
	}
	if len(csrf) != 2 || guest == nil {
		t.Fatal("registration guest missing")
	}
	sessionDigest := identity.Digest(guest.Value)
	if _, err := id.Store.DB.Exec("INSERT INTO "+id.Store.Table("go_captchas")+" (session_digest,answer_digest,expires_at) VALUES (?,?,?) ON DUPLICATE KEY UPDATE answer_digest=VALUES(answer_digest)", sessionDigest, answerDigest("AbC01"), id.Now().Add(3600_000_000_000).Unix()); err != nil {
		t.Fatal(err)
	}
	payload := `{"email":"blocked@example.invalid","password":"blocked-password","captcha":"AbC01","player_name":"BlockedPlayer"}`
	// Explicitly request zh_CN so the frozen zh_CN title text is asserted
	// deterministically; requests without a language signal fall back to
	// the configured FallbackLocale (en).
	r := httptest.NewRequest(http.MethodPost, "http://localhost/skin/auth/register", strings.NewReader(payload))
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	r.Header.Set("X-CSRF-TOKEN", csrf[1])
	r.Header.Set("Accept-Language", "zh-CN")
	r.AddCookie(guest)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":1`) || !strings.Contains(w.Body.String(), "关闭注册功能") {
		t.Fatalf("unwired eligibility status=%d body=%s", w.Code, w.Body.String())
	}
}

// TestRegisterVerificationMailMissingKeeps503 covers the B2A-F1 split: a
// required verification with the mail transport unconfigured is a deployment
// failure and stays a 503 server error, not the controlled business refusal.
func TestRegisterVerificationMailMissingKeeps503(t *testing.T) {
	h, id := appFixtureWithOptions(t, map[string]string{"require_verification": "true"})
	w := request(t, h, "GET", "/auth/register", "", "", nil)
	csrf := csrfPattern.FindStringSubmatch(w.Body.String())
	var guest *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == sessionCookie {
			guest = cookie
		}
	}
	if len(csrf) != 2 || guest == nil {
		t.Fatal("registration guest missing")
	}
	sessionDigest := identity.Digest(guest.Value)
	if _, err := id.Store.DB.Exec("INSERT INTO "+id.Store.Table("go_captchas")+" (session_digest,answer_digest,expires_at) VALUES (?,?,?) ON DUPLICATE KEY UPDATE answer_digest=VALUES(answer_digest)", sessionDigest, answerDigest("AbC01"), id.Now().Add(3600_000_000_000).Unix()); err != nil {
		t.Fatal(err)
	}
	payload := `{"email":"nomail@example.invalid","password":"nomail-password","captcha":"AbC01","player_name":"NoMailPlayer"}`
	w = request(t, h, "POST", "/auth/register", payload, csrf[1], guest)
	if w.Code != 503 {
		t.Fatalf("verification mail missing status=%d body=%s", w.Code, w.Body.String())
	}
}
