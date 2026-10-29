package oauthserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/testsupport"
)

func fixture(t *testing.T) *Server {
	return fixtureConfig(t, nil)
}
func fixtureConfig(t *testing.T, change func(*Config)) *Server {
	t.Helper()
	store, id := testsupport.Database(t, "m2_")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c := Config{Store: store, Identity: id, PrivateKey: key, Secret: []byte("synthetic-m2-opaque-secret-only-32bytes"), Issuer: "https://skin.example.invalid", Scopes: []string{"User.Read", "Player.Read", "Player.ReadWrite"}, AccessLifetime: time.Hour, RefreshLifetime: 24 * time.Hour, CodeLifetime: 10 * time.Minute}
	if change != nil {
		change(&c)
	}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestExpiredCredentialsAndCurrentClient(t *testing.T) {
	t.Run("expired code", func(t *testing.T) {
		s := fixtureConfig(t, func(c *Config) { c.CodeLifetime = time.Nanosecond })
		status, _ := exchange(s, codeForm(authorize(t, s, true)))
		if status == 200 {
			t.Fatal("expired code accepted")
		}
	})
	t.Run("expired refresh", func(t *testing.T) {
		s := fixtureConfig(t, func(c *Config) { c.RefreshLifetime = time.Nanosecond })
		status, data := exchange(s, codeForm(authorize(t, s, true)))
		success(t, status, data)
		status, _ = exchange(s, refreshForm(data["refresh_token"].(string)))
		if status == 200 {
			t.Fatal("expired refresh accepted")
		}
		if _, err := s.Validate(t.Context(), data["access_token"].(string)); err != nil {
			t.Fatal("expired refresh revoked a valid access token")
		}
	})
	t.Run("scope and revoked client", func(t *testing.T) {
		s := fixture(t)
		status, data := exchange(s, codeForm(authorize(t, s, true)))
		success(t, status, data)
		q := refreshForm(data["refresh_token"].(string))
		q.Set("scope", "Player.ReadWrite")
		status, _ = exchange(s, q)
		if status == 200 {
			t.Fatal("refresh expanded scope")
		}
		if _, err := s.cfg.Store.DB.Exec("UPDATE " + s.cfg.Store.Table("oauth_clients") + " SET revoked=1 WHERE id=1"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Validate(t.Context(), data["access_token"].(string)); !errors.Is(err, ErrToken) {
			t.Fatal("revoked client accepted")
		}
		status, _ = exchange(s, refreshForm(data["refresh_token"].(string)))
		if status == 200 {
			t.Fatal("revoked client refreshed")
		}
	})
}

const verifier = "synthetic-pkce-verifier-of-at-least-forty-three-characters"

func authorize(t *testing.T, s *Server, pkce bool) string {
	t.Helper()
	q := url.Values{"response_type": {"code"}, "client_id": {"1"}, "redirect_uri": {"https://client.example.invalid/callback"}, "state": {"synthetic-state-value"}, "scope": {"User.Read"}}
	if pkce {
		sum := sha256.Sum256([]byte(verifier))
		q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
		q.Set("code_challenge_method", "S256")
	}
	r := httptest.NewRequest("GET", "https://skin.example.invalid/oauth/authorize?"+q.Encode(), nil)
	browser, err := s.cfg.Identity.Login(t.Context(), "user@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	code, err := s.Authorize(t.Context(), r, browser)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestAuthorizeRechecksBrowserAndDoesNotGrantWildcard(t *testing.T) {
	s := fixture(t)
	b, err := s.cfg.Identity.Login(t.Context(), "user@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	q := url.Values{"response_type": {"code"}, "client_id": {"1"}, "redirect_uri": {"https://client.example.invalid/callback"}, "state": {"synthetic-state-value"}, "scope": {"*"}}
	makeRequest := func() *http.Request {
		return httptest.NewRequest("GET", "https://skin.example.invalid/oauth/authorize?"+q.Encode(), nil)
	}
	code, err := s.Authorize(t.Context(), makeRequest(), b)
	if err != nil {
		t.Fatal(err)
	}
	form := codeForm(code)
	form.Del("code_verifier")
	status, data := exchange(s, form)
	success(t, status, data)
	if _, err = s.Validate(t.Context(), data["access_token"].(string), "Player.ReadWrite"); !errors.Is(err, ErrScope) {
		t.Fatal("code grant acquired wildcard scope")
	}
	if err = s.cfg.Identity.Logout(t.Context(), b.Token); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authorize(t.Context(), makeRequest(), b); !errors.Is(err, identity.ErrSession) {
		t.Fatal("logged-out browser authorized a code")
	}
}

func TestPublicClientRequiresPKCE(t *testing.T) {
	s := fixture(t)
	if _, err := s.cfg.Store.DB.Exec("UPDATE " + s.cfg.Store.Table("oauth_clients") + " SET secret='' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	browser, err := s.cfg.Identity.Login(t.Context(), "user@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	issue := func(challenge, method string) (string, error) {
		q := url.Values{"response_type": {"code"}, "client_id": {"1"}, "redirect_uri": {"https://client.example.invalid/callback"}, "state": {"synthetic-state-value"}, "scope": {"User.Read"}}
		if challenge != "" {
			q.Set("code_challenge", challenge)
		}
		if method != "" {
			q.Set("code_challenge_method", method)
		}
		return s.Authorize(t.Context(), httptest.NewRequest("GET", "https://skin.example.invalid/oauth/authorize?"+q.Encode(), nil), browser)
	}
	if _, err = issue("", ""); err == nil {
		t.Fatal("public client authorized without PKCE")
	}
	for _, method := range []string{"S256", "plain", ""} {
		t.Run("method="+method, func(t *testing.T) {
			challenge := verifier
			if method == "S256" {
				sum := sha256.Sum256([]byte(verifier))
				challenge = base64.RawURLEncoding.EncodeToString(sum[:])
			}
			code, err := issue(challenge, method)
			if err != nil {
				t.Fatal(err)
			}
			form := codeForm(code)
			form.Del("client_secret")
			form.Del("code_verifier")
			status, _ := exchange(s, form)
			if status == 200 {
				t.Fatal("public code redeemed without verifier")
			}
			form.Set("code_verifier", verifier+"-wrong")
			status, _ = exchange(s, form)
			if status == 200 {
				t.Fatal("wrong verifier accepted")
			}
			form.Set("code_verifier", verifier)
			status, data := exchange(s, form)
			success(t, status, data)
		})
	}
}
func exchange(s *Server, q url.Values) (int, map[string]any) {
	r := httptest.NewRequest("POST", "https://skin.example.invalid/oauth/token", strings.NewReader(q.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Token(w, r)
	var data map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &data)
	return w.Code, data
}
func codeForm(code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {"1"}, "client_secret": {"client-secret"}, "redirect_uri": {"https://client.example.invalid/callback"}, "code": {code}, "code_verifier": {verifier}}
}
func refreshForm(refresh string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "client_id": {"1"}, "client_secret": {"client-secret"}, "refresh_token": {refresh}}
}
func success(t *testing.T, status int, data map[string]any) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("status=%d error=%v", status, data["error"])
	}
	if _, ok := data["access_token"].(string); !ok {
		t.Fatalf("missing access token; fields=%v", data["error"])
	}
}

func TestCodePKCEClientScopeAndSignature(t *testing.T) {
	s := fixture(t)
	code := authorize(t, s, true)
	for _, field := range []string{"code_verifier", "redirect_uri", "client_secret", "client_id"} {
		q := codeForm(code)
		q.Set(field, "incorrect")
		status, _ := exchange(s, q)
		if status == 200 {
			t.Fatalf("accepted wrong %s", field)
		}
	}
	status, data := exchange(s, codeForm(code))
	success(t, status, data)
	token := data["access_token"].(string)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("access token is not JWT")
	}
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var h map[string]any
	_ = json.Unmarshal(header, &h)
	if h["alg"] != "RS256" {
		t.Fatal("wrong signing algorithm")
	}
	p, err := s.Validate(t.Context(), token, "User.Read")
	if err != nil || p.UID != 1 || p.ClientID != "1" {
		t.Fatalf("validation failed: %v", err)
	}
	if _, err = s.Validate(t.Context(), token, "Player.ReadWrite"); err == nil {
		t.Fatal("scope expanded")
	}
	if _, err = s.Validate(t.Context(), token+"invalid"); err == nil {
		t.Fatal("accepted invalid signature")
	}
	status, _ = exchange(s, codeForm(code))
	if status == 200 {
		t.Fatal("code replay succeeded")
	}
	if _, err = s.Validate(t.Context(), token); err == nil {
		t.Fatal("code replay revocation did not persist")
	}
}

func TestFailedIssuanceRetainsCodeAndPKCE(t *testing.T) {
	s := fixture(t)
	code := authorize(t, s, true)
	_, err := s.cfg.Store.DB.Exec("CREATE TRIGGER fail_access BEFORE INSERT ON " + s.cfg.Store.Table("go_oauth_access") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic insert failure'")
	if err != nil {
		t.Fatal(err)
	}
	status, _ := exchange(s, codeForm(code))
	if status == 200 {
		t.Fatal("failed transaction succeeded")
	}
	if _, err = s.cfg.Store.DB.Exec("DROP TRIGGER fail_access"); err != nil {
		t.Fatal(err)
	}
	status, data := exchange(s, codeForm(code))
	success(t, status, data)
}

func TestRefreshRotationReplayAndUIDRevocation(t *testing.T) {
	s := fixture(t)
	status, data := exchange(s, codeForm(authorize(t, s, true)))
	success(t, status, data)
	original := data["access_token"].(string)
	refresh := data["refresh_token"].(string)
	bad := refreshForm(refresh)
	bad.Set("client_id", "2")
	bad.Set("client_secret", "other-secret")
	status, _ = exchange(s, bad)
	if status == 200 {
		t.Fatal("other client refreshed token")
	}
	status, rotated := exchange(s, refreshForm(refresh))
	success(t, status, rotated)
	if _, err := s.Validate(t.Context(), original); err == nil {
		t.Fatal("old access still active")
	}
	if _, err := s.Validate(t.Context(), rotated["access_token"].(string)); err != nil {
		t.Fatal(err)
	}
	status, _ = exchange(s, refreshForm(refresh))
	if status == 200 {
		t.Fatal("refresh replay succeeded")
	}
	if _, err := s.Validate(t.Context(), rotated["access_token"].(string)); err == nil {
		t.Fatal("refresh replay revocation rolled back")
	}
	status, data = exchange(s, codeForm(authorize(t, s, true)))
	success(t, status, data)
	err := s.cfg.Store.Transaction(t.Context(), func(tx *sql.Tx) error {
		var uid int
		if err := tx.QueryRow("SELECT uid FROM " + s.cfg.Store.Table("users") + " WHERE uid=1 FOR UPDATE").Scan(&uid); err != nil {
			return err
		}
		return s.cfg.Identity.RevokeUID(t.Context(), tx, 1)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Validate(t.Context(), data["access_token"].(string)); err == nil {
		t.Fatal("UID revocation bypassed")
	}
}

func TestConcurrentCodeAndRefresh(t *testing.T) {
	s := fixture(t)
	for _, kind := range []string{"code", "refresh"} {
		t.Run(kind, func(t *testing.T) {
			q := codeForm(authorize(t, s, true))
			if kind == "refresh" {
				status, data := exchange(s, q)
				success(t, status, data)
				q = refreshForm(data["refresh_token"].(string))
			}
			var wg sync.WaitGroup
			statuses := make(chan int, 2)
			for i := 0; i < 2; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); status, _ := exchange(s, q); statuses <- status }()
			}
			wg.Wait()
			close(statuses)
			wins := 0
			for status := range statuses {
				if status == 200 {
					wins++
				}
			}
			if wins != 1 {
				t.Fatalf("issued %d results for one credential", wins)
			}
		})
	}
}

func TestPasswordAndClientCredentials(t *testing.T) {
	s := fixture(t)
	status, data := exchange(s, url.Values{"grant_type": {"password"}, "client_id": {"3"}, "client_secret": {"password-secret"}, "username": {"user@example.invalid"}, "password": {"original-password"}, "scope": {"User.Read"}})
	success(t, status, data)
	if _, err := s.Validate(context.Background(), data["access_token"].(string), "User.Read"); err != nil {
		t.Fatal(err)
	}
	status, data = exchange(s, url.Values{"grant_type": {"client_credentials"}, "client_id": {"1"}, "client_secret": {"client-secret"}, "scope": {"User.Read"}})
	success(t, status, data)
	p, err := s.Validate(t.Context(), data["access_token"].(string))
	if err != nil || p.UID != 0 {
		t.Fatalf("client credential invented user: %v", err)
	}
}

func TestTamperedConsumedCredentialsCannotRevokeGrant(t *testing.T) {
	s := fixture(t)
	tamper := func(value string) string {
		parts := strings.Split(value, ".")
		if len(parts) != 2 {
			t.Fatal("unexpected opaque token shape")
		}
		if parts[0][0] == 'A' {
			parts[0] = "B" + parts[0][1:]
		} else {
			parts[0] = "A" + parts[0][1:]
		}
		return strings.Join(parts, ".")
	}
	code := authorize(t, s, true)
	status, data := exchange(s, codeForm(code))
	success(t, status, data)
	status, _ = exchange(s, codeForm(tamper(code)))
	if status == 200 {
		t.Fatal("tampered code accepted")
	}
	if _, err := s.Validate(t.Context(), data["access_token"].(string)); err != nil {
		t.Fatal("tampered consumed code revoked valid grant")
	}
	old := data["refresh_token"].(string)
	status, rotated := exchange(s, refreshForm(old))
	success(t, status, rotated)
	status, _ = exchange(s, refreshForm(tamper(old)))
	if status == 200 {
		t.Fatal("tampered refresh accepted")
	}
	if _, err := s.Validate(t.Context(), rotated["access_token"].(string)); err != nil {
		t.Fatal("tampered consumed refresh revoked valid grant")
	}
}

func TestPersistenceFailureIsNotInvalidGrant(t *testing.T) {
	s := fixture(t)
	status, data := exchange(s, codeForm(authorize(t, s, true)))
	success(t, status, data)
	if _, err := s.cfg.Store.DB.Exec("DROP TABLE " + s.cfg.Store.Table("go_auth_versions")); err != nil {
		t.Fatal(err)
	}
	status, result := exchange(s, refreshForm(data["refresh_token"].(string)))
	if status != 500 || result["error"] != "server_error" {
		t.Fatalf("database fault: status=%d error=%v", status, result["error"])
	}
}

func TestPasswordRecheckDatabaseFailureIsServerError(t *testing.T) {
	s := fixture(t)
	_, err := s.cfg.Store.DB.Exec("CREATE TRIGGER fail_version BEFORE INSERT ON " + s.cfg.Store.Table("go_auth_versions") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic version failure'")
	if err != nil {
		t.Fatal(err)
	}
	status, result := exchange(s, url.Values{"grant_type": {"password"}, "client_id": {"3"}, "client_secret": {"password-secret"}, "username": {"user@example.invalid"}, "password": {"original-password"}})
	if status != 500 || result["error"] != "server_error" {
		t.Fatalf("password recheck database fault: status=%d error=%v", status, result["error"])
	}
}

func TestPersonalTokenAndValidationFailureClassification(t *testing.T) {
	s := fixture(t)
	if _, err := s.cfg.Store.DB.Exec("INSERT INTO " + s.cfg.Store.Table("oauth_clients") + " (id,name,secret,redirect,personal_access_client) VALUES (4,'Personal','synthetic-personal-secret','http://localhost',1)"); err != nil {
		t.Fatal(err)
	}
	b, err := s.cfg.Identity.Login(t.Context(), "user@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.IssuePersonalToken(t.Context(), b, "Local tool", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Validate(t.Context(), token.AccessToken, "Player.ReadWrite")
	if err != nil || p.UID != 1 {
		t.Fatalf("personal token: %v", err)
	}
	if _, err = s.IssuePersonalToken(t.Context(), b, "Unknown", []string{"unknown"}); !errors.Is(err, ErrScope) {
		t.Fatal("unknown scope accepted")
	}
	status, _ := exchange(s, url.Values{"grant_type": {"personal_access"}, "client_id": {"4"}, "client_secret": {"synthetic-personal-secret"}, "user_id": {"1"}})
	if status == 200 {
		t.Fatal("public personal grant enabled")
	}
	if err = s.cfg.Identity.Logout(t.Context(), b.Token); err != nil {
		t.Fatal(err)
	}
	if _, err = s.IssuePersonalToken(t.Context(), b, "After logout", []string{"User.Read"}); !errors.Is(err, identity.ErrSession) {
		t.Fatalf("personal issuance after logout: %v", err)
	}
	if _, err = s.Validate(t.Context(), token.AccessToken); err != nil {
		t.Fatal("ordinary logout revoked OAuth token")
	}
	if _, err = s.cfg.Store.DB.Exec("DROP TABLE " + s.cfg.Store.Table("go_auth_versions")); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Validate(t.Context(), token.AccessToken); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("SQL failure classified as credential error: %v", err)
	}
}

func TestOAuthStatePayloadMeasurement(t *testing.T) {
	s := fixture(t)
	status, data := exchange(s, codeForm(authorize(t, s, true)))
	success(t, status, data)
	status, data = exchange(s, refreshForm(data["refresh_token"].(string)))
	success(t, status, data)
	for _, table := range []string{"go_oauth_codes", "go_oauth_access", "go_oauth_refresh", "go_oauth_pkce"} {
		var rows int
		var bytes float64
		if err := s.cfg.Store.DB.QueryRow("SELECT COUNT(*),COALESCE(AVG(OCTET_LENGTH(payload)),0) FROM "+s.cfg.Store.Table(table)).Scan(&rows, &bytes); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s rows=%d average_payload_bytes=%.1f", table, rows, bytes)
	}
}
