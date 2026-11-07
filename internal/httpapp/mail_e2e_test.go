//go:build e2e

package httpapp

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"blessing-skin-go/internal/account"
	"blessing-skin-go/internal/config"
	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/oauthserver"
	"blessing-skin-go/internal/outbox"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/testsupport"
	"blessing-skin-go/internal/yggdrasil"
	"blessing-skin-go/web"
)

// smtpCapture is one accepted message plus its transport properties.
type smtpCapture struct {
	data                     []byte
	authenticated, encrypted bool
}

// startSimulator runs a loopback SMTP server that speaks EHLO/STARTTLS/AUTH
// PLAIN/DATA with a self-signed CA, mirroring the frozen app's STARTTLS path.
func startSimulator(t *testing.T) (config.MailConfig, *tls.Config, <-chan smtpCapture) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "local SMTP e2e"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	cfg := config.MailConfig{
		Mailer: "smtp", Host: host, Port: port, Encryption: "tls",
		Username: "synthetic", Password: "synthetic-password",
		FromAddress: "sender@example.invalid", FromName: "Synthetic",
		SendTimeout: 2 * time.Second, RetryDelay: time.Minute,
	}
	captures := make(chan smtpCapture, 8)
	stop := make(chan struct{})
	var mutex sync.Mutex
	var accepted net.Conn
	var wg sync.WaitGroup
	t.Cleanup(func() {
		close(stop)
		listener.Close()
		mutex.Lock()
		if accepted != nil {
			accepted.Close()
		}
		mutex.Unlock()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mutex.Lock()
			accepted = conn
			mutex.Unlock()
			go serveSimulator(conn, serverTLS, captures)
		}
	}()
	return cfg, &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS12}, captures
}

func serveSimulator(conn net.Conn, serverTLS *tls.Config, captures chan<- smtpCapture) {
	defer conn.Close()
	reader := textproto.NewReader(bufio.NewReader(conn))
	writer := textproto.NewWriter(bufio.NewWriter(conn))
	encrypted, authenticated := false, false
	if err := writer.PrintfLine("220 local SMTP e2e"); err != nil {
		return
	}
	for {
		line, err := reader.ReadLine()
		if err != nil {
			return
		}
		switch strings.ToUpper(strings.SplitN(line, " ", 2)[0]) {
		case "EHLO":
			writer.PrintfLine("250-local")
			if !encrypted {
				writer.PrintfLine("250-STARTTLS")
			}
			writer.PrintfLine("250 AUTH PLAIN")
		case "HELO", "NOOP", "RSET":
			writer.PrintfLine("250 OK")
		case "STARTTLS":
			if err = writer.PrintfLine("220 Ready"); err != nil {
				return
			}
			conn = tls.Server(conn, serverTLS)
			encrypted = true
			reader = textproto.NewReader(bufio.NewReader(conn))
			writer = textproto.NewWriter(bufio.NewWriter(conn))
		case "AUTH":
			fields := strings.Fields(line)
			if len(fields) != 3 {
				writer.PrintfLine("535 authentication failed")
				continue
			}
			decoded, err := base64.StdEncoding.DecodeString(fields[2])
			authenticated = err == nil && string(decoded) == "\x00synthetic\x00synthetic-password"
			if authenticated {
				writer.PrintfLine("235 authenticated")
			} else {
				writer.PrintfLine("535 authentication failed")
			}
		case "MAIL":
			writer.PrintfLine("250 OK")
		case "RCPT":
			writer.PrintfLine("250 OK")
		case "DATA":
			if err = writer.PrintfLine("354 Send data"); err != nil {
				return
			}
			data, err := io.ReadAll(reader.DotReader())
			if err != nil {
				return
			}
			captures <- smtpCapture{data, authenticated, encrypted}
			writer.PrintfLine("250 accepted")
		case "QUIT":
			writer.PrintfLine("221 goodbye")
			return
		default:
			writer.PrintfLine("500 unknown command")
		}
	}
}

// linkPattern matches the href target only (the frozen template repeats the
// URL as link text, which is whitespace-separated in the HTML body).
var linkPattern = regexp.MustCompile(`href="(https?://[^"]+/auth/(reset|verify)/(\d+)\?token=[A-Za-z0-9_-]+)"`)

// newMailTransportForTest points the server at the loopback simulator. The
// production factory is restored when the test ends.
func newMailTransportForTest(t *testing.T, trust *tls.Config) {
	t.Helper()
	original := newMailTransport
	newMailTransport = func(c config.MailConfig) (account.Transport, error) {
		transport, err := account.NewSMTP(c)
		if err != nil {
			return nil, err
		}
		if err = transport.SetTLSConfig(trust); err != nil {
			return nil, err
		}
		return transport, nil
	}
	t.Cleanup(func() { newMailTransport = original })
}

func mailFixture(t *testing.T, options map[string]string) (http.Handler, *identity.Service, *account.Service, *account.Mail, <-chan smtpCapture) {
	t.Helper()
	store, id := testsupport.Database(t, "mail-")
	smtpCfg, trust, captures := startSimulator(t)
	newMailTransportForTest(t, trust)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oauth, err := oauthserver.New(oauthserver.Config{Store: store, Identity: id, PrivateKey: key, Secret: []byte("synthetic-m2-secret-at-least-32-bytes"), Issuer: "http://localhost/skin", Scopes: oauthserver.DefaultScopes, AccessLifetime: time.Hour, RefreshLifetime: 24 * time.Hour, CodeLifetime: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		BaseURL: "http://localhost/skin", Locale: "zh_CN", FallbackLocale: "en",
		RememberLifetime: 400 * 24 * time.Hour, TexturesDir: t.TempDir(),
		Mail: smtpCfg, AppKey: []byte("0123456789abcdef0123456789abcdef"),
	}
	modules := testsupport.Modules(store, id)
	view := &site.Service{Store: store, Identity: id, Location: time.UTC, OptionSnapshot: options, Modules: modules}
	assets, err := web.Load()
	if err != nil {
		t.Fatal(err)
	}
	transport, err := newMailTransport(cfg.Mail)
	if err != nil {
		t.Fatal(err)
	}
	mailService, err := account.NewMail(cfg.AppKey, cfg.BaseURL, cfg.FallbackLocale, view, assets.Messages, transport, cfg.Mail.RetryDelay)
	if err != nil {
		t.Fatal(err)
	}
	accounts := account.New(store, id, view, mailService)
	accounts.Modules = modules
	handler, err := newWithAccounts(cfg, id, view, oauth, accounts, mailService, yggdrasil.New(store, id, nil, []byte("synthetic-yggdrasil-hs256-key-32b"), false, id.Now), "m4-05-test")
	if err != nil {
		t.Fatal(err)
	}
	return handler, id, accounts, mailService, captures
}

// deliverOne runs one worker pass with the frozen wiring: the same account
// service (and transport) the server uses; `serve` never delivers by itself.
func deliverOne(t *testing.T, id *identity.Service, accounts *account.Service, mailService *account.Mail) bool {
	t.Helper()
	queue := &outbox.Store{Database: id.Store, Now: time.Now}
	worked, err := queue.DeliverOne(t.Context(), map[string]outbox.Handler{account.MailTopic: mailService.Handler(accounts)}, time.Minute)
	if err != nil {
		t.Fatalf("outbox delivery: %v", err)
	}
	return worked
}

func captureOne(t *testing.T, captures <-chan smtpCapture) smtpCapture {
	t.Helper()
	select {
	case capture := <-captures:
		return capture
	case <-time.After(5 * time.Second):
		t.Fatal("mail was not captured")
	}
	return smtpCapture{}
}

func linkFrom(t *testing.T, capture smtpCapture) (string, string) {
	t.Helper()
	if !capture.encrypted || !capture.authenticated {
		t.Fatalf("captured message was not sent over authenticated STARTTLS")
	}
	message, err := mail.ReadMessage(bytes.NewReader(capture.data))
	if err != nil {
		t.Fatal(err)
	}
	if message.Header.Get("Message-ID") == "" || !strings.Contains(message.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("MIME headers changed: %v", message.Header)
	}
	body, err := io.ReadAll(message.Body)
	if err != nil {
		t.Fatal(err)
	}
	// go-mail encodes HTML bodies as quoted-printable; soft line breaks would
	// otherwise split the token across lines.
	if strings.Contains(message.Header.Get("Content-Transfer-Encoding"), "quoted-printable") {
		var decoded bytes.Buffer
		if _, err = io.Copy(&decoded, quotedprintable.NewReader(bytes.NewReader(body))); err != nil {
			t.Fatal(err)
		}
		body = decoded.Bytes()
	}
	matches := linkPattern.FindAllStringSubmatch(string(body), -1)
	if len(matches) != 1 {
		t.Fatalf("expected exactly one challenge link, got %v", matches)
	}
	return matches[0][2], matches[0][1]
}

// TestMailResetEndToEnd covers forgot → worker → SMTP → link → reset, including
// single-use consumption and the obsolete-after-resend rule.
func TestMailResetEndToEnd(t *testing.T) {
	handler, id, accounts, mailService, captures := mailFixture(t, nil)
	seedChallengeState(t, id)
	// Request a reset for the seeded account.
	w := requestForgot(t, handler, id.Store)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("forgot status=%d body=%s", w.Code, w.Body.String())
	}
	if !deliverOne(t, id, accounts, mailService) {
		t.Fatal("outbox did not deliver the reset challenge")
	}
	_, link := linkFrom(t, captureOne(t, captures))
	if !strings.Contains(link, "/auth/reset/1?token=") {
		t.Fatalf("unexpected reset link %q", link)
	}
	resetPath := strings.TrimPrefix(link, "http://localhost/skin")
	csrf, resetCookie := guestCSRF(t, handler, resetPath)
	if w = request(t, handler, "POST", resetPath, `{"password":"new-password-1"}`, csrf, resetCookie); w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("reset submit status=%d body=%s", w.Code, w.Body.String())
	}
	// Same token again: consumed. The reset page itself now 403s (the challenge
	// is gone), so the replay reuses the session/CSRF obtained above.
	w = request(t, handler, "POST", resetPath, `{"password":"new-password-2"}`, csrf, resetCookie)
	if w.Code != 403 {
		t.Fatalf("reused reset token status=%d", w.Code)
	}
	// The new password works (the old one no longer does, asserted below).
	loginCSRF, loginCookie := guestCSRF(t, handler, "/auth/login")
	login := request(t, handler, "POST", "/auth/login", `{"identification":"user@example.invalid","password":"new-password-1"}`, loginCSRF, loginCookie)
	if login.Code != 200 || !strings.Contains(login.Body.String(), `"code":0`) {
		t.Fatalf("login with new password status=%d body=%s", login.Code, login.Body.String())
	}
	oldCSRF, oldCookie := guestCSRF(t, handler, "/auth/login")
	old := request(t, handler, "POST", "/auth/login", `{"identification":"user@example.invalid","password":"original-password"}`, oldCSRF, oldCookie)
	if old.Code == 200 && strings.Contains(old.Body.String(), `"code":0`) {
		t.Fatal("old password still works after reset")
	}
	var challenges int
	id.Store.DB.QueryRow("SELECT COUNT(*) FROM " + id.Store.Table("go_mail_challenges")).Scan(&challenges)
	if challenges != 0 {
		t.Fatalf("challenge rows left after reset: %d", challenges)
	}
}

// TestMailResendInvalidatesPreviousToken covers the obsolete-challenge rule.
func TestMailResendInvalidatesPreviousToken(t *testing.T) {
	handler, id, accounts, mailService, captures := mailFixture(t, nil)
	seedChallengeState(t, id)
	if w := requestForgot(t, handler, id.Store); w.Code != 200 {
		t.Fatalf("first forgot status=%d", w.Code)
	}
	if !deliverOne(t, id, accounts, mailService) {
		t.Fatal("first delivery missing")
	}
	_, firstLink := linkFrom(t, captureOne(t, captures))
	// Drop the IP cooldown so a second request is accepted.
	if _, err := id.Store.DB.Exec("DELETE FROM " + id.Store.Table("go_browser_limits")); err != nil {
		t.Fatal(err)
	}
	if w := requestForgot(t, handler, id.Store); w.Code != 200 {
		t.Fatalf("second forgot status=%d", w.Code)
	}
	if !deliverOne(t, id, accounts, mailService) {
		t.Fatal("second delivery missing")
	}
	_, secondLink := linkFrom(t, captureOne(t, captures))
	if firstLink == secondLink {
		t.Fatal("resend reused the same token")
	}
	secondPath := strings.TrimPrefix(secondLink, "http://localhost/skin")
	csrf, resetCookie := guestCSRF(t, handler, secondPath)
	firstPath := strings.TrimPrefix(firstLink, "http://localhost/skin")
	if w := request(t, handler, "POST", firstPath, `{"password":"another-password"}`, csrf, resetCookie); w.Code != 403 {
		t.Fatalf("superseded token accepted, status=%d", w.Code)
	}
	if w := request(t, handler, "POST", secondPath, `{"password":"another-password"}`, csrf, resetCookie); w.Code != 200 {
		t.Fatalf("current token rejected, status=%d body=%s", w.Code, w.Body.String())
	}
}

// TestMailVerificationEndToEnd covers the verify leg, including the email
// mismatch branch that leaves the account unverified.
func TestMailVerificationEndToEnd(t *testing.T) {
	handler, id, accounts, mailService, captures := mailFixture(t, map[string]string{"require_verification": "true"})
	seedChallengeState(t, id)
	if _, err := id.Store.DB.Exec("UPDATE " + id.Store.Table("users") + " SET verified=0 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := credentials(t, handler, false)
	w := request(t, handler, "POST", "/user/email-verification", `{}`, csrf, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"code":0`) {
		t.Fatalf("verification request status=%d body=%s", w.Code, w.Body.String())
	}
	if !deliverOne(t, id, accounts, mailService) {
		t.Fatal("verification mail missing")
	}
	kind, link := linkFrom(t, captureOne(t, captures))
	if kind != "verify" {
		t.Fatalf("expected verify link, got %q", kind)
	}
	path := strings.TrimPrefix(link, "http://localhost/skin")
	verifyCSRF, verifyCookie := guestCSRF(t, handler, path)
	w = request(t, handler, "POST", path, `{"email":"wrong@example.invalid"}`, verifyCSRF, verifyCookie)
	if w.Code != 302 {
		t.Fatalf("mismatched email status=%d body=%s", w.Code, w.Body.String())
	}
	var verified bool
	id.Store.DB.QueryRow("SELECT verified FROM " + id.Store.Table("users") + " WHERE uid=1").Scan(&verified)
	if verified {
		t.Fatal("mismatched email verified the account")
	}
	verifyCSRF, verifyCookie = guestCSRF(t, handler, path)
	w = request(t, handler, "POST", path, `{"email":"user@example.invalid"}`, verifyCSRF, verifyCookie)
	if w.Code != 302 {
		t.Fatalf("verification status=%d body=%s", w.Code, w.Body.String())
	}
	id.Store.DB.QueryRow("SELECT verified FROM " + id.Store.Table("users") + " WHERE uid=1").Scan(&verified)
	if !verified {
		t.Fatal("account was not verified")
	}
}

// requestForgot requests a reset for the seeded account. The frozen endpoint is
// a CSRF-protected browser route that also requires a local CAPTCHA; the test
// fetches a real image (exercising the endpoint) and then replaces the stored
// digest with a known answer so the mail flow can proceed. CAPTCHA generation
// itself is covered by the captcha package's own tests.
func requestForgot(t *testing.T, handler http.Handler, store *database.Store) *httptest.ResponseRecorder {
	t.Helper()
	return forgotFor(t, handler, store, "user@example.invalid")
}

const testCaptchaAnswer = "abcde"

func forgotFor(t *testing.T, handler http.Handler, store *database.Store, email string) *httptest.ResponseRecorder {
	t.Helper()
	w := request(t, handler, "GET", "/auth/forgot", "", "", nil)
	match := csrfPattern.FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatalf("missing CSRF on forgot page: %d", w.Code)
	}
	var cookie *http.Cookie
	for _, candidate := range w.Result().Cookies() {
		if candidate.Name == sessionCookie {
			cookie = candidate
		}
	}
	if cookie == nil {
		t.Fatal("missing session cookie on forgot page")
	}
	if image := request(t, handler, "GET", "/auth/captcha", "", "", cookie); image.Code != 200 || image.Header().Get("Content-Type") != "image/jpeg" {
		t.Fatalf("captcha image status=%d type=%s", image.Code, image.Header().Get("Content-Type"))
	}
	if _, err := store.DB.Exec("UPDATE "+store.Table("go_captchas")+" SET answer_digest=? WHERE session_digest=?", identity.Digest(testCaptchaAnswer), identity.Digest(cookie.Value)); err != nil {
		t.Fatal(err)
	}
	body := `{"email":"` + email + `","captcha":"` + testCaptchaAnswer + `"}`
	r := httptest.NewRequest("POST", "http://localhost/skin/auth/forgot", strings.NewReader(body))
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	r.Header.Set("X-CSRF-TOKEN", match[1])
	r.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	return recorder
}

// guestCSRF loads a guest page (the reset/verify form) and returns its CSRF
// token and session cookie, mirroring how a browser obtains them.
func guestCSRF(t *testing.T, handler http.Handler, path string) (string, *http.Cookie) {
	t.Helper()
	w := request(t, handler, "GET", path, "", "", nil)
	match := csrfPattern.FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatalf("missing CSRF on %s: %d", path, w.Code)
	}
	var cookie *http.Cookie
	for _, candidate := range w.Result().Cookies() {
		if candidate.Name == sessionCookie {
			cookie = candidate
		}
	}
	return match[1], cookie
}

// seedChallengeState keeps the fixture's account requestable: the frozen
// forgot flow needs an existing account and no pending cooldown.
func seedChallengeState(t *testing.T, id *identity.Service) {
	t.Helper()
	if _, err := id.Store.DB.Exec("DELETE FROM " + id.Store.Table("go_browser_limits")); err != nil {
		t.Fatal(err)
	}
}

// TestServeNeverDeliversMail asserts the structural rule: the HTTP server does
// not run the outbox; a task stays pending until the worker (or this test)
// delivers it.
func TestServeNeverDeliversMail(t *testing.T) {
	handler, id, _, _, _ := mailFixture(t, nil)
	seedChallengeState(t, id)
	if w := requestForgot(t, handler, id.Store); w.Code != 200 {
		t.Fatalf("forgot status=%d", w.Code)
	}
	var pending int
	if err := id.Store.DB.QueryRow("SELECT COUNT(*) FROM " + id.Store.Table("go_outbox") + " WHERE completed_at IS NULL").Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending == 0 {
		t.Fatal("expected a pending outbox task")
	}
	time.Sleep(50 * time.Millisecond)
	if err := id.Store.DB.QueryRow("SELECT COUNT(*) FROM " + id.Store.Table("go_outbox") + " WHERE completed_at IS NULL").Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending == 0 {
		t.Fatal("serve delivered the outbox task; delivery must stay in the worker")
	}
}
