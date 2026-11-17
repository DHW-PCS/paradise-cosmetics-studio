// M4-08 game client acceptance (test-only): source/spec-driven consumers.
//
// This file owns the launcher / game-session / proxy / backend contract
// consumers and their orchestrated acceptance scenarios against the real Go
// App over a synthetic DB. It is deliberately independent from the product's
// token parser, Yggdrasil serializer, UUID generation and signature code:
// expectations come from the consumer models below or from frozen constants
// whose provenance is documented inline. Test helpers are prefixed m408 and
// code comments are English.
//
// Source oracles (pinned during M4-08 preparation, 2026-11-06):
//   - HMCL v3.16.4 (commit fbcc1747): YggdrasilAccount state machine and
//     YggdrasilService request/response handling.
//   - Velocity commit 7fc49913: EncryptionUtils.generateServerId and
//     PlayerDataForwarding.createForwardingData (+ ProtocolUtils writer
//     order).
//   - authlib-injector v1.2.8 (commit 5437f5b): metadata fields consumed
//     (signaturePublickey, skinDomains, feature.non_email_login) and the
//     RSA-SHA1 profile-property signature scheme.
//   - Legacy Blessing Skin yggdrasil-api plugin (reference tree): HS256
//     JWT issued by "Yggdrasil-Auth" whose subject is the UUIDv5(DNS,
//     email) hex (legacy shape), rejected here per the approved cutover
//     contract. Legacy subject UUIDs are computed from the real email via
//     RFC 4122, never random garbage.
//
// Frozen vectors below were computed with an independent tool (Python
// hashlib/hmac/uuid stdlib) at record time and are reproduced by
// the local implementations in this file; they are not derived from Go
// internals. No raw credential or response bodies are ever logged.
package httpapp

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"paradise-cosmetics-studio/internal/maintenance"
)

// ---------------------------------------------------------------------------
// Frozen constants and independent vectors
// ---------------------------------------------------------------------------

const (
	m408GameEmail      = "user@example.invalid"
	m408AdminEmail     = "admin@example.invalid"
	m408GamePass       = "original-password"
	m408PlayerDashed   = "12345678-1234-4234-8234-123456789abc" // m408UUID hex
	m408AlexDashed     = "20000000-0000-4000-8000-000000000001"
	m408AlexHex        = "20000000000040008000000000000001"
	m408ForwardingSec  = "m408-forwarding-secret-000"
	m408ForwardingAddr = "127.0.0.1:25565"
	m408ForwardingName = "PlayerOne"
	m408ForwardingUUID = "12345678-1234-4234-8234-123456789abc"
	// UUIDv5(DNS, "user@example.invalid") hex, RFC 4122 (independent).
	m408UUIDv5Email = "933d5b89845a5e57bb530e6e51a17c6c"
	// Offline UUID ("OfflinePlayer:" + "PlayerOne"), the well-known
	// CraftBukkit/MultiLogin OFFLINE generator shape (independent).
	m408OfflinePlayerOne = "9fcfeca6-a915-30ca-b4d5-90473e8e3017"
	// serverId = BigInteger(SHA-1(secret || serverPublicKeyDER)).toString(16).
	m408ServerIDVecA     = "47e92b0b70564bacc9b28e0fcf353f4166f41d53"
	m408ServerIDVecB     = "-7428718db4ce445b71dd27516ba0a14fd7cb3191"
	m408ServerIDNegative = "-7e5061eeea36e1543a45daa19f488b0d7e1d889b"
	// Modern forwarding message bytes (HMAC-SHA256(secret, payload) ++ payload)
	// for version 1 and version 4 with the canonical profile below.
	m408ForwardingV1Msg = "45177878b9c5a3e3fa4d24e0b484d08093b261ebc37b22eeb70c6f538a495bdb010f3132372e302e302e313a323535363512345678123442348234123456789abc09506c617965724f6e65010874657874757265730c5645465956564a4652413d3d010455306c48"
	m408ForwardingV4Msg = "2a02ed2d02f760c545a39563bdba7872064d7b8c59d45a62fad25e6671ee6937040f3132372e302e302e313a323535363512345678123442348234123456789abc09506c617965724f6e65010874657874757265730c5645465956564a4652413d3d010455306c48"
)

var m408VecProps = []m408ForwardingProperty{
	{Name: "textures", Value: "VEFYVVJFRA==", HasSignature: true, Signature: "U0lH"},
}

// ---------------------------------------------------------------------------
// Consumer-side error and response shapes
// ---------------------------------------------------------------------------

type m408ErrBody struct {
	Error        string `json:"error"`
	ErrorMessage string `json:"errorMessage"`
	Cause        string `json:"cause"`
}

func (b m408ErrBody) remote() *m408RemoteError {
	if b.Error == "" {
		return nil
	}
	return &m408RemoteError{Name: b.Error, Message: b.ErrorMessage, Cause: b.Cause}
}

// m408RemoteError is the Yggdrasil error object as consumed by HMCL
// (ErrorResponse.error/errorMessage/cause).
type m408RemoteError struct {
	Name, Message, Cause string
}

func (e *m408RemoteError) Error() string { return e.Name + ": " + e.Message }
func (e *m408RemoteError) IsForbidden() bool {
	return e.Name == "ForbiddenOperationException"
}

type m408HTTPError struct{ Status int }

func (e m408HTTPError) Error() string { return fmt.Sprintf("http status %d", e.Status) }

type m408NoCharacterError struct{}

func (m408NoCharacterError) Error() string { return "no character" }

type m408CharacterDeletedError struct{}

func (m408CharacterDeletedError) Error() string { return "character deleted" }

type m408CredentialExpiredError struct{}

func (m408CredentialExpiredError) Error() string { return "credential expired" }

type m408MalformedError struct{}

func (m408MalformedError) Error() string { return "malformed response" }

// m408AuthResponse mirrors HMCL AuthenticationResponse (extends ErrorResponse).
type m408AuthResponse struct {
	AccessToken       string        `json:"accessToken"`
	ClientToken       string        `json:"clientToken"`
	AvailableProfiles []m408Profile `json:"availableProfiles"`
	SelectedProfile   *m408Profile  `json:"selectedProfile"`
	User              *struct {
		ID         string `json:"id"`
		Properties []any  `json:"properties"`
	} `json:"user"`
	m408ErrBody
}

type m408HasJoinedDoc struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Properties []m408Property `json:"properties"`
}

type m408Session = m408GameSession

func m408OptionalError(status int, body []byte) error {
	if status == http.StatusNoContent && len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var eb m408ErrBody
	if err := json.Unmarshal(body, &eb); err == nil && eb.Error != "" {
		want := map[string]int{"IllegalArgumentException": 400, "UnauthorizedException": 401, "ForbiddenOperationException": 403, "NotFoundException": 404}[eb.Error]
		if status != want || eb.ErrorMessage == "" {
			return m408HTTPError{Status: status}
		}
		return eb.remote()
	}
	return m408HTTPError{Status: status}
}

func m408PostJSON(ep m408Endpoint, path string, payload any) (int, []byte) {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(payload)
	return m408Request(ep, "POST", path, map[string]string{"Content-Type": "application/json"}, &buf)
}

func m408Request(ep m408Endpoint, method, path string, headers map[string]string, body io.Reader) (int, []byte) {
	req, err := http.NewRequest(method, ep.BaseURL+path, body)
	if err != nil {
		return 0, nil
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := ep.Client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil
	}
	return resp.StatusCode, data
}

func m408RandomCompactUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b)
}

// m408FakeRoundTripper serves canned responses without binding any socket,
// so consumer qualification runs in sandboxed environments too.
type m408FakeRoundTripper struct {
	respond func(*http.Request) (*http.Response, error)
}

func (f m408FakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f.respond(req)
}

func m408FakeEndpoint(respond func(*http.Request) (*http.Response, error)) m408Endpoint {
	return m408Endpoint{
		BaseURL: "http://fake.invalid",
		Client:  &http.Client{Transport: m408FakeRoundTripper{respond: respond}},
	}
}

func m408FakeJSON(status int, body string) (*http.Response, error) {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}

// ---------------------------------------------------------------------------
// Launcher consumer: HMCL YggdrasilAccount model
// ---------------------------------------------------------------------------

// m408HMCL is a test-side model of the HMCL v3.16.4 launcher flow:
// authenticate -> validate -> refresh -> password reauth, including the
// random client token per authenticate, the client-token echo check and the
// CredentialExpired path. It speaks HTTP only.
type m408HMCL struct {
	ep            m408Endpoint
	clientToken   string
	session       *m408Session
	authenticated bool
}

func m408NewHMCL(ep m408Endpoint) *m408HMCL {
	return &m408HMCL{ep: ep, clientToken: m408RandomCompactUUID()}
}

func (c *m408HMCL) parseAuth(status int, body []byte) (*m408Session, error) {
	if status != http.StatusOK {
		return nil, m408OptionalError(status, body)
	}
	var res m408AuthResponse
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, m408MalformedError{}
	}
	if rem := res.m408ErrBody.remote(); rem != nil {
		return nil, rem
	}
	sess := &m408Session{AccessToken: res.AccessToken, ClientToken: res.ClientToken, SelectedProfile: res.SelectedProfile, AvailableProfiles: res.AvailableProfiles}
	if res.User != nil {
		sess.UserID = res.User.ID
	}
	return sess, nil
}

// authenticate mirrors YggdrasilService.authenticate: fresh client token,
// agent block, requestUser=true, then the client-token echo check and the
// zero-profile/selection rules of the YggdrasilAccount constructor.
func (c *m408HMCL) authenticate(username, password string) (*m408Session, error) {
	clientToken := m408RandomCompactUUID()
	payload := map[string]any{
		"agent":       map[string]any{"name": "Minecraft", "version": 1},
		"username":    username,
		"password":    password,
		"clientToken": clientToken,
		"requestUser": true,
	}
	status, body := m408PostJSON(c.ep, "/api/yggdrasil/authserver/authenticate", payload)
	sess, err := c.parseAuth(status, body)
	if err != nil {
		return nil, err
	}
	if sess.ClientToken != clientToken {
		return nil, fmt.Errorf("client token changed")
	}
	c.clientToken = clientToken
	return sess, nil
}

// refresh mirrors YggdrasilService.refresh, including the selected-profile
// response re-validation.
func (c *m408HMCL) refresh(accessToken string, selected *m408Profile) (*m408Session, error) {
	payload := map[string]any{"accessToken": accessToken, "clientToken": c.clientToken, "requestUser": true}
	if selected != nil {
		payload["selectedProfile"] = map[string]string{"id": selected.ID, "name": selected.Name}
	}
	status, body := m408PostJSON(c.ep, "/api/yggdrasil/authserver/refresh", payload)
	sess, err := c.parseAuth(status, body)
	if err != nil {
		return nil, err
	}
	if selected != nil && (sess.SelectedProfile == nil || !strings.EqualFold(sess.SelectedProfile.ID, selected.ID)) {
		return nil, m408MalformedError{}
	}
	return sess, nil
}

// validate mirrors YggdrasilService.validate: ForbiddenOperationException is
// the not-valid answer, any other error propagates.
func (c *m408HMCL) validate(accessToken string) (bool, error) {
	payload := map[string]any{"accessToken": accessToken, "clientToken": c.clientToken}
	status, body := m408PostJSON(c.ep, "/api/yggdrasil/authserver/validate", payload)
	err := m408OptionalError(status, body)
	if err == nil {
		return true, nil
	}
	if rem, ok := err.(*m408RemoteError); ok && rem.IsForbidden() {
		return false, nil
	}
	return false, err
}

// withPassword mirrors YggdrasilAccount.logInWithPassword.
func (c *m408HMCL) withPassword(username, password string, want *m408Profile) (*m408Session, error) {
	acquired, err := c.authenticate(username, password)
	if err != nil {
		return nil, err
	}
	if acquired.SelectedProfile == nil {
		if len(acquired.AvailableProfiles) == 0 || want == nil {
			return nil, m408CharacterDeletedError{}
		}
		var found *m408Profile
		for i := range acquired.AvailableProfiles {
			if strings.EqualFold(acquired.AvailableProfiles[i].ID, want.ID) {
				found = &acquired.AvailableProfiles[i]
				break
			}
		}
		if found == nil {
			return nil, m408CharacterDeletedError{}
		}
		sess, err := c.refresh(acquired.AccessToken, found)
		if err != nil {
			return nil, err
		}
		c.session = sess
		c.authenticated = true
		return sess, nil
	}
	if want != nil && !strings.EqualFold(acquired.SelectedProfile.ID, want.ID) {
		return nil, m408CharacterDeletedError{}
	}
	c.session = acquired
	c.authenticated = true
	return acquired, nil
}

// login mirrors YggdrasilAccount.logIn (stored-session path).
func (c *m408HMCL) login() (*m408Session, error) {
	if c.authenticated && c.session != nil && c.session.SelectedProfile != nil {
		return c.session, nil
	}
	if c.session == nil || c.session.SelectedProfile == nil {
		return nil, m408MalformedError{}
	}
	ok, err := c.validate(c.session.AccessToken)
	if err != nil {
		return nil, err
	}
	if ok {
		c.authenticated = true
		return c.session, nil
	}
	acquired, err := c.refresh(c.session.AccessToken, nil)
	if err != nil {
		if rem, ok := err.(*m408RemoteError); ok && rem.IsForbidden() {
			return nil, m408CredentialExpiredError{}
		}
		return nil, err
	}
	if acquired.SelectedProfile == nil || !strings.EqualFold(acquired.SelectedProfile.ID, c.session.SelectedProfile.ID) || acquired.SelectedProfile.Name == "" {
		return nil, m408MalformedError{}
	}
	c.session = acquired
	c.authenticated = true
	return acquired, nil
}

func (c *m408HMCL) invalidate() error {
	payload := map[string]any{"accessToken": c.session.AccessToken, "clientToken": c.clientToken}
	status, body := m408PostJSON(c.ep, "/api/yggdrasil/authserver/invalidate", payload)
	if err := m408OptionalError(status, body); err != nil {
		return err
	}
	c.authenticated = false
	return nil
}

// ---------------------------------------------------------------------------
// Game session consumer (Minecraft client model)
// ---------------------------------------------------------------------------

type m408GameClient struct{ ep m408Endpoint }

func (g m408GameClient) join(accessToken, selectedProfile, serverID string) error {
	payload := map[string]any{"accessToken": accessToken, "selectedProfile": selectedProfile, "serverId": serverID}
	status, body := m408PostJSON(g.ep, "/api/yggdrasil/sessionserver/session/minecraft/join", payload)
	return m408OptionalError(status, body)
}

func (g m408GameClient) hasJoined(username, serverID, ip string) (*m408HasJoinedDoc, bool, error) {
	q := url.Values{}
	q.Set("username", username)
	q.Set("serverId", serverID)
	if ip != "" {
		q.Set("ip", ip)
	}
	status, body := m408Request(g.ep, "GET", "/api/yggdrasil/sessionserver/session/minecraft/hasJoined?"+q.Encode(), nil, nil)
	if status == http.StatusNoContent {
		if len(body) != 0 {
			return nil, false, m408MalformedError{}
		}
		return nil, false, nil
	}
	if status != http.StatusOK {
		return nil, false, m408HTTPError{Status: status}
	}
	var doc m408HasJoinedDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false, err
	}
	return &doc, true, nil
}

// ---------------------------------------------------------------------------
// Metadata consumer (discovery / public key / skin domain whitelist)
// ---------------------------------------------------------------------------

type m408Meta struct {
	ServerName            string            `json:"serverName"`
	ImplementationName    string            `json:"implementationName"`
	ImplementationVersion string            `json:"implementationVersion"`
	Links                 map[string]string `json:"links"`
	NonEmailLogin         bool              `json:"feature.non_email_login"`
}

type m408Metadata struct {
	Meta               m408Meta `json:"meta"`
	SkinDomains        []string `json:"skinDomains"`
	SignaturePublickey string   `json:"signaturePublickey"`
}

func m408DiscoverAPI(ep m408Endpoint, initial string, followALI bool) (string, *m408Metadata, error) {
	cur := initial
	// Pinned injector fetchAPIMetadata follows ALI once, including relative URLs.
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest("GET", cur, nil)
		if err != nil {
			return "", nil, err
		}
		resp, err := ep.Client.Do(req)
		if err != nil {
			return "", nil, err
		}
		body, readErr := io.ReadAll(resp.Body)
		ali := resp.Header.Get("X-Authlib-Injector-API-Location")
		resp.Body.Close()
		if readErr != nil {
			return "", nil, readErr
		}
		if resp.StatusCode != http.StatusOK {
			return "", nil, m408OptionalError(resp.StatusCode, body)
		}
		if attempt == 0 && followALI && ali != "" {
			base, _ := url.Parse(cur)
			reference, err := url.Parse(ali)
			if err != nil {
				return "", nil, err
			}
			target := base.ResolveReference(reference).String()
			if strings.TrimRight(target, "/") != strings.TrimRight(cur, "/") {
				cur = target
				continue
			}
		}
		var meta m408Metadata
		if err := json.Unmarshal(body, &meta); err != nil {
			return "", nil, m408MalformedError{}
		}
		if meta.SignaturePublickey == "" {
			return "", nil, m408MalformedError{}
		}
		return cur, &meta, nil
	}
	return "", nil, fmt.Errorf("ali redirect limit")
}

func (m *m408Metadata) PublicKey() (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(m.SignaturePublickey))
	if block == nil {
		return nil, fmt.Errorf("metadata pem decode failed")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("metadata key is not RSA")
	}
	return pub, nil
}

func (m *m408Metadata) AllowsDomain(host string) bool {
	for _, d := range m.SkinDomains {
		if strings.EqualFold(d, host) {
			return true
		}
	}
	return false
}

// m408VerifySignedProperties verifies every RSA-SHA1 property signature
// against the metadata public key (independent of Go internals).
func m408VerifySignedProperties(pub *rsa.PublicKey, props []m408Property) error {
	for _, p := range props {
		if p.Signature == "" {
			if p.Name == "textures" {
				return fmt.Errorf("textures signature missing")
			}
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(p.Signature)
		if err != nil {
			return fmt.Errorf("property %s signature decode: %w", p.Name, err)
		}
		sum := sha1.Sum([]byte(p.Value))
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, sum[:], sig); err != nil {
			return fmt.Errorf("property %s signature verify: %w", p.Name, err)
		}
	}
	return nil
}

type m408TextureEntry struct {
	URL      string `json:"url"`
	Metadata *struct {
		Model string `json:"model"`
	} `json:"metadata,omitempty"`
}

type m408TexturePayload struct {
	Timestamp         int64                       `json:"timestamp"`
	ProfileID         string                      `json:"profileId"`
	ProfileName       string                      `json:"profileName"`
	IsPublic          bool                        `json:"isPublic"`
	SignatureRequired bool                        `json:"signatureRequired,omitempty"`
	Textures          map[string]m408TextureEntry `json:"textures"`
}

func m408DecodeTextures(props []m408Property) (*m408TexturePayload, error) {
	for _, p := range props {
		if p.Name != "textures" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(p.Value)
		if err != nil {
			return nil, err
		}
		var tp m408TexturePayload
		if err := json.Unmarshal(raw, &tp); err != nil {
			return nil, err
		}
		return &tp, nil
	}
	return nil, fmt.Errorf("no textures property")
}

func m408Download(ep m408Endpoint, rawURL string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := ep.Client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return data, resp.StatusCode, err
}

// ---------------------------------------------------------------------------
// Texture upload consumer (multipart, Bearer)
// ---------------------------------------------------------------------------

func m408UploadTexture(t *testing.T, ep m408Endpoint, accessToken, uuid, slot, model, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("model", model); err != nil {
		t.Fatal(err)
	}
	part, err := mw.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	status, body := m408Request(ep, "PUT", "/api/yggdrasil/api/user/profile/"+uuid+"/"+slot,
		map[string]string{"Content-Type": mw.FormDataContentType(), "Authorization": "Bearer " + accessToken}, &buf)
	if status != http.StatusNoContent {
		var eb m408ErrBody
		_ = json.Unmarshal(body, &eb)
		t.Fatalf("upload slot=%s status=%d error=%s", slot, status, eb.Error)
	}
}

func m408StageTexture(t *testing.T, name string) (string, string) {
	t.Helper()
	src := filepath.Join("testdata", "m4-08", name)
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return dst, hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Identity/crypto helpers (RFC 4122 and standard crypto only)
// ---------------------------------------------------------------------------

func m408UUIDv5Hex(name string) string {
	ns := []byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	h := sha1.New()
	h.Write(ns)
	h.Write([]byte(name))
	sum := h.Sum(nil)
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80
	return hex.EncodeToString(sum[:16])
}

func m408OfflineUUID(name string) string {
	h := md5.Sum([]byte("OfflinePlayer:" + name))
	sum := h[:]
	sum[6] = (sum[6] & 0x0f) | 0x30
	sum[8] = (sum[8] & 0x3f) | 0x80
	return m408DashedFromBytes(sum[:16])
}

func m408DashedFromBytes(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return hex.EncodeToString(b[0:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" + hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:16])
}

// m408LegacyJWT builds the legacy Blessing Skin HS256 JWT shape: issuer
// "Yggdrasil-Auth", subject = UUIDv5(DNS, email) hex, yggt claim. The
// signing secret represents legacy jwt.secret. The synthetic fixture uses
// the new AppKey too, so rejection is not proved merely by changing HMAC keys.
func m408LegacyJWT(subject, yggt string, issuedAt, expiresAt int64, secret []byte) string {
	type legacyClaims struct {
		Issuer    string `json:"iss"`
		Subject   string `json:"sub"`
		TokenID   string `json:"yggt"`
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
	}
	header := `{"alg":"HS256","typ":"JWT"}`
	payload, err := json.Marshal(legacyClaims{Issuer: "Yggdrasil-Auth", Subject: subject, TokenID: yggt, IssuedAt: issuedAt, ExpiresAt: expiresAt})
	if err != nil {
		return ""
	}
	input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func m408VerifyLegacyJWT(token string, secret []byte, wantSubject string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	input := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var c struct {
		Issuer  string `json:"iss"`
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return false
	}
	return c.Issuer == "Yggdrasil-Auth" && c.Subject == wantSubject
}

// m408TamperJWT flips one bit of the signature deterministically so the
// tampered token is guaranteed to differ from the original in every run.
func m408TamperJWT(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return token
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) == 0 {
		return token
	}
	sig[0] ^= 0x01
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	return strings.Join(parts, ".")
}

// m408ServerID implements Velocity EncryptionUtils.generateServerId:
// new BigInteger(SHA-1(sharedSecret || serverPublicKeyDER)).toString(16).
func m408ServerID(sharedSecret, serverPubDER []byte) string {
	h := sha1.New()
	h.Write(sharedSecret)
	h.Write(serverPubDER)
	digest := h.Sum(nil)
	signed := new(big.Int).SetBytes(digest)
	if digest[0]&0x80 != 0 {
		signed.Sub(signed, new(big.Int).Lsh(big.NewInt(1), 160))
	}
	return signed.Text(16)
}

func m408BytesRange(lo, hi int) []byte {
	b := make([]byte, 0, int(hi)-int(lo))
	for i := lo; i < hi; i++ {
		b = append(b, byte(i))
	}
	return b
}

// ---------------------------------------------------------------------------
// Modern forwarding codec (Velocity PlayerDataForwarding / ProtocolUtils)
// ---------------------------------------------------------------------------

type m408BufWriter struct{ buf []byte }

func (w *m408BufWriter) varInt(v int) {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			w.buf = append(w.buf, b|0x80)
		} else {
			w.buf = append(w.buf, b)
			return
		}
	}
}

func (w *m408BufWriter) strUTF8(s string) {
	w.varInt(len(s))
	w.buf = append(w.buf, s...)
}

func (w *m408BufWriter) bytes(b []byte) { w.buf = append(w.buf, b...) }

func (w *m408BufWriter) uuid(u string) {
	raw, err := hex.DecodeString(strings.ReplaceAll(u, "-", ""))
	if err == nil && len(raw) == 16 {
		w.bytes(raw)
	}
}

func (w *m408BufWriter) bool(v bool) {
	if v {
		w.buf = append(w.buf, 1)
	} else {
		w.buf = append(w.buf, 0)
	}
}

type m408BufReader struct {
	buf []byte
	off int
}

func (r *m408BufReader) remaining() int { return len(r.buf) - r.off }

func (r *m408BufReader) varInt() (int, error) {
	num := 0
	for i := 0; i < 5; i++ {
		if r.remaining() <= 0 {
			return 0, io.ErrUnexpectedEOF
		}
		b := r.buf[r.off]
		r.off++
		num |= int(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			return num, nil
		}
	}
	return 0, fmt.Errorf("varint too long")
}

func (r *m408BufReader) strUTF8() (string, error) {
	n, err := r.varInt()
	if err != nil {
		return "", err
	}
	if n < 0 || r.remaining() < n {
		return "", io.ErrUnexpectedEOF
	}
	s := string(r.buf[r.off : r.off+n])
	r.off += n
	return s, nil
}

func (r *m408BufReader) bytes(n int) ([]byte, error) {
	if n < 0 || r.remaining() < n {
		return nil, io.ErrUnexpectedEOF
	}
	out := r.buf[r.off : r.off+n]
	r.off += n
	return out, nil
}

func (r *m408BufReader) bool() (bool, error) {
	b, err := r.bytes(1)
	if err != nil {
		return false, err
	}
	return b[0] == 1, nil
}

func (r *m408BufReader) uuid() (string, error) {
	raw, err := r.bytes(16)
	if err != nil {
		return "", err
	}
	return m408DashedFromBytes(raw), nil
}

type m408ForwardingProperty struct {
	Name         string
	Value        string
	HasSignature bool
	Signature    string
}

type m408Forwarded struct {
	Version    int
	Address    string
	UUID       string
	Name       string
	Properties []m408ForwardingProperty
}

func m408EncodeModernForwarding(secret []byte, version int, address, uuid, name string, props []m408ForwardingProperty) []byte {
	w := &m408BufWriter{}
	w.varInt(version)
	w.strUTF8(address)
	w.uuid(uuid)
	w.strUTF8(name)
	w.varInt(len(props))
	for _, p := range props {
		w.strUTF8(p.Name)
		w.strUTF8(p.Value)
		if p.HasSignature && p.Signature != "" {
			w.bool(true)
			w.strUTF8(p.Signature)
		} else {
			w.bool(false)
		}
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(w.buf)
	out := make([]byte, 0, 32+len(w.buf))
	out = append(out, mac.Sum(nil)...)
	out = append(out, w.buf...)
	return out
}

func m408DecodeModernForwarding(secret []byte, msg []byte) (*m408Forwarded, error) {
	if len(msg) < 32 {
		return nil, io.ErrUnexpectedEOF
	}
	mac, payload := msg[:32], msg[32:]
	expect := hmac.New(sha256.New, secret)
	expect.Write(payload)
	if !hmac.Equal(mac, expect.Sum(nil)) {
		return nil, fmt.Errorf("bad hmac")
	}
	r := &m408BufReader{buf: payload}
	version, err := r.varInt()
	if err != nil {
		return nil, err
	}
	address, err := r.strUTF8()
	if err != nil {
		return nil, err
	}
	u, err := r.uuid()
	if err != nil {
		return nil, err
	}
	name, err := r.strUTF8()
	if err != nil {
		return nil, err
	}
	count, err := r.varInt()
	if err != nil {
		return nil, err
	}
	if count < 0 || count > 1024 {
		return nil, fmt.Errorf("property count out of range")
	}
	props := make([]m408ForwardingProperty, 0, count)
	for i := 0; i < count; i++ {
		pn, err := r.strUTF8()
		if err != nil {
			return nil, err
		}
		pv, err := r.strUTF8()
		if err != nil {
			return nil, err
		}
		has, err := r.bool()
		if err != nil {
			return nil, err
		}
		var ps string
		if has {
			ps, err = r.strUTF8()
			if err != nil {
				return nil, err
			}
		}
		props = append(props, m408ForwardingProperty{Name: pn, Value: pv, HasSignature: has, Signature: ps})
	}
	if r.remaining() != 0 {
		return nil, fmt.Errorf("trailing bytes")
	}
	return &m408Forwarded{Version: version, Address: address, UUID: u, Name: name, Properties: props}, nil
}

// ---------------------------------------------------------------------------
// DB arrangement helpers (test-only control)
// ---------------------------------------------------------------------------

func m408SetScore(t *testing.T, f *m408Fixture, uid, score int64) {
	t.Helper()
	if _, err := f.Identity.Store.DB.Exec("UPDATE "+f.Identity.Store.Table("users")+" SET score=? WHERE uid=?", score, uid); err != nil {
		t.Fatal(err)
	}
}

func m408AddPlayer(t *testing.T, f *m408Fixture, uid int64, name, uuidHex string) {
	t.Helper()
	uuidHex = strings.ReplaceAll(uuidHex, "-", "")
	if _, err := f.Identity.Store.DB.Exec("INSERT INTO "+f.Identity.Store.Table("players")+" (uid,name,tid_skin,tid_cape,last_modified) VALUES (?,?,0,0,'2026-01-01 00:00:00')", uid, name); err != nil {
		t.Fatal(err)
	}
	var pid int64
	if err := f.Identity.Store.DB.QueryRow("SELECT pid FROM "+f.Identity.Store.Table("players")+" WHERE name=? ORDER BY pid LIMIT 1", name).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Identity.Store.DB.Exec("INSERT INTO "+f.Identity.Store.Table("uuid")+" (name,uuid) VALUES (?,?)", name, uuidHex); err != nil {
		t.Fatal(err)
	}
	var rowID int64
	if err := f.Identity.Store.DB.QueryRow("SELECT id FROM "+f.Identity.Store.Table("uuid")+" WHERE name=? ORDER BY id LIMIT 1", name).Scan(&rowID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Identity.Store.DB.Exec("INSERT INTO "+f.Identity.Store.Table("go_uuid_bindings")+" (pid,uuid_row_id,uuid,version) VALUES (?,?,?,1)", pid, rowID, uuidHex); err != nil {
		t.Fatal(err)
	}
}

func m408SetModule(t *testing.T, f *m408Fixture, enabled bool) {
	t.Helper()
	value := `[]`
	if enabled {
		value = `[{"name":"yggdrasil-api","version":"5.2.1"}]`
	}
	if _, err := f.Identity.Store.DB.Exec("UPDATE "+f.Identity.Store.Table("options")+" SET option_value=? WHERE option_name='plugins_enabled'", value); err != nil {
		t.Fatal(err)
	}
}

// m408EachBasePath runs a scenario at the root deployment and at a /skin
// subpath deployment, matching the fixture's supported deployments.
func m408EachBasePath(t *testing.T, fn func(t *testing.T, f *m408Fixture)) {
	for _, bp := range []string{"", "/skin"} {
		bp := bp
		name := "root"
		if bp != "" {
			name = "subpath"
		}
		t.Run(name, func(t *testing.T) {
			f := m408NewFixture(t, bp, nil)
			fn(t, f)
		})
	}
}

func m408RemoteName(t *testing.T, err error) string {
	t.Helper()
	if rem, ok := err.(*m408RemoteError); ok {
		return rem.Name
	}
	return ""
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestM408VectorConstants reproduces every frozen vector with the local
// consumer implementations. This runs without any database.
func TestM408VectorConstants(t *testing.T) {
	if got := m408UUIDv5Hex(m408GameEmail); got != m408UUIDv5Email {
		t.Fatalf("uuidv5 email = %s want %s", got, m408UUIDv5Email)
	}
	if got := m408OfflineUUID("PlayerOne"); got != m408OfflinePlayerOne {
		t.Fatalf("offline uuid = %s want %s", got, m408OfflinePlayerOne)
	}
	if got := m408ServerID([]byte("m408-negative-0"), m408BytesRange(0x80, 0x100)); got != m408ServerIDNegative {
		t.Fatal("negative serverId vector mismatch")
	}
	s1 := m408BytesRange(0x00, 0x10)
	d1 := m408BytesRange(0x21, 0x51)
	s2 := []byte("m408-shared-secret-1234567890")
	d2 := m408BytesRange(0x80, 0x100)
	if got := m408ServerID(s1, d1); got != m408ServerIDVecA {
		t.Fatalf("serverId vector A = %s want %s", got, m408ServerIDVecA)
	}
	if got := m408ServerID(s2, d2); got != m408ServerIDVecB {
		t.Fatalf("serverId vector B = %s want %s", got, m408ServerIDVecB)
	}
	secret := []byte(m408ForwardingSec)
	msg1, _ := hex.DecodeString(m408ForwardingV1Msg)
	msg4, _ := hex.DecodeString(m408ForwardingV4Msg)
	enc1 := m408EncodeModernForwarding(secret, 1, m408ForwardingAddr, m408ForwardingUUID, m408ForwardingName, m408VecProps)
	if !bytes.Equal(enc1, msg1) {
		t.Fatalf("forwarding v1 encode mismatch")
	}
	enc4 := m408EncodeModernForwarding(secret, 4, m408ForwardingAddr, m408ForwardingUUID, m408ForwardingName, m408VecProps)
	if !bytes.Equal(enc4, msg4) {
		t.Fatalf("forwarding v4 encode mismatch")
	}
	for _, msg := range [][]byte{msg1, msg4} {
		dec, err := m408DecodeModernForwarding(secret, msg)
		if err != nil {
			t.Fatalf("decode vector: %v", err)
		}
		if dec.UUID != m408ForwardingUUID || dec.Name != m408ForwardingName || dec.Address != m408ForwardingAddr {
			t.Fatalf("decoded vector identity = %+v", dec)
		}
		if len(dec.Properties) != 1 || dec.Properties[0].Name != "textures" || dec.Properties[0].Value != "VEFYVVJFRA==" || !dec.Properties[0].HasSignature || dec.Properties[0].Signature != "U0lH" {
			t.Fatalf("decoded vector property = %+v", dec.Properties)
		}
	}
	if dec, err := m408DecodeModernForwarding([]byte("wrong-secret"), msg1); err == nil || dec != nil {
		t.Fatalf("wrong secret accepted")
	}
}

// TestM408HMCLSessionLifecycle exercises the HMCL state machine against the
// real App: authenticate, validate, refresh rotation, credential expiry and
// password reauth, plus the exact client-token mismatch protocol error.
func TestM408HMCLSessionLifecycle(t *testing.T) {
	m408EachBasePath(t, func(t *testing.T, f *m408Fixture) {
		c := m408NewHMCL(f.Endpoint)
		sess, err := c.withPassword(m408GameEmail, m408GamePass, nil)
		if err != nil {
			t.Fatalf("withPassword: %v", err)
		}
		if sess.SelectedProfile == nil || sess.SelectedProfile.Name != "PlayerOne" || sess.SelectedProfile.ID != m408UUID {
			t.Fatalf("selected profile = %+v", sess.SelectedProfile)
		}
		if sess.UserID != m408UUIDv5Email {
			t.Fatalf("requestUser id = %s want %s", sess.UserID, m408UUIDv5Email)
		}
		// Stored-session login without network refresh.
		sess2, err := c.login()
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		if sess2.AccessToken != sess.AccessToken {
			t.Fatalf("login rotated token without need")
		}
		// Wrong password: frozen error.
		_, err = c.withPassword(m408GameEmail, "wrong-password", nil)
		if rem := m408RemoteName(t, err); rem != "ForbiddenOperationException" {
			t.Fatalf("wrong password error name = %s", rem)
		}
		// Unknown user: frozen auth.not-existed message.
		_, err = c.withPassword("nobody@example.invalid", m408GamePass, nil)
		if rem, ok := err.(*m408RemoteError); !ok || rem.Name != "ForbiddenOperationException" || rem.Message != "User nobody@example.invalid is not found." {
			t.Fatalf("unknown user error = %v", err)
		}
		// Client-token mismatch protocol error (validate and refresh).
		status, body := m408PostJSON(f.Endpoint, "/api/yggdrasil/authserver/validate", map[string]any{"accessToken": sess.AccessToken, "clientToken": "wrong-client"})
		if err := m408OptionalError(status, body); err == nil {
			t.Fatalf("validate wrong clientToken accepted")
		} else if rem, ok := err.(*m408RemoteError); !ok || rem.Name != "ForbiddenOperationException" || rem.Message != "ClientToken isn't matched with AccessToken. Please re-login." {
			t.Fatalf("validate wrong clientToken error = %v", err)
		}
		status, body = m408PostJSON(f.Endpoint, "/api/yggdrasil/authserver/refresh", map[string]any{"accessToken": sess.AccessToken, "clientToken": "wrong-client"})
		if err := m408OptionalError(status, body); err == nil {
			t.Fatalf("refresh wrong clientToken accepted")
		} else if rem, ok := err.(*m408RemoteError); !ok || rem.Name != "ForbiddenOperationException" || rem.Message != "ClientToken isn't matched with AccessToken. Please re-login." {
			t.Fatalf("refresh wrong clientToken error = %v", err)
		}
		// Refresh rotates: old token dies, new token validates.
		rotated, err := c.refresh(sess.AccessToken, nil)
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		if rotated.AccessToken == sess.AccessToken || rotated.ClientToken != c.clientToken {
			t.Fatalf("rotation did not rotate token")
		}
		if ok, err := c.validate(sess.AccessToken); err != nil || ok {
			t.Fatalf("old token valid after rotation ok=%v err=%v", ok, err)
		}
		if ok, err := c.validate(rotated.AccessToken); err != nil || !ok {
			t.Fatalf("new token invalid ok=%v err=%v", ok, err)
		}
		// Server-side invalidate -> login() degrades to refresh, which
		// fails with CredentialExpired because the token is gone.
		c.session = rotated
		c.authenticated = true
		if err := c.invalidate(); err != nil {
			t.Fatalf("invalidate: %v", err)
		}
		c.authenticated = false
		_, err = c.login()
		if _, ok := err.(m408CredentialExpiredError); !ok {
			t.Fatalf("login after invalidate error = %v", err)
		}
		// Password reauth issues a fresh client token and session.
		reauth, err := c.withPassword(m408GameEmail, m408GamePass, nil)
		if err != nil {
			t.Fatalf("reauth: %v", err)
		}
		if reauth.ClientToken == rotated.ClientToken || reauth.AccessToken == rotated.AccessToken {
			t.Fatalf("reauth did not mint a fresh credential")
		}
		ok, err := c.validate(reauth.AccessToken)
		if err != nil || !ok {
			t.Fatalf("reauth token invalid ok=%v err=%v", ok, err)
		}
	})
}

// TestM408ProfilesZeroMultipleSelection covers the zero-profile, multi-profile
// and current-selection states of the launcher model.
func TestM408ProfilesZeroMultipleSelection(t *testing.T) {
	m408EachBasePath(t, func(t *testing.T, f *m408Fixture) {
		c := m408NewHMCL(f.Endpoint)
		// Zero profiles: admin has no players.
		if _, err := c.withPassword(m408AdminEmail, m408GamePass, nil); err == nil {
			t.Fatalf("admin withPassword succeeded")
		} else if _, ok := err.(m408CharacterDeletedError); !ok {
			t.Fatalf("admin withPassword error = %v", err)
		}
		status, body := m408PostJSON(f.Endpoint, "/api/yggdrasil/authserver/authenticate", map[string]any{"username": m408AdminEmail, "password": m408GamePass, "clientToken": "ct-admin"})
		var raw map[string]any
		_ = json.Unmarshal(body, &raw)
		arr, ok := raw["availableProfiles"].([]any)
		if status != 200 || !ok || len(arr) != 0 {
			t.Fatalf("admin authenticate status=%d profiles=%v", status, arr)
		}
		if _, present := raw["selectedProfile"]; present {
			t.Fatalf("admin authenticate has selectedProfile")
		}
		// Multiple profiles: two owned players, no automatic selection.
		m408AddPlayer(t, f, 1, "TwoPlayer", m408AlexDashed)
		authSess, err := c.authenticate(m408GameEmail, m408GamePass)
		if err != nil {
			t.Fatalf("multi authenticate: %v", err)
		}
		if len(authSess.AvailableProfiles) != 2 || authSess.SelectedProfile != nil {
			t.Fatalf("multi authenticate profiles=%d selected=%v", len(authSess.AvailableProfiles), authSess.SelectedProfile)
		}
		var first, second *m408Profile
		for i := range authSess.AvailableProfiles {
			if authSess.AvailableProfiles[i].ID == m408UUID {
				first = &authSess.AvailableProfiles[i]
			}
			if authSess.AvailableProfiles[i].ID == m408AlexHex {
				second = &authSess.AvailableProfiles[i]
			}
		}
		if first == nil || second == nil {
			t.Fatalf("missing owned profiles")
		}
		// Current selection: bind via refresh like the HMCL constructor.
		selFirst, err := c.refresh(authSess.AccessToken, first)
		if err != nil {
			t.Fatalf("refresh select first: %v", err)
		}
		g := m408GameClient{ep: f.Endpoint}
		if err := g.join(selFirst.AccessToken, m408UUID, "srv-1"); err != nil {
			t.Fatalf("join selected first: %v", err)
		}
		// Joining the non-selected profile is player.not-matched.
		err = g.join(selFirst.AccessToken, m408AlexHex, "srv-2")
		if rem := m408RemoteName(t, err); rem != "ForbiddenOperationException" {
			t.Fatalf("join non-selected error = %v", err)
		}
		// Selecting a foreign/wrong id for an owned name is the 400
		// player.not-matched form.
		_, err = c.refresh(selFirst.AccessToken, &m408Profile{ID: m408AlexHex, Name: "PlayerOne"})
		if rem := m408RemoteName(t, err); rem != "IllegalArgumentException" {
			t.Fatalf("refresh wrong-id error = %v", err)
		}
		// Refreshing with a non-existent player name is player.not-existed.
		_, err = c.refresh(selFirst.AccessToken, &m408Profile{ID: m408AlexHex, Name: "Nobody"})
		if rem := m408RemoteName(t, err); rem != "IllegalArgumentException" {
			t.Fatalf("refresh unknown name error = %v", err)
		}
		// Switch selection through a fresh authenticate (the frozen service
		// refuses to re-bind a token that already has a selection).
		auth2, err := c.authenticate(m408GameEmail, m408GamePass)
		if err != nil {
			t.Fatalf("second authenticate: %v", err)
		}
		selSecond, err := c.refresh(auth2.AccessToken, second)
		if err != nil {
			t.Fatalf("refresh select second: %v", err)
		}
		if err := g.join(selSecond.AccessToken, m408AlexHex, "srv-3"); err != nil {
			t.Fatalf("join selected second: %v", err)
		}
		m408ExpectRemote(t, g.join(selSecond.AccessToken, m408UUID, "srv-4"), "ForbiddenOperationException", "The player requested doesn't match with that token.")
	})
}

// TestM408LegacyJWTRejected proves a legacy-shape HS256 JWT (subject UUIDv5
// of the real email) is independently verifiable offline and then rejected
// by the Go App at every credential entry point.
func TestM408LegacyJWTRejected(t *testing.T) {
	f := m408NewFixture(t, "", nil)
	secret := []byte(m408AppKey)
	subject := m408UUIDv5Hex(m408GameEmail)
	if subject != m408UUIDv5Email {
		t.Fatalf("uuidv5 subject mismatch")
	}
	now := f.Clock.Load()
	legacy := m408LegacyJWT(subject, m408RandomCompactUUID(), now, now+3600, secret)
	if !m408VerifyLegacyJWT(legacy, secret, subject) {
		t.Fatalf("legacy JWT failed offline verification")
	}
	tampered := m408TamperJWT(legacy)
	if m408VerifyLegacyJWT(tampered, secret, subject) {
		t.Fatalf("tampered legacy JWT verified")
	}
	for _, tc := range []struct {
		name string
		path string
		body map[string]any
		want string
	}{
		{"validate", "/api/yggdrasil/authserver/validate", map[string]any{"accessToken": legacy, "clientToken": "ct"}, "Invalid AccessToken. Please re-login."},
		{"refresh", "/api/yggdrasil/authserver/refresh", map[string]any{"accessToken": legacy, "clientToken": "ct"}, "Invalid AccessToken. Please re-login."},
		{"join", "/api/yggdrasil/sessionserver/session/minecraft/join", map[string]any{"accessToken": legacy, "selectedProfile": m408PlayerDashed, "serverId": "srv"}, "No valid credential information."},
	} {
		status, body := m408PostJSON(f.Endpoint, tc.path, tc.body)
		err := m408OptionalError(status, body)
		rem, ok := err.(*m408RemoteError)
		if !ok || rem.Name != "ForbiddenOperationException" || rem.Message != tc.want {
			t.Fatalf("%s status=%d error=%v", tc.name, status, err)
		}
	}
	// Tampered signature is also rejected by the server.
	status, body := m408PostJSON(f.Endpoint, "/api/yggdrasil/authserver/validate", map[string]any{"accessToken": tampered, "clientToken": "ct"})
	m408ExpectRemote(t, m408OptionalError(status, body), "ForbiddenOperationException", "Invalid AccessToken. Please re-login.")
}

// TestM408TexturesAlexSlimProfile covers the slim Alex skin metadata and the
// signed profile endpoint at a /skin subpath deployment.
func TestM408TexturesAlexSlimProfile(t *testing.T) {
	f := m408NewFixture(t, "/skin", nil)
	m408SetScore(t, f, 1, 100000)
	m408AddPlayer(t, f, 1, "AlexPlayer", m408AlexDashed)
	alexPath, alexHash := m408StageTexture(t, "alex-64x64.png")
	c := m408NewHMCL(f.Endpoint)
	authSess, err := c.authenticate(m408GameEmail, m408GamePass)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	var alex *m408Profile
	for i := range authSess.AvailableProfiles {
		if authSess.AvailableProfiles[i].ID == m408AlexHex {
			alex = &authSess.AvailableProfiles[i]
		}
	}
	if alex == nil {
		t.Fatalf("alex profile not found")
	}
	sess, err := c.refresh(authSess.AccessToken, alex)
	if err != nil {
		t.Fatalf("select alex: %v", err)
	}
	m408UploadTexture(t, f.Endpoint, sess.AccessToken, m408AlexDashed, "skin", "slim", alexPath)
	_, meta, err := m408DiscoverAPI(f.Endpoint, f.Endpoint.BaseURL+"/api/yggdrasil", false)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	pub, err := meta.PublicKey()
	if err != nil {
		t.Fatalf("metadata key: %v", err)
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serverPubDER, err := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	serverID := m408ServerID([]byte("alex-shared-secret-0000"), serverPubDER)
	g := m408GameClient{ep: f.Endpoint}
	if err := g.join(sess.AccessToken, m408AlexHex, serverID); err != nil {
		t.Fatalf("join: %v", err)
	}
	doc, found, err := g.hasJoined("AlexPlayer", serverID, "")
	if err != nil || !found || doc == nil {
		t.Fatalf("hasJoined found=%v err=%v", found, err)
	}
	if doc.ID != m408AlexHex {
		t.Fatalf("hasJoined doc id = %s", doc.ID)
	}
	if err := m408VerifySignedProperties(pub, doc.Properties); err != nil {
		t.Fatalf("RSA-SHA1 verify: %v", err)
	}
	tp, err := m408DecodeTextures(doc.Properties)
	if err != nil {
		t.Fatalf("textures decode: %v", err)
	}
	skin, ok := tp.Textures["SKIN"]
	if !ok || skin.Metadata == nil || skin.Metadata.Model != "slim" {
		t.Fatalf("alex skin entry = %+v", skin)
	}
	data, status, err := m408Download(f.Endpoint, skin.URL)
	if err != nil || status != 200 {
		t.Fatalf("alex download status=%d err=%v", status, err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != alexHash {
		t.Fatalf("alex texture hash mismatch")
	}
	// Signed profile endpoint exposes the same signed textures property.
	status, body := m408Request(f.Endpoint, "GET", "/api/yggdrasil/sessionserver/session/minecraft/profile/"+m408AlexDashed+"?unsigned=false", nil, nil)
	if status != 200 {
		t.Fatalf("profile status=%d", status)
	}
	var prof m408HasJoinedDoc
	if err := json.Unmarshal(body, &prof); err != nil {
		t.Fatalf("profile decode: %v", err)
	}
	if err := m408VerifySignedProperties(pub, prof.Properties); err != nil {
		t.Fatalf("profile signature verify: %v", err)
	}
	tp2, err := m408DecodeTextures(prof.Properties)
	if err != nil {
		t.Fatalf("profile textures decode: %v", err)
	}
	if tp2.Textures["SKIN"].URL != skin.URL {
		t.Fatalf("profile and hasJoined skin URLs differ")
	}
}

// TestM408NegativesTokenLifecycle covers clientToken/profile mismatches,
// rotation, invalidate, signout and both expiry windows.
func TestM408NegativesTokenLifecycle(t *testing.T) {
	f := m408NewFixture(t, "", nil)
	c := m408NewHMCL(f.Endpoint)
	sess, err := c.withPassword(m408GameEmail, m408GamePass, nil)
	if err != nil {
		t.Fatalf("withPassword: %v", err)
	}
	g := m408GameClient{ep: f.Endpoint}
	// Rotation: the old token must be rejected everywhere.
	rotated, err := c.refresh(sess.AccessToken, nil)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	status, body := m408PostJSON(f.Endpoint, "/api/yggdrasil/authserver/validate", map[string]any{"accessToken": sess.AccessToken, "clientToken": rotated.ClientToken})
	m408ExpectRemote(t, m408OptionalError(status, body), "ForbiddenOperationException", "Invalid AccessToken. Please re-login.")
	// Signout revokes every token including join tickets.
	sess2, err := c.withPassword(m408GameEmail, m408GamePass, nil)
	if err != nil {
		t.Fatalf("second withPassword: %v", err)
	}
	if err := g.join(sess2.AccessToken, m408UUID, "srv-signout"); err != nil {
		t.Fatalf("join before signout: %v", err)
	}
	status, body = m408PostJSON(f.Endpoint, "/api/yggdrasil/authserver/signout", map[string]any{"username": m408GameEmail, "password": m408GamePass})
	if status != http.StatusNoContent {
		t.Fatalf("signout status=%d", status)
	}
	status, body = m408PostJSON(f.Endpoint, "/api/yggdrasil/authserver/validate", map[string]any{"accessToken": sess2.AccessToken, "clientToken": sess2.ClientToken})
	m408ExpectRemote(t, m408OptionalError(status, body), "ForbiddenOperationException", "Invalid AccessToken. Please re-login.")
	m408ExpectRemote(t, g.join(sess2.AccessToken, m408UUID, "srv-signout2"), "ForbiddenOperationException", "No valid credential information.")
	if _, found, err := g.hasJoined("PlayerOne", "srv-signout", ""); err != nil || found {
		t.Fatalf("hasJoined after signout found=%v err=%v", found, err)
	}
	// Expiry windows: the frozen join lifetime is 120s; fixture access and
	// refresh lifetimes are 3600s/86400s. The injected clock crosses each.
	base := f.Clock.Load()
	sessT, err := c.withPassword(m408GameEmail, m408GamePass, nil)
	if err != nil {
		t.Fatalf("token at base: %v", err)
	}
	if err := g.join(sessT.AccessToken, m408UUID, "srv-exp"); err != nil {
		t.Fatalf("join at base: %v", err)
	}
	f.Clock.Add(121)
	if _, found, err := g.hasJoined("PlayerOne", "srv-exp", ""); err != nil || found {
		t.Fatalf("hasJoined after ticket expiry found=%v err=%v", found, err)
	}
	f.Clock.Store(base + 3601)
	status, body = m408PostJSON(f.Endpoint, "/api/yggdrasil/authserver/validate", map[string]any{"accessToken": sessT.AccessToken, "clientToken": sessT.ClientToken})
	m408ExpectRemote(t, m408OptionalError(status, body), "ForbiddenOperationException", "Invalid AccessToken. Please re-login.")
	m408ExpectRemote(t, g.join(sessT.AccessToken, m408UUID, "srv-exp2"), "ForbiddenOperationException", "No valid credential information.")
	// Refresh works inside the refresh window even after access expiry.
	c.session = sessT
	c.authenticated = false
	refreshed, err := c.login()
	if err != nil {
		t.Fatalf("refresh inside refresh window: %v", err)
	}
	if ok, err := c.validate(refreshed.AccessToken); err != nil || !ok {
		t.Fatalf("refreshed token invalid ok=%v err=%v", ok, err)
	}
	f.Clock.Store(base + 3601 + 86401)
	status, body = m408PostJSON(f.Endpoint, "/api/yggdrasil/authserver/refresh", map[string]any{"accessToken": refreshed.AccessToken, "clientToken": refreshed.ClientToken})
	m408ExpectRemote(t, m408OptionalError(status, body), "ForbiddenOperationException", "Invalid AccessToken. Please re-login.")
}

// TestM408NegativesBanAndOwnership covers ban, ownership transfer and player
// deletion with the frozen protocol answers.
func TestM408NegativesBanAndOwnership(t *testing.T) {
	f := m408NewFixture(t, "", nil)
	c := m408NewHMCL(f.Endpoint)
	sess, err := c.withPassword(m408GameEmail, m408GamePass, nil)
	if err != nil {
		t.Fatalf("withPassword: %v", err)
	}
	g := m408GameClient{ep: f.Endpoint}
	if err := g.join(sess.AccessToken, m408UUID, "srv-ban"); err != nil {
		t.Fatalf("join before ban: %v", err)
	}
	if _, err := f.Identity.Store.DB.Exec("UPDATE " + f.Identity.Store.Table("users") + " SET permission=-2 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	_, err = c.withPassword(m408GameEmail, m408GamePass, nil)
	m408ExpectRemote(t, err, "ForbiddenOperationException", "You're banned.")
	status, body := m408PostJSON(f.Endpoint, "/api/yggdrasil/authserver/validate", map[string]any{"accessToken": sess.AccessToken, "clientToken": sess.ClientToken})
	if err := m408OptionalError(status, body); err == nil {
		t.Fatalf("banned validate succeeded")
	} else if rem, ok := err.(*m408RemoteError); !ok || rem.Message != "You're banned." {
		t.Fatalf("banned validate error = %v", err)
	}
	m408ExpectRemote(t, g.join(sess.AccessToken, m408UUID, "srv-ban2"), "ForbiddenOperationException", "You're banned.")
	if _, found, err := g.hasJoined("PlayerOne", "srv-ban", ""); err != nil || found {
		t.Fatalf("banned hasJoined found=%v err=%v", found, err)
	}
	status, body = m408PostJSON(f.Endpoint, "/api/yggdrasil/authserver/signout", map[string]any{"username": m408GameEmail, "password": m408GamePass})
	if status != http.StatusNoContent {
		t.Fatalf("banned signout status=%d", status)
	}
	// Unban, then transfer the player to uid 2 (admin).
	if _, err := f.Identity.Store.DB.Exec("UPDATE " + f.Identity.Store.Table("users") + " SET permission=0 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	sess3, err := c.withPassword(m408GameEmail, m408GamePass, nil)
	if err != nil {
		t.Fatalf("reauth after unban: %v", err)
	}
	if err := g.join(sess3.AccessToken, m408UUID, "srv-owner"); err != nil {
		t.Fatalf("join before transfer: %v", err)
	}
	if _, err := f.Identity.Store.DB.Exec("UPDATE " + f.Identity.Store.Table("players") + " SET uid=2 WHERE pid=1"); err != nil {
		t.Fatal(err)
	}
	if err := g.join(sess3.AccessToken, m408UUID, "srv-owner2"); err == nil {
		t.Fatalf("join after transfer succeeded")
	} else if rem, ok := err.(*m408RemoteError); !ok || rem.Message != "No valid credential information." {
		t.Fatalf("join after transfer error = %v", err)
	}
	if _, found, err := g.hasJoined("PlayerOne", "srv-owner", ""); err != nil || found {
		t.Fatalf("hasJoined after transfer found=%v err=%v", found, err)
	}
	// Player deletion: join answers uuid exception, profile/hasJoined 204.
	if _, err := f.Identity.Store.DB.Exec("DELETE FROM " + f.Identity.Store.Table("players") + " WHERE pid=1"); err != nil {
		t.Fatal(err)
	}
	err = g.join(sess3.AccessToken, m408UUID, "srv-del")
	m408ExpectRemote(t, err, "ForbiddenOperationException", "Invalid Profile UUID "+m408UUID+". It doesn't belong to any players.")
	if _, found, err := g.hasJoined("PlayerOne", "srv-owner2", ""); err != nil || found {
		t.Fatalf("hasJoined after delete found=%v err=%v", found, err)
	}
	status, _ = m408Request(f.Endpoint, "GET", "/api/yggdrasil/sessionserver/session/minecraft/profile/"+m408UUID, nil, nil)
	if status != http.StatusNoContent {
		t.Fatalf("profile after delete status=%d", status)
	}
}

// TestM408NegativesHasJoinedMismatches covers bad server ids, IP mismatch and
// repeated hasJoined on the same ticket.
func TestM408NegativesHasJoinedMismatches(t *testing.T) {
	f := m408NewFixture(t, "", nil)
	c := m408NewHMCL(f.Endpoint)
	sess, err := c.withPassword(m408GameEmail, m408GamePass, nil)
	if err != nil {
		t.Fatalf("withPassword: %v", err)
	}
	g := m408GameClient{ep: f.Endpoint}
	if err := g.join(sess.AccessToken, m408UUID, "srv-a"); err != nil {
		t.Fatalf("join: %v", err)
	}
	// Repeated hasJoined on the same ticket both succeed.
	for i := 0; i < 2; i++ {
		doc, found, err := g.hasJoined("PlayerOne", "srv-a", "")
		if err != nil || !found || doc == nil || doc.ID != m408UUID {
			t.Fatalf("repeated hasJoined %d found=%v err=%v", i, found, err)
		}
	}
	// Wrong server id on a live ticket.
	if _, found, err := g.hasJoined("PlayerOne", "srv-b", ""); err != nil || found {
		t.Fatalf("bad serverId found=%v err=%v", found, err)
	}
	// IP mismatch, then the exact stored IP.
	if _, found, err := g.hasJoined("PlayerOne", "srv-a", "127.0.0.2"); err != nil || found {
		t.Fatalf("ip mismatch found=%v err=%v", found, err)
	}
	if doc, found, err := g.hasJoined("PlayerOne", "srv-a", "127.0.0.1"); err != nil || !found || doc == nil {
		t.Fatalf("exact ip found=%v err=%v", found, err)
	}
	// Name mismatch.
	if _, found, err := g.hasJoined("Nobody", "srv-a", ""); err != nil || found {
		t.Fatalf("name mismatch found=%v err=%v", found, err)
	}
}

// TestM408ModuleDisableEnable verifies the module gate at every entry point
// and token persistence across a disable/enable cycle.
func TestM408ModuleDisableEnable(t *testing.T) {
	f := m408NewFixture(t, "", nil)
	c := m408NewHMCL(f.Endpoint)
	sess, err := c.withPassword(m408GameEmail, m408GamePass, nil)
	if err != nil {
		t.Fatalf("withPassword: %v", err)
	}
	g := m408GameClient{ep: f.Endpoint}
	if err := g.join(sess.AccessToken, m408UUID, "srv-enabled"); err != nil {
		t.Fatalf("join enabled: %v", err)
	}
	m408SetModule(t, f, false)
	for _, tc := range []struct {
		name string
		do   func() int
	}{
		{"metadata", func() int { status, _ := m408Request(f.Endpoint, "GET", "/api/yggdrasil", nil, nil); return status }},
		{"validate", func() int {
			status, _ := m408PostJSON(f.Endpoint, "/api/yggdrasil/authserver/validate", map[string]any{"accessToken": sess.AccessToken, "clientToken": sess.ClientToken})
			return status
		}},
		{"join", func() int {
			status, _ := m408PostJSON(f.Endpoint, "/api/yggdrasil/sessionserver/session/minecraft/join", map[string]any{"accessToken": sess.AccessToken, "selectedProfile": m408UUID, "serverId": "srv-disabled"})
			return status
		}},
		{"hasJoined", func() int {
			status, _ := m408Request(f.Endpoint, "GET", "/api/yggdrasil/sessionserver/session/minecraft/hasJoined?username=PlayerOne&serverId=srv-enabled", nil, nil)
			return status
		}},
		{"profile", func() int {
			status, _ := m408Request(f.Endpoint, "GET", "/api/yggdrasil/sessionserver/session/minecraft/profile/"+m408UUID, nil, nil)
			return status
		}},
	} {
		if status := tc.do(); status != http.StatusNotFound {
			t.Fatalf("%s disabled status=%d", tc.name, status)
		}
	}
	m408SetModule(t, f, true)
	// The token survived the disable/enable cycle.
	if status, _ := m408PostJSON(f.Endpoint, "/api/yggdrasil/authserver/validate", map[string]any{"accessToken": sess.AccessToken, "clientToken": sess.ClientToken}); status != http.StatusNoContent {
		t.Fatalf("validate after re-enable status=%d", status)
	}
	if err := g.join(sess.AccessToken, m408UUID, "srv-enabled2"); err != nil {
		t.Fatalf("join after re-enable: %v", err)
	}
}

// TestM408AuthResetPreservesDataKeyHashReauth verifies that an atomic
// auth-reset leaves account/business data, the profile-signing key and the
// published texture files intact, rejects every old credential and still
// allows reauthentication with the original password.
func TestM408AuthResetPreservesDataKeyHashReauth(t *testing.T) {
	f := m408NewFixture(t, "", nil)
	m408SetScore(t, f, 1, 100000)
	c := m408NewHMCL(f.Endpoint)
	sess, err := c.withPassword(m408GameEmail, m408GamePass, nil)
	if err != nil {
		t.Fatalf("withPassword: %v", err)
	}
	stevePath, steveHash := m408StageTexture(t, "steve-64x64.png")
	m408UploadTexture(t, f.Endpoint, sess.AccessToken, m408UUID, "skin", "", stevePath)
	g := m408GameClient{ep: f.Endpoint}
	if err := g.join(sess.AccessToken, m408UUID, "srv-reset"); err != nil {
		t.Fatalf("join: %v", err)
	}
	var keyBefore string
	if err := f.Identity.Store.DB.QueryRow("SELECT option_value FROM " + f.Identity.Store.Table("options") + " WHERE option_name='ygg_private_key'").Scan(&keyBefore); err != nil {
		t.Fatal(err)
	}
	_, meta, err := m408DiscoverAPI(f.Endpoint, f.Endpoint.BaseURL+"/api/yggdrasil", false)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	pubBefore, err := meta.PublicKey()
	if err != nil {
		t.Fatalf("metadata key: %v", err)
	}
	var passwordBefore, uuidBefore string
	if err := f.Identity.Store.DB.QueryRow("SELECT password FROM " + f.Identity.Store.Table("users") + " WHERE uid=1").Scan(&passwordBefore); err != nil {
		t.Fatal("password fixture read failed")
	}
	if err := f.Identity.Store.DB.QueryRow("SELECT uuid FROM " + f.Identity.Store.Table("go_uuid_bindings") + " WHERE pid=1").Scan(&uuidBefore); err != nil || uuidBefore != m408UUID {
		t.Fatal("fixed UUID fixture missing")
	}
	if err := maintenance.ResetAuthentication(t.Context(), f.Identity.Store); err != nil {
		t.Fatalf("ResetAuthentication: %v", err)
	}
	// Users/players/textures and the signing key survive.
	var users, players, textures int
	_ = f.Identity.Store.DB.QueryRow("SELECT COUNT(*) FROM " + f.Identity.Store.Table("users")).Scan(&users)
	_ = f.Identity.Store.DB.QueryRow("SELECT COUNT(*) FROM " + f.Identity.Store.Table("players")).Scan(&players)
	_ = f.Identity.Store.DB.QueryRow("SELECT COUNT(*) FROM " + f.Identity.Store.Table("textures")).Scan(&textures)
	if users < 2 || players < 1 || textures < 1 {
		t.Fatalf("reset lost data users=%d players=%d textures=%d", users, players, textures)
	}
	var keyAfter string
	if err := f.Identity.Store.DB.QueryRow("SELECT option_value FROM " + f.Identity.Store.Table("options") + " WHERE option_name='ygg_private_key'").Scan(&keyAfter); err != nil || keyAfter != keyBefore {
		t.Fatalf("key changed after reset")
	}
	_, meta2, err := m408DiscoverAPI(f.Endpoint, f.Endpoint.BaseURL+"/api/yggdrasil", false)
	if err != nil {
		t.Fatalf("rediscover: %v", err)
	}
	pubAfter, err := meta2.PublicKey()
	if err != nil || pubAfter.N.Cmp(pubBefore.N) != 0 {
		t.Fatalf("metadata key changed after reset")
	}
	var passwordAfter, uuidAfter string
	if err := f.Identity.Store.DB.QueryRow("SELECT password FROM " + f.Identity.Store.Table("users") + " WHERE uid=1").Scan(&passwordAfter); err != nil || passwordAfter != passwordBefore {
		t.Fatal("original password hash changed after reset")
	}
	if err := f.Identity.Store.DB.QueryRow("SELECT uuid FROM " + f.Identity.Store.Table("go_uuid_bindings") + " WHERE pid=1").Scan(&uuidAfter); err != nil || uuidAfter != uuidBefore {
		t.Fatal("fixed UUID changed after reset")
	}
	// Old credential rejected at every entry point.
	status, body := m408PostJSON(f.Endpoint, "/api/yggdrasil/authserver/validate", map[string]any{"accessToken": sess.AccessToken, "clientToken": sess.ClientToken})
	m408ExpectRemote(t, m408OptionalError(status, body), "ForbiddenOperationException", "Invalid AccessToken. Please re-login.")
	m408ExpectRemote(t, g.join(sess.AccessToken, m408UUID, "srv-reset2"), "ForbiddenOperationException", "No valid credential information.")
	// Reauthentication with the original password issues a fresh credential
	// and the published texture hash is preserved through hasJoined.
	reauth, err := c.withPassword(m408GameEmail, m408GamePass, nil)
	if err != nil {
		t.Fatalf("reauth: %v", err)
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serverPubDER, err := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	serverID := m408ServerID([]byte("reset-shared-secret-00"), serverPubDER)
	if err := g.join(reauth.AccessToken, m408UUID, serverID); err != nil {
		t.Fatalf("join after reset: %v", err)
	}
	doc, found, err := g.hasJoined("PlayerOne", serverID, "")
	if err != nil || !found || doc == nil {
		t.Fatalf("hasJoined after reset found=%v err=%v", found, err)
	}
	if err := m408VerifySignedProperties(pubAfter, doc.Properties); err != nil {
		t.Fatalf("signature after reset: %v", err)
	}
	tp, err := m408DecodeTextures(doc.Properties)
	if err != nil {
		t.Fatalf("textures after reset: %v", err)
	}
	skin, ok := tp.Textures["SKIN"]
	if !ok {
		t.Fatalf("skin lost after reset")
	}
	data, status, err := m408Download(f.Endpoint, skin.URL)
	if err != nil || status != 200 {
		t.Fatalf("skin download after reset status=%d err=%v", status, err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != steveHash {
		t.Fatalf("texture hash changed after reset")
	}
}

// TestM408QualificationFakeResponses qualifies the consumer models against
// fake responses: bad metadata, wrong client token echo, tampered signature,
// disallowed skin domain and bad HMAC. No Go App is involved.
func TestM408QualificationFakeResponses(t *testing.T) {
	t.Run("badmetadata", func(t *testing.T) {
		ep := m408FakeEndpoint(func(r *http.Request) (*http.Response, error) {
			return m408FakeJSON(200, `this is not json`)
		})
		if _, _, err := m408DiscoverAPI(ep, ep.BaseURL, false); err == nil {
			t.Fatalf("malformed metadata accepted")
		}
	})
	t.Run("wrongclientToken", func(t *testing.T) {
		ep := m408FakeEndpoint(func(r *http.Request) (*http.Response, error) {
			return m408FakeJSON(200, `{"accessToken":"acc-token","clientToken":"other-token","availableProfiles":[{"id":"12345678-1234-4234-8234-123456789abc","name":"PlayerOne"}],"selectedProfile":{"id":"12345678-1234-4234-8234-123456789abc","name":"PlayerOne"}}`)
		})
		c := &m408HMCL{ep: ep, clientToken: "my-token"}
		if _, err := c.authenticate("u", "p"); err == nil || !strings.Contains(err.Error(), "client token changed") {
			t.Fatalf("client token echo not detected: %v", err)
		}
	})
	t.Run("tamperedSignature", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal("qualification key generation failed")
		}
		value := base64.StdEncoding.EncodeToString([]byte(`{"textures":{}}`))
		sum := sha1.Sum([]byte(value))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sum[:])
		if err != nil {
			t.Fatal("qualification signing failed")
		}
		props := []m408Property{{Name: "textures", Value: value, Signature: base64.StdEncoding.EncodeToString(signature)}}
		ep := m408FakeEndpoint(func(r *http.Request) (*http.Response, error) {
			body, _ := json.Marshal(m408HasJoinedDoc{ID: m408UUID, Name: "PlayerOne", Properties: props})
			return m408FakeJSON(200, string(body))
		})
		doc, found, err := (m408GameClient{ep: ep}).hasJoined("PlayerOne", "qualification", "")
		if err != nil || !found || m408VerifySignedProperties(&key.PublicKey, doc.Properties) != nil {
			t.Fatal("qualification baseline rejected")
		}
		signature[0] ^= 1
		props[0].Signature = base64.StdEncoding.EncodeToString(signature)
		doc, _, err = (m408GameClient{ep: ep}).hasJoined("PlayerOne", "qualification", "")
		if err != nil || m408VerifySignedProperties(&key.PublicKey, doc.Properties) == nil {
			t.Fatal("tampered RSA property signature accepted")
		}
		props[0].Signature = ""
		doc, _, err = (m408GameClient{ep: ep}).hasJoined("PlayerOne", "qualification", "")
		if err != nil || m408VerifySignedProperties(&key.PublicKey, doc.Properties) == nil {
			t.Fatal("missing RSA property signature accepted")
		}
	})
	t.Run("relativeALI", func(t *testing.T) {
		requests := 0
		ep := m408FakeEndpoint(func(r *http.Request) (*http.Response, error) {
			requests++
			if requests == 1 {
				resp, _ := m408FakeJSON(200, "<html>discovery</html>")
				resp.Header.Set("X-Authlib-Injector-API-Location", "../api/yggdrasil")
				return resp, nil
			}
			if r.URL.String() != "http://fake.invalid/api/yggdrasil" {
				t.Fatal("relative ALI resolved incorrectly")
			}
			return m408FakeJSON(200, `{"signaturePublickey":"qualification-key","skinDomains":["fake.invalid"]}`)
		})
		target, meta, err := m408DiscoverAPI(ep, "http://fake.invalid/skin/discovery", true)
		if err != nil || meta == nil || target != "http://fake.invalid/api/yggdrasil" || requests != 2 {
			t.Fatal("ALI qualification failed")
		}
	})
	t.Run("disallowedDomain", func(t *testing.T) {
		meta := &m408Metadata{SkinDomains: []string{"skin.example.invalid"}}
		if meta.AllowsDomain("evil.example") {
			t.Fatalf("disallowed domain accepted")
		}
		if !meta.AllowsDomain("skin.example.invalid") {
			t.Fatalf("allowed domain refused")
		}
	})
	t.Run("badHMAC", func(t *testing.T) {
		msg := m408EncodeModernForwarding([]byte(m408ForwardingSec), 1, m408ForwardingAddr, m408ForwardingUUID, m408ForwardingName, m408VecProps)
		if _, err := m408DecodeModernForwarding([]byte("wrong"), msg); err == nil {
			t.Fatalf("bad hmac accepted")
		}
		if _, err := m408DecodeModernForwarding([]byte(m408ForwardingSec), msg[:31]); err == nil {
			t.Fatalf("truncated message accepted")
		}
		flipped := append([]byte(nil), msg...)
		flipped[40] ^= 0xff
		if _, err := m408DecodeModernForwarding([]byte(m408ForwardingSec), flipped); err == nil {
			t.Fatalf("tampered payload accepted")
		}
	})
}

// Exact frozen Yggdrasil errors; m408OptionalError also checks their HTTP
// status (400/401/403/404) without importing the product error renderer.
func m408ExpectRemote(t *testing.T, err error, name, message string) {
	t.Helper()
	remote, ok := err.(*m408RemoteError)
	if !ok || remote.Name != name || remote.Message != message || remote.Cause != "" {
		t.Fatal("Yggdrasil rejection status/error/shape mismatch")
	}
}
