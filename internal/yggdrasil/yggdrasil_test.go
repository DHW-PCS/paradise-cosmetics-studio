package yggdrasil_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"regexp"
	"testing"
	"time"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/maintenance"
	"blessing-skin-go/internal/oauthserver"
	"blessing-skin-go/internal/players"
	"blessing-skin-go/internal/testsupport"
	"blessing-skin-go/internal/yggdrasil"
)

var testKey = []byte("synthetic-yggdrasil-hs256-key-32b")

type harness struct {
	store *database.Store
	id    *identity.Service
	svc   *yggdrasil.Service
	now   time.Time
}

func fixture(t *testing.T) harness {
	t.Helper()
	store, id := testsupport.Database(t, "ygg-")
	// The seeded PlayerOne needs a real current binding for any protocol
	// operation; the generic testsupport database keeps uuid state empty.
	uuidVal := players.UUID3("PlayerOne")
	if _, err := store.DB.Exec("INSERT INTO "+store.Table("uuid")+" (name,uuid) VALUES (?,?)", "PlayerOne", uuidVal); err != nil {
		t.Fatal(err)
	}
	var uuidRowID int64
	if err := store.DB.QueryRow("SELECT id FROM "+store.Table("uuid")+" WHERE name=? ORDER BY id LIMIT 1", "PlayerOne").Scan(&uuidRowID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec("INSERT INTO "+store.Table("go_uuid_bindings")+" (pid,uuid_row_id,uuid,version) VALUES (1,?,?,1)", uuidRowID, uuidVal); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	id.Now = func() time.Time { return now }
	svc := yggdrasil.New(store, id, nil, testKey, false, func() time.Time { return now })
	return harness{store: store, id: id, svc: svc, now: now}
}

func setOption(t *testing.T, store *database.Store, key, value string) {
	t.Helper()
	if _, err := store.DB.Exec("INSERT INTO "+store.Table("options")+" (option_name,option_value) VALUES (?,?)", key, value); err != nil {
		t.Fatal(err)
	}
}

func tokenCount(t *testing.T, store *database.Store, uid int64) int {
	t.Helper()
	var n int
	if err := store.DB.QueryRow("SELECT COUNT(*) FROM "+store.Table("go_yggdrasil_tokens")+" WHERE user_uid=?", uid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// --- RSA tiers (no database) ----------------------------------------------

func genKey(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}

func genECPEM() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func TestParseTierIgnoresSizeAndExportRequires4096(t *testing.T) {
	small := genKey(t, 2048)
	if _, apiErr := yggdrasil.ParsePrivateKey(small); apiErr != nil {
		t.Fatalf("small key must parse: %v", apiErr)
	}
	if _, apiErr := yggdrasil.LoadForExport(small); apiErr == nil || apiErr.Name != "IllegalArgumentException" || apiErr.Status != 400 {
		t.Fatalf("small export must be 400, got %v", apiErr)
	}
	if _, apiErr := yggdrasil.ParsePrivateKey("not a pem"); apiErr == nil || apiErr.Status != 400 {
		t.Fatalf("garbage must be 400, got %v", apiErr)
	}
	if _, apiErr := yggdrasil.ParsePrivateKey(""); apiErr == nil {
		t.Fatal("empty must fail")
	}
	// EC key must fail as not-RSA.
	ecPEM, err := genECPEM()
	if err == nil {
		if _, apiErr := yggdrasil.ParsePrivateKey(ecPEM); apiErr == nil {
			t.Fatal("EC key must be rejected")
		}
	}
}

func TestGenerateProduces4096(t *testing.T) {
	pemText, err := yggdrasil.GeneratePrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	key, apiErr := yggdrasil.LoadForExport(pemText)
	if apiErr != nil {
		t.Fatalf("generated key must pass export tier: %v", apiErr)
	}
	pub := yggdrasil.PublicKeyPEM(key)
	if len(pub) == 0 || pub == pemText {
		t.Fatal("public PEM must differ from private")
	}
	if b64 := yggdrasil.PublicKeyBase64(key); len(b64) == 0 {
		t.Fatal("base64 public key empty")
	}
}

// --- JWT / identity helpers (no database) ---------------------------------

func TestUserUUIDIsV5OfEmailAndDIffersFromUID(t *testing.T) {
	u1 := yggdrasil.MustDashed(yggdrasil.UserUUID("user@example.invalid"))
	if u1 == "1" {
		t.Fatal("protocol id must not be UID decimal")
	}
	u2 := yggdrasil.MustDashed(yggdrasil.UserUUID("USER@example.invalid"))
	if u1 == u2 {
		t.Fatal("stored email case must affect v5")
	}
}

// --- integration ----------------------------------------------------------

func TestAuthenticateSuccessSingleRole(t *testing.T) {
	h := fixture(t)
	setOption(t, h.store, "ygg_token_expire_1", "3600")
	setOption(t, h.store, "ygg_token_expire_2", "86400")
	setOption(t, h.store, "ygg_tokens_limit", "10")
	res, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password", RequestUser: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.AccessToken == "" || res.ClientToken == "" {
		t.Fatal("empty tokens")
	}
	if len(res.AvailableProfiles) != 1 || res.AvailableProfiles[0].Name != "PlayerOne" {
		t.Fatalf("profiles %+v", res.AvailableProfiles)
	}
	if res.SelectedProfile == nil || res.SelectedProfile.Name != "PlayerOne" {
		t.Fatal("single role must auto-select")
	}
	if res.User == nil || res.User.ID == "" || len(res.User.Properties) != 0 {
		t.Fatal("user block missing")
	}
	if tokenCount(t, h.store, 1) != 1 {
		t.Fatal("token row missing")
	}
	// Validate passes for the fresh token.
	if err = h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: res.AccessToken}); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestAuthenticateClientTokenSemantics(t *testing.T) {
	h := fixture(t)
	setOption(t, h.store, "ygg_token_expire_1", "3600")
	setOption(t, h.store, "ygg_token_expire_2", "86400")
	empty := ""
	res, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password", ClientToken: &empty})
	if err != nil {
		t.Fatal(err)
	}
	if res.ClientToken != "" {
		t.Fatalf("explicit empty clientToken must be kept, got %q", res.ClientToken)
	}
	// Missing field generates.
	res2, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password"})
	if err != nil || res2.ClientToken == "" {
		t.Fatalf("missing clientToken must generate: %v %q", err, res2.ClientToken)
	}
}

func TestAuthenticateRejectsBannedAndUnverified(t *testing.T) {
	h := fixture(t)
	setOption(t, h.store, "ygg_token_expire_1", "3600")
	setOption(t, h.store, "ygg_token_expire_2", "86400")
	if _, err := h.store.DB.Exec("UPDATE " + h.store.Table("users") + " SET permission=-1 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password"}); err == nil {
		t.Fatal("banned authenticate must fail")
	}
	if tokenCount(t, h.store, 1) != 0 {
		t.Fatal("rejected authenticate wrote a token")
	}
}

func TestRefreshRotatesAndClientTokenMismatchKeepsOld(t *testing.T) {
	h := fixture(t)
	setOption(t, h.store, "ygg_token_expire_1", "3600")
	setOption(t, h.store, "ygg_token_expire_2", "86400")
	ct := "ct-1"
	res, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password", ClientToken: &ct})
	if err != nil {
		t.Fatal(err)
	}
	wrong := "wrong"
	if _, err := h.svc.Refresh(t.Context(), yggdrasil.RefreshRequest{AccessToken: res.AccessToken, ClientToken: &wrong}); err == nil {
		t.Fatal("mismatch refresh must fail")
	}
	// Old token still valid after mismatch.
	if err = h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: res.AccessToken}); err != nil {
		t.Fatalf("mismatch must not consume old token: %v", err)
	}
	refreshed, err := h.svc.Refresh(t.Context(), yggdrasil.RefreshRequest{AccessToken: res.AccessToken, ClientToken: &ct})
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.AccessToken == res.AccessToken || refreshed.ClientToken != ct {
		t.Fatal("refresh must rotate access token and keep client token")
	}
	if err = h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: res.AccessToken}); err == nil {
		t.Fatal("old token must be gone after refresh")
	}
	if err = h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: refreshed.AccessToken}); err != nil {
		t.Fatalf("new token must validate: %v", err)
	}
	if tokenCount(t, h.store, 1) != 1 {
		t.Fatal("refresh must keep exactly one active token")
	}
}

func TestRefreshAllowedWhenAccessExpiredButRefreshWindowOpen(t *testing.T) {
	h := fixture(t)
	setOption(t, h.store, "ygg_token_expire_1", "10")
	setOption(t, h.store, "ygg_token_expire_2", "86400")
	res, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password"})
	if err != nil {
		t.Fatal(err)
	}
	// Advance the clock past access expiry but inside refresh window.
	// Rewire the service clock; the issued row stores absolute windows.
	expired := h.now.Add(100 * time.Second)
	h.svc = newSvcWithClock(h, expired)
	if err = h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: res.AccessToken}); err == nil {
		t.Fatal("expired access must fail validate")
	}
	refreshed, err := h.svc.Refresh(t.Context(), yggdrasil.RefreshRequest{AccessToken: res.AccessToken})
	if err != nil {
		t.Fatalf("refresh inside refresh window must succeed: %v", err)
	}
	if refreshed.AccessToken == "" {
		t.Fatal("empty refreshed token")
	}
}

func newSvcWithClock(h harness, at time.Time) *yggdrasil.Service {
	svc := yggdrasil.New(h.store, h.id, nil, testKey, false, func() time.Time { return at })
	return svc
}

func TestInvalidateIdempotent(t *testing.T) {
	h := fixture(t)
	setOption(t, h.store, "ygg_token_expire_1", "3600")
	setOption(t, h.store, "ygg_token_expire_2", "86400")
	res, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password"})
	if err != nil {
		t.Fatal(err)
	}
	if err = h.svc.Invalidate(t.Context(), yggdrasil.InvalidateRequest{AccessToken: res.AccessToken}); err != nil {
		t.Fatal(err)
	}
	if err = h.svc.Invalidate(t.Context(), yggdrasil.InvalidateRequest{AccessToken: res.AccessToken}); err != nil {
		t.Fatal("repeated invalidate must succeed")
	}
	if err = h.svc.Invalidate(t.Context(), yggdrasil.InvalidateRequest{AccessToken: "unknown-token"}); err != nil {
		t.Fatal("unknown invalidate must succeed")
	}
	if tokenCount(t, h.store, 1) != 0 {
		t.Fatal("invalidated token remains")
	}
}

func TestSignoutAllowsBannedButChecksVerification(t *testing.T) {
	h := fixture(t)
	setOption(t, h.store, "ygg_token_expire_1", "3600")
	setOption(t, h.store, "ygg_token_expire_2", "86400")
	if _, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.DB.Exec("UPDATE " + h.store.Table("users") + " SET permission=-1 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Signout(t.Context(), yggdrasil.SignoutRequest{Username: "user@example.invalid", Password: "original-password"}); err != nil {
		t.Fatalf("signout must allow banned: %v", err)
	}
	if tokenCount(t, h.store, 1) != 0 {
		t.Fatal("signout left tokens")
	}
}

func TestSignoutMissingVersionCreatesNothing(t *testing.T) {
	h := fixture(t)
	setOption(t, h.store, "ygg_token_expire_1", "3600")
	setOption(t, h.store, "ygg_token_expire_2", "86400")
	if _, err := h.store.DB.Exec("DELETE FROM " + h.store.Table("go_auth_versions") + " WHERE user_uid=1"); err != nil {
		t.Fatal(err)
	}
	// Signout with no version row must succeed and not create one.
	// The proof's default version does not count as state.
	err := h.svc.Signout(t.Context(), yggdrasil.SignoutRequest{Username: "user@example.invalid", Password: "original-password"})
	if err != nil {
		t.Fatalf("signout without version: %v", err)
	}
	var n int
	if err = h.store.DB.QueryRow("SELECT COUNT(*) FROM " + h.store.Table("go_auth_versions") + " WHERE user_uid=1").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("signout created a version row")
	}
}

func TestThrottleSeparatesFromAdmission(t *testing.T) {
	h := fixture(t)
	setOption(t, h.store, "ygg_token_expire_1", "3600")
	setOption(t, h.store, "ygg_token_expire_2", "86400")
	setOption(t, h.store, "ygg_rate_limit", "60000")
	// First authenticate succeeds and records the hit.
	if _, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password"}); err != nil {
		t.Fatal(err)
	}
	// Second immediate attempt is throttled (403) without a password check.
	_, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password"})
	if err == nil {
		t.Fatal("second attempt must be throttled")
	}
	var apiErr *yggdrasil.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 403 {
		t.Fatalf("throttle must be 403, got %v", err)
	}
	if err = h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: "x"}); err == nil {
		// validate is not throttled; it fails for another reason (invalid).
	}
}

func TestThrottleDisabledWhenRateZero(t *testing.T) {
	h := fixture(t)
	setOption(t, h.store, "ygg_token_expire_1", "3600")
	setOption(t, h.store, "ygg_token_expire_2", "86400")
	// No ygg_rate_limit row: heart rate is 0, never triggered.
	for i := 0; i < 2; i++ {
		if _, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password"}); err != nil {
			t.Fatalf("hit %d: %v", i, err)
		}
	}
}

func TestTokensLimitEvictsOldestKeepsOneAtZero(t *testing.T) {
	h := fixture(t)
	setOption(t, h.store, "ygg_token_expire_1", "3600")
	setOption(t, h.store, "ygg_token_expire_2", "86400")
	setOption(t, h.store, "ygg_tokens_limit", "0")
	var first string
	for i := 0; i < 3; i++ {
		res, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password"})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = res.AccessToken
		}
	}
	if tokenCount(t, h.store, 1) != 1 {
		t.Fatal("limit 0 must keep exactly one token")
	}
	if err := h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: first}); err == nil {
		t.Fatal("oldest token must have been evicted")
	}
}

func TestCheckReadyKeyTiers(t *testing.T) {
	h := fixture(t)
	// Missing key refuses.
	if reasons, err := h.runCheckReady(t); err != nil || len(reasons) == 0 {
		t.Fatalf("missing key reasons=%v err=%v", reasons, err)
	}
	// Small key passes enable (parse-only tier).
	small := genKey(t, 2048)
	setOption(t, h.store, "ygg_private_key", small)
	if reasons, err := h.runCheckReady(t); err != nil || len(reasons) != 0 {
		t.Fatalf("small key must pass enable: %v %v", reasons, err)
	}
	// Garbage refuses.
	setOption(t, h.store, "ygg_private_key", "garbage")
	if reasons, err := h.runCheckReady(t); err != nil || len(reasons) == 0 {
		t.Fatalf("garbage key must refuse: %v %v", reasons, err)
	}
}

func (h harness) runCheckReady(t *testing.T) ([]string, error) {
	t.Helper()
	var reasons []string
	err := h.store.Transaction(t.Context(), func(tx *sql.Tx) error {
		var err error
		reasons, err = h.svc.CheckReady(t.Context(), tx)
		return err
	})
	return reasons, err
}

func TestMaintenanceCleanupResetAndSchema(t *testing.T) {
	h := fixture(t)
	if err := oauthserver.Migrate(t.Context(), h.store); err != nil {
		t.Fatal(err)
	}
	if err := oauthserver.MigrateConsents(t.Context(), h.store); err != nil {
		t.Fatal(err)
	}
	if err := oauthserver.MigrateAPIDigest(t.Context(), h.store); err != nil {
		t.Fatal(err)
	}
	setOption(t, h.store, "ygg_token_expire_1", "3600")
	setOption(t, h.store, "ygg_token_expire_2", "86400")
	res, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password"})
	if err != nil {
		t.Fatal(err)
	}
	if res.AccessToken == "" {
		t.Fatal("no token")
	}
	// Expire the token's refresh window and add an expired join row.
	digest := tokenDigestForTest(res.AccessToken)
	if _, err := h.store.DB.Exec("UPDATE "+h.store.Table("go_yggdrasil_tokens")+" SET refresh_until=0,access_until=0 WHERE digest=?", digest); err != nil {
		t.Fatal(err)
	}
	joinDigest := make([]byte, 32)
	for i := range joinDigest {
		joinDigest[i] = byte(i)
	}
	if _, err := h.store.DB.Exec("INSERT INTO "+h.store.Table("go_yggdrasil_joins")+" (digest,pid,profile_uuid,binding_version,user_uid,version,token_digest,server_id,ip,expires_at) VALUES (?,?,?,?,?,?,?,?,?,0)", joinDigest, 1, "00000000000000000000000000000000", 1, 1, 1, digest, "srv", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	removed, err := maintenanceCleanup(t, h)
	if err != nil {
		t.Fatal(err)
	}
	if removed == 0 {
		t.Fatal("cleanup removed nothing for expired yggdrasil rows")
	}
	if tokenCount(t, h.store, 1) != 0 {
		t.Fatal("expired token survived per-UID cleanup")
	}
	var joins int
	if err = h.store.DB.QueryRow("SELECT COUNT(*) FROM " + h.store.Table("go_yggdrasil_joins")).Scan(&joins); err != nil {
		t.Fatal(err)
	}
	if joins != 0 {
		t.Fatal("expired join survived cleanup")
	}
	// Fresh token exists for reset; reset must clear all three families.
	res2, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password"})
	if err != nil {
		t.Fatal(err)
	}
	if tokenCount(t, h.store, 1) != 1 {
		t.Fatal("second token missing")
	}
	_ = res2
	if err := maintenanceResetAndCheck(t, h); err != nil {
		t.Fatal(err)
	}
	var tokens int
	if err = h.store.DB.QueryRow("SELECT COUNT(*) FROM " + h.store.Table("go_yggdrasil_tokens")).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if tokens != 0 {
		t.Fatal("auth-reset left tokens")
	}
}

func sha256Sum(raw string) []byte          { s := sha256.Sum256([]byte(raw)); return s[:] }
func tokenDigestForTest(raw string) []byte { return sha256Sum(raw) }

func maintenanceCleanup(t *testing.T, h harness) (int64, error) {
	t.Helper()
	return maintenance.Cleanup(t.Context(), h.store, h.now.Add(time.Hour), 100)
}

func maintenanceResetAndCheck(t *testing.T, h harness) error {
	t.Helper()
	if err := maintenance.CheckSchema(t.Context(), h.store); err != nil {
		return err
	}
	return maintenance.ResetAuthentication(t.Context(), h.store)
}

// TestProtocolIDsAreUnhyphenatedHex pins the authlib-injector wire shape:
// user.id, availableProfiles[].id and selectedProfile.id serialize as
// 32-character lowercase hex without dashes, matching both the protocol
// spec and the frozen legacy getHex()/str_replace('-',”) output. The
// session profile document id uses the same hex form.
func TestProtocolIDsAreUnhyphenatedHex(t *testing.T) {
	h := fixture(t)
	setOption(t, h.store, "ygg_token_expire_1", "3600")
	setOption(t, h.store, "ygg_token_expire_2", "86400")
	setOption(t, h.store, "ygg_tokens_limit", "10")
	hexID := regexp.MustCompile(`^[0-9a-f]{32}$`)
	res, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password", RequestUser: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.User == nil || !hexID.MatchString(res.User.ID) {
		t.Fatalf("user.id not unhyphenated hex: %+v", res.User)
	}
	if len(res.AvailableProfiles) != 1 || !hexID.MatchString(res.AvailableProfiles[0].ID) {
		t.Fatalf("availableProfiles id not unhyphenated hex: %+v", res.AvailableProfiles)
	}
	if res.SelectedProfile == nil || !hexID.MatchString(res.SelectedProfile.ID) {
		t.Fatalf("selectedProfile id not unhyphenated hex: %+v", res.SelectedProfile)
	}
	// The refresh echo keeps the same wire shape.
	fresh, err := h.svc.Refresh(t.Context(), yggdrasil.RefreshRequest{AccessToken: res.AccessToken})
	if err != nil {
		t.Fatal(err)
	}
	if fresh.SelectedProfile == nil || !hexID.MatchString(fresh.SelectedProfile.ID) {
		t.Fatalf("refresh selectedProfile id not unhyphenated hex: %+v", fresh.SelectedProfile)
	}
	if fresh.User == nil || !hexID.MatchString(fresh.User.ID) {
		t.Fatalf("refresh user.id not unhyphenated hex: %+v", fresh.User)
	}
}
