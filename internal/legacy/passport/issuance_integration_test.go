package passport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"

	"blessing-skin-go/internal/legacy/registration"
	"blessing-skin-go/internal/legacy/revocation"
	"blessing-skin-go/internal/legacy/testdb"
	"blessing-skin-go/internal/legacy/users"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

// requireAccountLock asserts that uid's row is held by another transaction.
func requireAccountLock(t *testing.T, db *sql.DB, uid int64) {
	t.Helper()
	var got int64
	err := db.QueryRowContext(context.Background(),
		"SELECT uid FROM users WHERE uid=? FOR UPDATE NOWAIT", uid).Scan(&got)
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) && (mysqlErr.Number == 3572 || mysqlErr.Number == 1205) {
		return
	}
	if err != nil {
		t.Fatalf("lock probe: %v", err)
	}
	t.Fatal("account row is not locked")
}

func newPassport(t *testing.T, db *sql.DB) *Service {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Config{
		DB:         db,
		Prefix:     "",
		Users:      users.New(db, ""),
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
		AppKey:     []byte("0123456789abcdef0123456789abcdef"),
		AccessTTL:  time.Hour,
		RefreshTTL: time.Hour,
		CodeTTL:    time.Minute,
		Scopes:     RegisteredScopes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func seedPasswordClient(t *testing.T, db *sql.DB, email, raw string) (int64, int64) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	result, err := db.Exec(`INSERT INTO users(email,nickname,password,permission,verified)
		VALUES(?,?,?,0,1)`, email, "Nick", string(hash))
	if err != nil {
		t.Fatal(err)
	}
	uid, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	clientID := int64(9101)
	if _, err := db.Exec(`INSERT INTO oauth_clients(id,name,secret,provider,redirect,
		personal_access_client,password_client,revoked,created_at,updated_at)
		VALUES(?,?,?,?,?,0,1,0,NOW(),NOW())`, clientID, "Test", "secret-value", "users",
		"https://client.invalid/callback"); err != nil {
		t.Fatal(err)
	}
	return uid, clientID
}

// TestPasswordGrantHoldsAccountLock covers R02 both ways: the grant holds the
// account row while verifying, a concurrent password change cannot commit
// early, and the pair it issued is revoked once the change lands.
func TestPasswordGrantHoldsAccountLock(t *testing.T) {
	db := testdb.Open(t)
	svc := newPassport(t, db)
	ctx := context.Background()
	uid, clientID := seedPasswordClient(t, db, "grant@example.invalid", "old-password-1")
	client := strconv.FormatInt(clientID, 10)

	verified := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseGrant := func() { releaseOnce.Do(func() { close(release) }) }
	svc.afterVerify = func() {
		close(verified)
		<-release
	}

	type outcome struct {
		response *TokenResponse
		err      error
	}
	done := make(chan outcome, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		response, err := svc.Password(ctx, client, "secret-value", "grant@example.invalid", "old-password-1", "")
		done <- outcome{response, err}
	}()
	t.Cleanup(func() {
		releaseGrant()
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
		}
	})
	<-verified
	requireAccountLock(t, db, uid)

	changeDone := make(chan error, 1)
	go func() {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			changeDone <- err
			return
		}
		defer tx.Rollback()
		if err := registration.ChangePassword(ctx, tx, "", uid, "new-password-1", testSecret); err != nil {
			changeDone <- err
			return
		}
		changeDone <- tx.Commit()
	}()
	select {
	case err := <-changeDone:
		t.Fatalf("password change committed while the grant held the account lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	releaseGrant()
	got := <-done
	if got.err != nil {
		t.Fatalf("password grant failed: %v", got.err)
	}
	if err := <-changeDone; err != nil {
		t.Fatalf("password change: %v", err)
	}
	if _, err := svc.ValidateAccess(ctx, got.response.AccessToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("access token error = %v, want ErrInvalidToken", err)
	}
	if _, err := svc.Refresh(ctx, got.response.RefreshToken, client, "secret-value", ""); err == nil {
		t.Fatal("refresh succeeded after the password change")
	}
	if _, err := svc.Password(ctx, client, "secret-value", "grant@example.invalid", "old-password-1", ""); err == nil {
		t.Fatal("old password grant succeeded after the password change")
	}
}

// TestPasswordGrantStillIssuesForCurrentPassword keeps the normal path working.
func TestPasswordGrantStillIssuesForCurrentPassword(t *testing.T) {
	db := testdb.Open(t)
	svc := newPassport(t, db)
	uid, _ := seedPasswordClient(t, db, "ok@example.invalid", "old-password-1")

	response, err := svc.Password(context.Background(), "9101", "secret-value", "ok@example.invalid", "old-password-1", "")
	if err != nil {
		t.Fatalf("password grant failed: %v", err)
	}
	identity, err := svc.ValidateAccess(context.Background(), response.AccessToken)
	if err != nil {
		t.Fatalf("issued token rejected: %v", err)
	}
	if identity.UID != uid {
		t.Fatalf("uid = %d, want %d", identity.UID, uid)
	}
}

const codeRedirect = "https://client.invalid/callback"

func seedCodeClient(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	const id = int64(9103)
	if _, err := db.Exec(`INSERT INTO oauth_clients(id,name,secret,provider,redirect,
		personal_access_client,password_client,revoked,created_at,updated_at)
		VALUES(?,?,?,?,?,0,0,0,NOW(),NOW())`, id, "Code", "code-secret", "users", codeRedirect); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestIssuedTokensRevokedByPasswordChange covers the other ordering: tokens
// issued first must be revoked when the password change commits.
func TestIssuedTokensRevokedByPasswordChange(t *testing.T) {
	db := testdb.Open(t)
	svc := newPassport(t, db)
	ctx := context.Background()
	uid, _ := seedPasswordClient(t, db, "revoke@example.invalid", "old-password-1")

	response, err := svc.Password(ctx, "9101", "secret-value", "revoke@example.invalid", "old-password-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ValidateAccess(ctx, response.AccessToken); err != nil {
		t.Fatalf("new token rejected before the change: %v", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := registration.ChangePassword(ctx, tx, "", uid, "new-password-1", testSecret); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.ValidateAccess(ctx, response.AccessToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("access token error = %v, want ErrInvalidToken", err)
	}
	if _, err := svc.Refresh(ctx, response.RefreshToken, "9101", "secret-value", ""); err == nil {
		t.Fatal("refresh succeeded after the password change")
	}
	if _, err := svc.Password(ctx, "9101", "secret-value", "revoke@example.invalid", "old-password-1", ""); err == nil {
		t.Fatal("old password grant succeeded after the password change")
	}
}

// TestIssueCodeBindsApprovalGeneration covers the authorization-code issuance
// path: a code approved before a version change must not be redeemable after it
// even if a writer failed to revoke the row.
func TestIssueCodeBindsApprovalGeneration(t *testing.T) {
	db := testdb.Open(t)
	svc := newPassport(t, db)
	ctx := context.Background()
	uid, _ := seedPasswordClient(t, db, "code@example.invalid", "old-password-1")
	clientID := seedCodeClient(t, db)

	user, found, err := users.New(db, "").ByUID(ctx, uid)
	if err != nil || !found {
		t.Fatalf("load user: %v", err)
	}
	store := revocation.New(db, "")
	if _, err := store.Ensure(ctx, uid, user.Password, testSecret, time.Now()); err != nil {
		t.Fatal(err)
	}

	code, _, _, err := svc.IssueCode(ctx, clientID, uid, codeRedirect, []string{"User.Read"}, "", "")
	if err != nil {
		t.Fatalf("issue code: %v", err)
	}
	// Advance the account generation without revoking the code row, isolating
	// the approval-epoch check from the row flag.
	if _, err := store.Bump(ctx, uid, user.Password, testSecret, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExchangeCode(ctx, code, strconv.FormatInt(clientID, 10), "code-secret", codeRedirect, ""); err == nil {
		t.Fatal("code issued before the version change was redeemed")
	}

	// A code issued after the change still works.
	fresh, _, _, err := svc.IssueCode(ctx, clientID, uid, codeRedirect, []string{"User.Read"}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExchangeCode(ctx, fresh, strconv.FormatInt(clientID, 10), "code-secret", codeRedirect, ""); err != nil {
		t.Fatalf("fresh code rejected: %v", err)
	}
}

// craftedCode builds an authorization-code ciphertext from an explicit JSON map.
// Using a raw map (instead of codePayload) keeps the crafted fixtures readable
// in both the fixed and the pre-fix baseline source tree.
func craftedCode(t *testing.T, svc *Service, fields map[string]any) (string, string) {
	t.Helper()
	id := fields["auth_code_id"].(string)
	uid := fields["user_id"].(int64)
	clientID := fields["client_id"].(string)
	if err := svc.Repo().CreateAuthCode(context.Background(), AuthCodeRow{
		ID: id, UserID: uid, ClientID: clientID,
		Scopes: []string{"User.Read"},
		// Give the row a little headroom so the crafted payload's expiry (not the
		// row) is the value under test.
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("create crafted code row: %v", err)
	}
	code, err := svc.encryptPayload(fields)
	if err != nil {
		t.Fatalf("encrypt crafted code: %v", err)
	}
	return code, id
}

func craftedCodeFields(uid, clientID int64, codeID string) map[string]any {
	return map[string]any{
		"client_id":             strconv.FormatInt(clientID, 10),
		"redirect_uri":          codeRedirect,
		"auth_code_id":          codeID,
		"scopes":                []string{"User.Read"},
		"user_id":               uid,
		"expire_time":           time.Now().Add(5 * time.Minute).Unix(),
		"code_challenge":        "",
		"code_challenge_method": "",
	}
}

// TestIssueCodeRecordsApprovalGeneration covers the issuance side of the
// generation boundary: a Go code always carries approved_rev, and issuance
// materializes the generation-1 baseline it recorded, so a first login or
// revocation later compares against the same value instead of a missing row.
func TestIssueCodeRecordsApprovalGeneration(t *testing.T) {
	db := testdb.Open(t)
	svc := newPassport(t, db)
	ctx := context.Background()
	uid, _ := seedPasswordClient(t, db, "generation@example.invalid", "old-password-1")
	clientID := seedCodeClient(t, db)

	var rows int
	if err := db.QueryRow("SELECT COUNT(*) FROM legacy_auth_revocations WHERE user_uid=?", uid).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("precondition: %d revocation rows exist, want 0", rows)
	}

	code, _, _, err := svc.IssueCode(ctx, clientID, uid, codeRedirect, []string{"User.Read"}, "", "")
	if err != nil {
		t.Fatalf("issue code: %v", err)
	}
	var payload map[string]any
	if err := svc.decryptPayload(code, &payload); err != nil {
		t.Fatalf("decrypt payload: %v", err)
	}
	value, present := payload["approved_rev"]
	if !present {
		t.Fatal("a Go authorization code must always carry approved_rev")
	}
	rev, ok := value.(float64)
	if !ok || rev != 1 {
		t.Fatalf("approved_rev = %v, want 1 (baseline materialized at issuance)", value)
	}
	if _, err := svc.ExchangeCode(ctx, code, strconv.FormatInt(clientID, 10), "code-secret", codeRedirect, ""); err != nil {
		t.Fatalf("code issued at the baseline generation was rejected: %v", err)
	}
}

// TestZeroApprovalGenerationIsRejected is the R06/R02 generation boundary for
// the value zero: a code that records generation 0 must be compared, not
// treated as "no approval generation". Otherwise an approval recorded before the
// first generation advance stays redeemable after it.
func TestZeroApprovalGenerationIsRejected(t *testing.T) {
	db := testdb.Open(t)
	svc := newPassport(t, db)
	ctx := context.Background()
	uid, _ := seedPasswordClient(t, db, "zero-generation@example.invalid", "old-password-1")
	clientID := seedCodeClient(t, db)

	user, found, err := users.New(db, "").ByUID(ctx, uid)
	if err != nil || !found {
		t.Fatalf("load user: %v", err)
	}
	// A first login materializes generation 1.
	if _, err := revocation.New(db, "").Ensure(ctx, uid, user.Password, testSecret, time.Now()); err != nil {
		t.Fatal(err)
	}

	fields := craftedCodeFields(uid, clientID, "crafted-zero-approval")
	fields["approved_rev"] = 0
	code, id := craftedCode(t, svc, fields)

	if _, err := svc.ExchangeCode(ctx, code, strconv.FormatInt(clientID, 10), "code-secret", codeRedirect, ""); err == nil {
		t.Fatal("code recording approval generation 0 was redeemed at generation 1")
	}
	revoked, err := svc.Repo().AuthCodeRevoked(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Fatal("rejected code was consumed in the database")
	}
}

// TestNativeCodeWithoutApprovalGenerationStillExchanges keeps the frozen native
// compatibility path: a PHP writer's code has no approved_rev field, and it must
// still exchange while the row is active and every native check passes.
func TestNativeCodeWithoutApprovalGenerationStillExchanges(t *testing.T) {
	db := testdb.Open(t)
	svc := newPassport(t, db)
	ctx := context.Background()
	uid, _ := seedPasswordClient(t, db, "native-code@example.invalid", "old-password-1")
	clientID := seedCodeClient(t, db)

	user, found, err := users.New(db, "").ByUID(ctx, uid)
	if err != nil || !found {
		t.Fatalf("load user: %v", err)
	}
	// The native writer never records an approval generation; a later revocation
	// advance must not fabricate one for this code either.
	if _, err := revocation.New(db, "").Ensure(ctx, uid, user.Password, testSecret, time.Now()); err != nil {
		t.Fatal(err)
	}
	fields := craftedCodeFields(uid, clientID, "crafted-native-approval")
	code, _ := craftedCode(t, svc, fields)
	if _, err := svc.ExchangeCode(ctx, code, strconv.FormatInt(clientID, 10), "code-secret", codeRedirect, ""); err != nil {
		t.Fatalf("native-shaped code without approved_rev was rejected: %v", err)
	}
}

// TestMalformedApprovalGenerationIsRejected covers the negative and wrong-type
// forms: a negative generation and a non-numeric generation must both be
// refused instead of being skipped as "not positive".
func TestMalformedApprovalGenerationIsRejected(t *testing.T) {
	db := testdb.Open(t)
	svc := newPassport(t, db)
	ctx := context.Background()
	uid, _ := seedPasswordClient(t, db, "malformed-generation@example.invalid", "old-password-1")
	clientID := seedCodeClient(t, db)
	client := strconv.FormatInt(clientID, 10)

	for name, value := range map[string]any{
		"negative":  int64(-3),
		"not-a-num": "not-a-number",
	} {
		t.Run(name, func(t *testing.T) {
			fields := craftedCodeFields(uid, clientID, "crafted-"+name)
			fields["approved_rev"] = value
			code, id := craftedCode(t, svc, fields)
			if _, err := svc.ExchangeCode(ctx, code, client, "code-secret", codeRedirect, ""); err == nil {
				t.Fatalf("code with approved_rev=%v was redeemed", value)
			}
			revoked, err := svc.Repo().AuthCodeRevoked(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if revoked {
				t.Fatal("rejected code was consumed in the database")
			}
		})
	}
}

// TestExchangeCodeConsumesOnce keeps single consumption: one winner, including
// when two redemptions race.
func TestExchangeCodeConsumesOnce(t *testing.T) {
	db := testdb.Open(t)
	svc := newPassport(t, db)
	ctx := context.Background()
	uid, _ := seedPasswordClient(t, db, "once@example.invalid", "old-password-1")
	clientID := seedCodeClient(t, db)
	client := strconv.FormatInt(clientID, 10)

	code, _, _, err := svc.IssueCode(ctx, clientID, uid, codeRedirect, []string{"User.Read"}, "", "")
	if err != nil {
		t.Fatalf("issue code: %v", err)
	}
	if _, err := svc.ExchangeCode(ctx, code, client, "code-secret", codeRedirect, ""); err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	if _, err := svc.ExchangeCode(ctx, code, client, "code-secret", codeRedirect, ""); err == nil {
		t.Fatal("replayed code was exchanged twice")
	}

	racy, _, _, err := svc.IssueCode(ctx, clientID, uid, codeRedirect, []string{"User.Read"}, "", "")
	if err != nil {
		t.Fatalf("issue racy code: %v", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.ExchangeCode(ctx, racy, client, "code-secret", codeRedirect, "")
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent exchanges succeeded %d times, want exactly 1", successes)
	}
}

// TestExchangeCodeRollsBackWhenIssuanceFails keeps the failure invariant: a
// storage error while writing the token rows must not consume the code or leave
// half a token pair behind.
func TestExchangeCodeRollsBackWhenIssuanceFails(t *testing.T) {
	db := testdb.Open(t)
	svc := newPassport(t, db)
	ctx := context.Background()
	uid, _ := seedPasswordClient(t, db, "rollback@example.invalid", "old-password-1")
	clientID := seedCodeClient(t, db)
	client := strconv.FormatInt(clientID, 10)

	code, codeID, _, err := svc.IssueCode(ctx, clientID, uid, codeRedirect, []string{"User.Read"}, "", "")
	if err != nil {
		t.Fatalf("issue code: %v", err)
	}
	if _, err := db.Exec("RENAME TABLE oauth_access_tokens TO oauth_access_tokens_unavailable"); err != nil {
		t.Fatalf("hide access-token table: %v", err)
	}
	if _, err := svc.ExchangeCode(ctx, code, client, "code-secret", codeRedirect, ""); err == nil {
		t.Fatal("exchange succeeded while the access-token write was failing")
	}
	if _, err := db.Exec("RENAME TABLE oauth_access_tokens_unavailable TO oauth_access_tokens"); err != nil {
		t.Fatalf("restore access-token table: %v", err)
	}
	revoked, err := svc.Repo().AuthCodeRevoked(ctx, codeID)
	if err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Fatal("failed exchange consumed the authorization code")
	}
	var tokens int
	if err := db.QueryRow("SELECT COUNT(*) FROM oauth_access_tokens").Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if tokens != 0 {
		t.Fatalf("failed exchange left %d access-token rows", tokens)
	}
	if _, err := svc.ExchangeCode(ctx, code, client, "code-secret", codeRedirect, ""); err != nil {
		t.Fatalf("code was not redeemable after the failed attempt: %v", err)
	}
}
