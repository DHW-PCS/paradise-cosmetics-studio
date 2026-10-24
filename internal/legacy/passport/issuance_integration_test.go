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
