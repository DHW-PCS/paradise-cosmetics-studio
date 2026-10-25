package passport

// Independent review of the A package (identity generation, current reads and
// the account-lock contract). This file is review-only: it adds no production
// behavior and every adversarial case runs against a disposable testdb database.
//
// The cases that document a suspected defect are opt-in via M1_REVIEW_A=1 so a
// deliberately failing assertion does not break the regular regression matrix
// while the finding is being triaged.
//
// Review additions (not part of the A package):
//   - TestReviewFirstTimeIssuanceProbeThenInsertDoesNotDeadlock
//   - TestReviewConcurrentFirstTimeIssueCodeDoesNotDeadlock
//   - TestReviewApprovedRevExtremeInputs
//   - TestReviewExchangeCodeUsesCurrentGenerationAfterLockWait
//   - TestReviewIssueCodeUsesCurrentGenerationAfterLockWait
//   - TestReviewNativeShapedCodeRejectedAfterPasswordChange

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"blessing-skin-go/internal/legacy/registration"
	"blessing-skin-go/internal/legacy/revocation"
	"blessing-skin-go/internal/legacy/testdb"
	"blessing-skin-go/internal/legacy/users"
)

var reviewSecret = []byte("0123456789abcdef0123456789abcdef")

// reviewHash is a synthetic password hash; only its HMAC fingerprint matters here.
const reviewHash = "$2y$04$independent-review-hash"

// reviewRedirect must match the client redirect and the crafted payloads.
const reviewRedirect = "https://client.invalid/callback"

func reviewPassport(t *testing.T, db *sql.DB) *Service {
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
		AppKey:     reviewSecret,
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

func reviewUser(t *testing.T, db *sql.DB, email string) int64 {
	t.Helper()
	result, err := db.Exec(`INSERT INTO users(email,nickname,password,permission,verified)
		VALUES(?,?,?,0,1)`, email, "Review", reviewHash)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	uid, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("seed user id: %v", err)
	}
	return uid
}

func reviewCodeClient(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	const id = int64(9107)
	if _, err := db.Exec(`INSERT INTO oauth_clients(id,name,secret,provider,redirect,
		personal_access_client,password_client,revoked,created_at,updated_at)
		VALUES(?,?,?,?,?,0,0,0,NOW(),NOW())`, id, "ReviewCode", "review-secret", "users", reviewRedirect); err != nil {
		t.Fatalf("seed code client: %v", err)
	}
	return id
}

// reviewLockRow takes the users row lock inside tx.
func reviewLockRow(t *testing.T, tx *sql.Tx, uid int64) {
	t.Helper()
	var got int64
	if err := tx.QueryRowContext(context.Background(), "SELECT uid FROM users WHERE uid=? FOR UPDATE", uid).Scan(&got); err != nil {
		t.Fatalf("lock users row %d: %v", uid, err)
	}
}

// reviewWaitForInnoDBLockWait blocks until at least one transaction is waiting
// for a lock. It is a state probe, not a fixed sleep: the test fails when no
// lock wait appears within the bound.
func reviewWaitForInnoDBLockWait(t *testing.T, db *sql.DB) {
	t.Helper()
	reviewWaitForInnoDBLockWaitOrDone(t, db, nil)
}

// reviewWaitForInnoDBLockWaitOrDone additionally fails when the goroutine that
// should be blocked returns instead of waiting for the lock.
//
// Probe note: MariaDB 10.11 keeps a transaction blocked on a plain
// "SELECT ... FOR UPDATE" row lock at TRX_STATE='RUNNING' in
// information_schema.INNODB_TRX (verified by hand with two CLI sessions), so a
// TRX_STATE='LOCK WAIT' probe never fires there. MySQL reports LOCK WAIT in the
// same column, which is why the first version of this probe looked correct.
// The portable source of truth is SHOW ENGINE INNODB STATUS: its TRANSACTIONS
// section contains "LOCK WAIT" and "TRX HAS BEEN WAITING" for the blocked
// transaction. The loop is still bounded and state-driven, not a fixed sleep.
func reviewWaitForInnoDBLockWaitOrDone(t *testing.T, db *sql.DB, done <-chan error) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		waiting, err := reviewInnoDBStatusReportsLockWait(db)
		if err != nil {
			t.Fatalf("lock-wait probe: %v", err)
		}
		if waiting {
			return
		}
		if done != nil {
			select {
			case err := <-done:
				t.Fatalf("the blocked operation returned before the lock was released: err=%v", err)
			default:
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	status, _ := reviewInnoDBTransactionsSection(db)
	t.Fatalf("no InnoDB lock wait appeared in SHOW ENGINE INNODB STATUS while a goroutine should be blocked on the account lock\nTRANSACTIONS section:\n%s\nGOROUTINES:\n%s", status, buf[:n])
}

// reviewInnoDBStatusReportsLockWait scans the TRANSACTIONS section of
// SHOW ENGINE INNODB STATUS for a blocked transaction. MariaDB adds
// "------- TRX HAS BEEN WAITING ... FOR THIS LOCK TO BE GRANTED" while MySQL
// prints "LOCK WAIT" on the transaction line; both are accepted.
func reviewInnoDBStatusReportsLockWait(db *sql.DB) (bool, error) {
	section, err := reviewInnoDBTransactionsSection(db)
	if err != nil {
		return false, err
	}
	return strings.Contains(section, "LOCK WAIT") || strings.Contains(section, "TRX HAS BEEN WAITING"), nil
}

// reviewInnoDBTransactionsSection returns the bounded TRANSACTIONS section of
// SHOW ENGINE INNODB STATUS.
func reviewInnoDBTransactionsSection(db *sql.DB) (string, error) {
	var typ, name, status string
	if err := db.QueryRow("SHOW ENGINE INNODB STATUS").Scan(&typ, &name, &status); err != nil {
		return "", err
	}
	index := strings.Index(status, "TRANSACTIONS")
	if index < 0 {
		return "no TRANSACTIONS section", nil
	}
	section := status[index:]
	if len(section) > 4000 {
		section = section[:4000]
	}
	return section, nil
}

func reviewIsDeadlock(err error) bool {
	var mysqlErr *mysql.MySQLError
	return errors.As(err, &mysqlErr) && mysqlErr.Number == 1213
}

// reviewInnoDBDeadlockSection returns the LATEST DETECTED DEADLOCK section, or a
// short note when InnoDB has not recorded one.
func reviewInnoDBDeadlockSection(t *testing.T, db *sql.DB) string {
	t.Helper()
	var typ, name, status string
	if err := db.QueryRow("SHOW ENGINE INNODB STATUS").Scan(&typ, &name, &status); err != nil {
		return fmt.Sprintf("cannot read InnoDB status: %v", err)
	}
	index := strings.Index(status, "LATEST DETECTED DEADLOCK")
	if index < 0 {
		return "no LATEST DETECTED DEADLOCK section"
	}
	lines := strings.Split(status[index:], "\n")
	var kept []string
	separators := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "----") {
			separators++
		}
		if strings.HasPrefix(line, "----") && len(kept) > 3 && separators > 2 {
			break
		}
		kept = append(kept, line)
		if len(strings.Join(kept, "\n")) > 1600 {
			break
		}
	}
	return strings.Join(kept, "\n")
}

// TestReviewConcurrentFirstTimeIssueCodeDoesNotDeadlock exercises the real
// exported entry point instead of the statement sequence: several accounts with
// no revocation row issue their first authorization code concurrently.
func TestReviewConcurrentFirstTimeIssueCodeDoesNotDeadlock(t *testing.T) {
	db := testdb.Open(t)
	svc := reviewPassport(t, db)
	ctx := context.Background()
	clientID := reviewCodeClient(t, db)
	const accounts = 8
	uids := make([]int64, 0, accounts)
	for i := 0; i < accounts; i++ {
		uids = append(uids, reviewUser(t, db, fmt.Sprintf("review-concurrent-%d@example.invalid", i)))
	}
	for round := 0; round < 3; round++ {
		start := make(chan struct{})
		errs := make(chan error, accounts)
		var wg sync.WaitGroup
		for _, uid := range uids {
			wg.Add(1)
			go func(uid int64) {
				defer wg.Done()
				<-start
				_, _, _, err := svc.IssueCode(ctx, clientID, uid, reviewRedirect, []string{"User.Read"}, "", "")
				errs <- err
			}(uid)
		}
		close(start)
		wg.Wait()
		close(errs)
		var failures []error
		for err := range errs {
			if err != nil {
				failures = append(failures, err)
			}
		}
		if len(failures) > 0 {
			deadlocks := 0
			for _, err := range failures {
				if reviewIsDeadlock(err) {
					deadlocks++
				}
			}
			t.Errorf("round %d: %d/%d first-time IssueCode calls failed (%d deadlocks): %v",
				round, len(failures), accounts, deadlocks, failures)
			if deadlocks > 0 {
				t.Logf("InnoDB LATEST DETECTED DEADLOCK:\n%s", reviewInnoDBDeadlockSection(t, db))
			}
		}
	}
	if t.Failed() {
		t.Log("finding: concurrent first-time Passport issuance for different accounts fails with InnoDB deadlocks")
	}
}

// reviewCraftCode inserts an active code row and encrypts an explicit payload.
// rawApprovedRev is a raw JSON token so wrong JSON types can be represented.
func reviewCraftCode(t *testing.T, svc *Service, uid, clientID int64, codeID string, includeApprovedRev bool, rawApprovedRev string) string {
	t.Helper()
	if err := svc.Repo().CreateAuthCode(context.Background(), AuthCodeRow{
		ID: codeID, UserID: uid, ClientID: strconv.FormatInt(clientID, 10),
		Scopes: []string{"User.Read"}, ExpiresAt: time.Now().Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("create crafted code row: %v", err)
	}
	fields := map[string]any{
		"client_id":             strconv.FormatInt(clientID, 10),
		"redirect_uri":          reviewRedirect,
		"auth_code_id":          codeID,
		"scopes":                []string{"User.Read"},
		"user_id":               uid,
		"expire_time":           time.Now().Add(5 * time.Minute).Unix(),
		"code_challenge":        "",
		"code_challenge_method": "",
	}
	if includeApprovedRev {
		fields["approved_rev"] = json.RawMessage(rawApprovedRev)
	}
	code, err := svc.encryptPayload(fields)
	if err != nil {
		t.Fatalf("encrypt crafted payload: %v", err)
	}
	return code
}

// TestReviewApprovedRevExtremeInputs checks the pointer semantics of
// approved_rev beyond the Lead's negative/string cases: integer bounds, wrong
// JSON types, an explicit null and a missing field. A missing/null field must
// still reach the native compatibility path; every Go-shaped value must be
// compared against the current generation.
func TestReviewApprovedRevExtremeInputs(t *testing.T) {
	db := testdb.Open(t)
	svc := reviewPassport(t, db)
	ctx := context.Background()
	uid := reviewUser(t, db, "review-extreme-rev@example.invalid")
	clientID := reviewCodeClient(t, db)
	if _, err := revocation.New(db, "").Ensure(ctx, uid, reviewHash, reviewSecret, time.Now()); err != nil {
		t.Fatalf("materialize baseline: %v", err)
	}
	cases := []struct {
		name         string
		include      bool
		raw          string
		wantAccepted bool
	}{
		{"max-int64", true, "9223372036854775807", false},
		{"min-int64", true, "-9223372036854775808", false},
		{"int64-overflow", true, "9223372036854775808", false},
		{"float-one", true, "1.0", false},
		{"string-one", true, `"1"`, false},
		{"empty-object", true, "{}", false},
		{"null-native-path", true, "null", true},
		{"missing-native-path", false, "", true},
	}
	client := strconv.FormatInt(clientID, 10)
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			codeID := "review-extreme-" + tc.name
			code := reviewCraftCode(t, svc, uid, clientID, codeID, tc.include, tc.raw)
			_, err := svc.ExchangeCode(ctx, code, client, "review-secret", reviewRedirect, "")
			accepted := err == nil
			if accepted != tc.wantAccepted {
				t.Fatalf("accepted=%v err=%v, want accepted=%v", accepted, err, tc.wantAccepted)
			}
			revoked, revErr := svc.Repo().AuthCodeRevoked(ctx, codeID)
			if revErr != nil {
				t.Fatalf("re-read code row: %v", revErr)
			}
			if !accepted && revoked {
				t.Fatalf("rejected code with approved_rev=%s was consumed", tc.raw)
			}
			if accepted && !revoked {
				t.Fatalf("accepted code with approved_rev=%s was not consumed", tc.raw)
			}
		})
	}
}

// TestReviewExchangeCodeUsesCurrentGenerationAfterLockWait binds the other
// ordering of the current-read fix: ExchangeCode establishes its snapshot (client
// lookup) before waiting for the account lock, and the generation advances and
// commits while it waits. The code must then be rejected as revoked.
func TestReviewExchangeCodeUsesCurrentGenerationAfterLockWait(t *testing.T) {
	db := testdb.Open(t)
	svc := reviewPassport(t, db)
	ctx := context.Background()
	uid := reviewUser(t, db, "review-exchange-wait@example.invalid")
	clientID := reviewCodeClient(t, db)
	client := strconv.FormatInt(clientID, 10)
	if _, err := revocation.New(db, "").Ensure(ctx, uid, reviewHash, reviewSecret, time.Now()); err != nil {
		t.Fatalf("materialize baseline: %v", err)
	}
	code, codeID, _, err := svc.IssueCode(ctx, clientID, uid, reviewRedirect, []string{"User.Read"}, "", "")
	if err != nil {
		t.Fatalf("issue code: %v", err)
	}

	advance, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer advance.Rollback()
	reviewLockRow(t, advance, uid)
	if err := revocation.BumpTx(ctx, advance, "", uid, reviewHash, reviewSecret, time.Now()); err != nil {
		t.Fatalf("hold the generation advance: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := svc.ExchangeCode(context.Background(), code, client, "review-secret", reviewRedirect, "")
		done <- err
	}()
	reviewWaitForInnoDBLockWaitOrDone(t, db, done)
	if err := advance.Commit(); err != nil {
		t.Fatalf("commit the generation advance: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("code approved at generation 1 was redeemed after generation 2 committed while waiting for the account lock")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("exchange did not return after the generation advance committed")
	}
	revoked, err := svc.Repo().AuthCodeRevoked(ctx, codeID)
	if err != nil {
		t.Fatalf("re-read code row: %v", err)
	}
	if revoked {
		t.Fatal("rejected exchange consumed the authorization code")
	}
}

// TestReviewIssueCodeUsesCurrentGenerationAfterLockWait is the issuance side:
// the generation advances and commits while IssueCode waits for the account
// lock. The code must carry the committed generation and remain redeemable.
func TestReviewIssueCodeUsesCurrentGenerationAfterLockWait(t *testing.T) {
	db := testdb.Open(t)
	svc := reviewPassport(t, db)
	ctx := context.Background()
	uid := reviewUser(t, db, "review-issue-wait@example.invalid")
	clientID := reviewCodeClient(t, db)
	client := strconv.FormatInt(clientID, 10)
	if _, err := revocation.New(db, "").Ensure(ctx, uid, reviewHash, reviewSecret, time.Now()); err != nil {
		t.Fatalf("materialize baseline: %v", err)
	}

	advance, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer advance.Rollback()
	reviewLockRow(t, advance, uid)
	if err := revocation.BumpTx(ctx, advance, "", uid, reviewHash, reviewSecret, time.Now()); err != nil {
		t.Fatalf("hold the generation advance: %v", err)
	}

	type issueResult struct {
		code string
		err  error
	}
	done := make(chan issueResult, 1)
	go func() {
		code, _, _, err := svc.IssueCode(context.Background(), clientID, uid, reviewRedirect, []string{"User.Read"}, "", "")
		done <- issueResult{code, err}
	}()
	reviewWaitForInnoDBLockWait(t, db)
	if err := advance.Commit(); err != nil {
		t.Fatalf("commit the generation advance: %v", err)
	}
	var issued issueResult
	select {
	case issued = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("issuance did not return after the generation advance committed")
	}
	if issued.err != nil {
		t.Fatalf("issue code after the committed advance: %v", issued.err)
	}
	var payload map[string]any
	if err := svc.decryptPayload(issued.code, &payload); err != nil {
		t.Fatalf("decrypt issued payload: %v", err)
	}
	rev, ok := payload["approved_rev"].(float64)
	if !ok || rev != 2 {
		t.Fatalf("approved_rev = %v, want 2 (generation committed while waiting for the account lock)", payload["approved_rev"])
	}
	if _, err := svc.ExchangeCode(ctx, issued.code, client, "review-secret", reviewRedirect, ""); err != nil {
		t.Fatalf("code recorded at the committed generation was rejected: %v", err)
	}
}

// TestReviewNativeShapedCodeRejectedAfterPasswordChange keeps the compatibility
// branch honest: a native-shaped code (no approved_rev) is not generation
// checked, so its rejection after a password change must come from the frozen
// row revocation and the conditional single-winner UPDATE.
func TestReviewNativeShapedCodeRejectedAfterPasswordChange(t *testing.T) {
	db := testdb.Open(t)
	svc := reviewPassport(t, db)
	ctx := context.Background()
	uid := reviewUser(t, db, "review-native-revoked@example.invalid")
	clientID := reviewCodeClient(t, db)
	client := strconv.FormatInt(clientID, 10)
	if _, err := revocation.New(db, "").Ensure(ctx, uid, reviewHash, reviewSecret, time.Now()); err != nil {
		t.Fatalf("materialize baseline: %v", err)
	}
	code := reviewCraftCode(t, svc, uid, clientID, "review-native-revoked-code", false, "")

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := registration.ChangePassword(ctx, tx, "", uid, "review-new-password", reviewSecret); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit password change: %v", err)
	}

	if _, err := svc.ExchangeCode(ctx, code, client, "review-secret", reviewRedirect, ""); err == nil {
		t.Fatal("native-shaped code was redeemed after the password change that revoked it")
	}
	revoked, err := svc.Repo().AuthCodeRevoked(ctx, "review-native-revoked-code")
	if err != nil {
		t.Fatalf("re-read code row: %v", err)
	}
	if !revoked {
		t.Fatal("password change did not revoke the native-shaped authorization code row")
	}
}
