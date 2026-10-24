package auth

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"

	"blessing-skin-go/internal/legacy/password"
	"blessing-skin-go/internal/legacy/revocation"
	"blessing-skin-go/internal/legacy/session"
	"blessing-skin-go/internal/legacy/testdb"
	"blessing-skin-go/internal/legacy/users"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func newService(t *testing.T, db *sql.DB) *Service {
	t.Helper()
	hasher, err := password.New("BCRYPT", "")
	if err != nil {
		t.Fatal(err)
	}
	return &Service{
		Repo:     users.New(db, ""),
		Rev:      revocation.New(db, ""),
		Hasher:   hasher,
		Secret:   testSecret,
		LoginKey: "login_web_test",
	}
}

// requireAccountLock asserts that uid's row is held by another transaction.
// The NOWAIT probe fails only when a real lock exists, so this is a direct
// observation rather than a guess about scheduling.
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

func hashPassword(t *testing.T, raw string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(hash)
}

func seedUser(t *testing.T, db *sql.DB, email, raw, remember string) int64 {
	t.Helper()
	result, err := db.Exec(`INSERT INTO users(email,nickname,password,permission,verified,remember_token)
		VALUES(?,?,?,0,1,?)`, email, "Nick", hashPassword(t, raw), remember)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO players(uid,name) VALUES(?,?)", uid, "Player"+email); err != nil {
		t.Fatal(err)
	}
	return uid
}

// TestStaleVerificationCannotObtainNewVersion reproduces R01's root cause: a
// credential verified before a password change must not be stamped with the
// version created by that change.
func TestStaleVerificationCannotObtainNewVersion(t *testing.T) {
	db := testdb.Open(t)
	svc := newService(t, db)
	ctx := context.Background()
	uid := seedUser(t, db, "stale@example.invalid", "old-password-1", "")

	// The old hash is what a login would have verified before the change.
	user, found, err := svc.Repo.ByUID(ctx, uid)
	if err != nil || !found {
		t.Fatalf("load user: %v %v", found, err)
	}
	verifiedHash := user.Password

	newHash := hashPassword(t, "new-password-1")
	if _, err := db.Exec("UPDATE users SET password=? WHERE uid=?", newHash, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Rev.Bump(ctx, uid, newHash, testSecret, time.Now()); err != nil {
		t.Fatal(err)
	}

	state, err := svc.EnsureState(ctx, uid, verifiedHash)
	if err == nil {
		t.Fatalf("stale verification was upgraded to session version %d", state.SessionVersion)
	}
	if !errors.Is(err, ErrStaleCredential) {
		t.Fatalf("error = %v, want ErrStaleCredential", err)
	}
}

// TestLoginHoldsAccountLockAcrossIssuance pauses login inside its transaction
// after the password matched, then checks that the account row is really locked,
// that a concurrent password change cannot commit, and that the session it
// issued is rejected once the change lands.
func TestLoginHoldsAccountLockAcrossIssuance(t *testing.T) {
	db := testdb.Open(t)
	svc := newService(t, db)
	ctx := context.Background()
	uid := seedUser(t, db, "race@example.invalid", "old-password-1", "")
	newHash := hashPassword(t, "new-password-1")

	verified := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseLogin := func() { releaseOnce.Do(func() { close(release) }) }
	svc.afterVerify = func() {
		close(verified)
		<-release
	}

	type outcome struct {
		result *LoginResult
		err    error
	}
	done := make(chan outcome, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		result, err := svc.Login(ctx, "race@example.invalid", "old-password-1", false)
		done <- outcome{result, err}
	}()
	// A failed assertion must not leave the account transaction open: it would
	// block the warm-down drop of the test database.
	t.Cleanup(func() {
		releaseLogin()
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
		if _, err := tx.Exec("UPDATE users SET password=? WHERE uid=?", newHash, uid); err != nil {
			changeDone <- err
			return
		}
		changeDone <- tx.Commit()
	}()
	select {
	case err := <-changeDone:
		t.Fatalf("password change committed while login held the account lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	releaseLogin()
	got := <-done
	if got.err != nil {
		t.Fatalf("login failed: %v", got.err)
	}
	if err := <-changeDone; err != nil {
		t.Fatalf("password change: %v", err)
	}
	payload := svc.WritePayload(got.result.User, got.result.State, "csrf", "")
	if _, err := svc.ValidateSession(ctx, payload); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("session issued before the change survived it: %v", err)
	}
}

// TestOldRecallerRejectedAfterRotation covers the remember half of R01.
func TestOldRecallerRejectedAfterRotation(t *testing.T) {
	db := testdb.Open(t)
	svc := newService(t, db)
	ctx := context.Background()
	uid := seedUser(t, db, "remember@example.invalid", "old-password-1", "old-token")

	user, state, err := svc.RememberState(ctx, uid, "old-token")
	if err != nil {
		t.Fatalf("valid recaller rejected: %v", err)
	}
	payload := svc.WritePayload(user, state, "csrf", "")

	if _, _, err := svc.RevokeSessions(ctx, uid); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.RememberState(ctx, uid, "old-token"); !errors.Is(err, ErrRememberRejected) {
		t.Fatalf("rotated recaller error = %v, want ErrRememberRejected", err)
	}
	if _, err := svc.ValidateSession(ctx, payload); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("pre-revocation session error = %v, want ErrStaleSession", err)
	}
}

// TestRememberStateHoldsAccountLock covers the remember half of R01: the
// recaller check holds the account row, a concurrent global revocation cannot
// commit early, and the state it returned is rejected after that revocation.
func TestRememberStateHoldsAccountLock(t *testing.T) {
	db := testdb.Open(t)
	svc := newService(t, db)
	ctx := context.Background()
	uid := seedUser(t, db, "remember-race@example.invalid", "old-password-1", "old-token")

	verified := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseCheck := func() { releaseOnce.Do(func() { close(release) }) }
	svc.afterVerify = func() {
		close(verified)
		<-release
	}

	type outcome struct {
		user  *users.User
		state *revocation.State
		err   error
	}
	done := make(chan outcome, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		user, state, err := svc.RememberState(ctx, uid, "old-token")
		done <- outcome{user, state, err}
	}()
	t.Cleanup(func() {
		releaseCheck()
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
		}
	})
	<-verified
	requireAccountLock(t, db, uid)

	revokeDone := make(chan error, 1)
	go func() {
		_, _, err := svc.RevokeSessions(ctx, uid)
		revokeDone <- err
	}()
	select {
	case err := <-revokeDone:
		t.Fatalf("revocation committed while the recaller check held the account lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	releaseCheck()
	got := <-done
	if got.err != nil {
		t.Fatalf("remember check failed: %v", got.err)
	}
	if err := <-revokeDone; err != nil {
		t.Fatalf("revocation: %v", err)
	}
	payload := svc.WritePayload(got.user, got.state, "csrf", "")
	if _, err := svc.ValidateSession(ctx, payload); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("restored session survived the revocation: %v", err)
	}
	if _, _, err := svc.RememberState(ctx, uid, "old-token"); !errors.Is(err, ErrRememberRejected) {
		t.Fatalf("rotated recaller error = %v, want ErrRememberRejected", err)
	}
}

// TestRevokeSessionsIsAtomic makes the remember rotation fail and proves the
// version bump rolls back with it.
func TestRevokeSessionsIsAtomic(t *testing.T) {
	db := testdb.Open(t)
	svc := newService(t, db)
	ctx := context.Background()
	uid := seedUser(t, db, "atomic@example.invalid", "old-password-1", "old-token")

	if _, err := db.Exec(`CREATE TRIGGER m1_fail_remember BEFORE UPDATE ON users
		FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'm1 failure'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.RevokeSessions(ctx, uid); err == nil {
		t.Fatal("revocation reported success while the remember rotation failed")
	}
	before, err := svc.Rev.Get(ctx, uid)
	if err != nil {
		if !errors.Is(err, revocation.ErrNoState) {
			t.Fatal(err)
		}
	} else if before.SessionVersion != 1 {
		t.Fatalf("session version = %d after a rolled-back revocation, want 1", before.SessionVersion)
	}
	var remember string
	if err := db.QueryRow("SELECT COALESCE(remember_token,'') FROM users WHERE uid=?", uid).Scan(&remember); err != nil {
		t.Fatal(err)
	}
	if remember != "old-token" {
		t.Fatalf("remember token = %q after a rolled-back revocation", remember)
	}
}

// TestConcurrentFirstStateIsSafe covers the first-initialization race.
func TestConcurrentFirstStateIsSafe(t *testing.T) {
	db := testdb.Open(t)
	svc := newService(t, db)
	ctx := context.Background()
	uid := seedUser(t, db, "init@example.invalid", "old-password-1", "")
	user, _, err := svc.Repo.ByUID(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}

	const callers = 8
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	versions := make(chan int64, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			state, err := svc.EnsureState(ctx, uid, user.Password)
			if err != nil {
				errs <- err
				return
			}
			versions <- state.SessionVersion
		}()
	}
	wg.Wait()
	close(errs)
	close(versions)
	for err := range errs {
		t.Fatalf("concurrent EnsureState failed: %v", err)
	}
	for version := range versions {
		if version != 1 {
			t.Fatalf("session version = %d, want 1", version)
		}
	}
}

// TestWrittenPayloadRoundTrip keeps the session encoding contract intact.
func TestWrittenPayloadRoundTrip(t *testing.T) {
	db := testdb.Open(t)
	svc := newService(t, db)
	ctx := context.Background()
	uid := seedUser(t, db, "roundtrip@example.invalid", "old-password-1", "")
	user, _, err := svc.Repo.ByUID(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	state, err := svc.EnsureState(ctx, uid, user.Password)
	if err != nil {
		t.Fatal(err)
	}
	attrs := session.NewPayload(svc.LoginKey, uid, "csrf", "")
	svc.WriteGoAuth(attrs, uid, state)
	validation, err := svc.ValidateSession(ctx, attrs)
	if err != nil || validation.User.UID != uid {
		t.Fatalf("round trip failed: %v", err)
	}
}
