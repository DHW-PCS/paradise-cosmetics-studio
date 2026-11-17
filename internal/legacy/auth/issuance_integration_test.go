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

	"paradise-cosmetics-studio/internal/legacy/password"
	"paradise-cosmetics-studio/internal/legacy/revocation"
	"paradise-cosmetics-studio/internal/legacy/session"
	"paradise-cosmetics-studio/internal/legacy/testdb"
	"paradise-cosmetics-studio/internal/legacy/users"
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

// TestKeepLoginReusesExistingRememberToken covers R07: SessionGuard::
// ensureRememberTokenIsSet only creates a token when the account has none, so a
// second keep login must report and reuse the committed token instead of
// rotating it and invalidating the first device's recaller.
func TestKeepLoginReusesExistingRememberToken(t *testing.T) {
	db := testdb.Open(t)
	svc := newService(t, db)
	ctx := context.Background()
	uid := seedUser(t, db, "reuse@example.invalid", "old-password-1", "existing-token")

	result, err := svc.Login(ctx, "reuse@example.invalid", "old-password-1", true)
	if err != nil {
		t.Fatalf("keep login failed: %v", err)
	}
	if result.Remember != "existing-token" {
		t.Fatalf("LoginResult.Remember = %q, want the committed token", result.Remember)
	}
	if result.User.RememberToken != result.Remember {
		t.Fatalf("result user token = %q, remember = %q; the caller would encode a different value",
			result.User.RememberToken, result.Remember)
	}
	if got := storedRememberToken(t, db, uid); got != "existing-token" {
		t.Fatalf("users.remember_token = %q after a keep login, want the committed token", got)
	}
	if _, _, err := svc.RememberState(ctx, uid, "existing-token"); err != nil {
		t.Fatalf("the first device's recaller no longer validates: %v", err)
	}
}

// TestKeepLoginReuseNeedsNoRememberTokenWrite proves the reuse path is really
// conditional: with an existing token, a keep login must not touch users at all,
// so a failing remember-token write cannot break it.
func TestKeepLoginReuseNeedsNoRememberTokenWrite(t *testing.T) {
	db := testdb.Open(t)
	svc := newService(t, db)
	ctx := context.Background()
	uid := seedUser(t, db, "nowrite@example.invalid", "old-password-1", "existing-token")
	installUserUpdateFailure(t, db)

	result, err := svc.Login(ctx, "nowrite@example.invalid", "old-password-1", true)
	if err != nil {
		t.Fatalf("keep login with an existing token performed a users write: %v", err)
	}
	if result.Remember != "existing-token" {
		t.Fatalf("LoginResult.Remember = %q, want the committed token", result.Remember)
	}
	if got := storedRememberToken(t, db, uid); got != "existing-token" {
		t.Fatalf("users.remember_token = %q after the failed write path", got)
	}
}

// TestKeepLoginCreatesRememberTokenWhenEmpty is the other half of the frozen
// rule: an account without a token gets one, and later keep logins reuse it.
func TestKeepLoginCreatesRememberTokenWhenEmpty(t *testing.T) {
	db := testdb.Open(t)
	svc := newService(t, db)
	ctx := context.Background()
	uid := seedUser(t, db, "create@example.invalid", "old-password-1", "")

	first, err := svc.Login(ctx, "create@example.invalid", "old-password-1", true)
	if err != nil {
		t.Fatalf("first keep login failed: %v", err)
	}
	if len(first.Remember) != 60 {
		t.Fatalf("remember token length = %d, want 60", len(first.Remember))
	}
	if first.User.RememberToken != first.Remember {
		t.Fatalf("result user token = %q, remember = %q", first.User.RememberToken, first.Remember)
	}
	if got := storedRememberToken(t, db, uid); got != first.Remember {
		t.Fatalf("users.remember_token = %q, want the issued token", got)
	}

	second, err := svc.Login(ctx, "create@example.invalid", "old-password-1", true)
	if err != nil {
		t.Fatalf("second keep login failed: %v", err)
	}
	if second.Remember != first.Remember {
		t.Fatalf("second keep login rotated the token: %q -> %q", first.Remember, second.Remember)
	}
	if _, _, err := svc.RememberState(ctx, uid, first.Remember); err != nil {
		t.Fatalf("the first device's recaller no longer validates: %v", err)
	}
}

// TestNonKeepLoginLeavesRememberToken keeps the frozen rule that remember=false
// does not create, rotate or clear the recaller token.
func TestNonKeepLoginLeavesRememberToken(t *testing.T) {
	db := testdb.Open(t)
	svc := newService(t, db)
	ctx := context.Background()
	uid := seedUser(t, db, "nokeep@example.invalid", "old-password-1", "existing-token")

	result, err := svc.Login(ctx, "nokeep@example.invalid", "old-password-1", false)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if result.Remember != "" {
		t.Fatalf("non-keep login reported remember token %q", result.Remember)
	}
	if got := storedRememberToken(t, db, uid); got != "existing-token" {
		t.Fatalf("users.remember_token = %q after a non-keep login", got)
	}
	if _, _, err := svc.RememberState(ctx, uid, "existing-token"); err != nil {
		t.Fatalf("non-keep login invalidated an existing recaller: %v", err)
	}
}

// TestConcurrentFirstKeepLoginSharesOneToken checks that simultaneous first keep
// logins serialize on the users row and converge on one token all of them can
// report and validate.
func TestConcurrentFirstKeepLoginSharesOneToken(t *testing.T) {
	db := testdb.Open(t)
	svc := newService(t, db)
	ctx := context.Background()
	uid := seedUser(t, db, "concurrent-keep@example.invalid", "old-password-1", "")

	// Initialize the revocation state first so this test isolates the remember
	// token decision from first-state initialization.
	user, found, err := svc.Repo.ByUID(ctx, uid)
	if err != nil || !found {
		t.Fatalf("load user: %v %v", found, err)
	}
	if _, err := svc.EnsureState(ctx, uid, user.Password); err != nil {
		t.Fatalf("initialize revocation state: %v", err)
	}

	const callers = 8
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	tokens := make(chan string, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := svc.Login(ctx, "concurrent-keep@example.invalid", "old-password-1", true)
			if err != nil {
				errs <- err
				return
			}
			tokens <- result.Remember
		}()
	}
	wg.Wait()
	close(errs)
	close(tokens)
	for err := range errs {
		t.Fatalf("concurrent keep login failed: %v", err)
	}
	var token string
	for got := range tokens {
		if token == "" {
			token = got
			continue
		}
		if got != token {
			t.Fatalf("concurrent keep logins reported different tokens: %q and %q", token, got)
		}
	}
	if token == "" {
		t.Fatal("no keep login reported a token")
	}
	if stored := storedRememberToken(t, db, uid); stored != token {
		t.Fatalf("users.remember_token = %q, all logins reported %q", stored, token)
	}
	if _, _, err := svc.RememberState(ctx, uid, token); err != nil {
		t.Fatalf("the shared token does not validate: %v", err)
	}
}

// storedRememberToken reads the committed value, treating NULL as empty.
func storedRememberToken(t *testing.T, db *sql.DB, uid int64) string {
	t.Helper()
	var token string
	if err := db.QueryRow("SELECT COALESCE(remember_token,'') FROM users WHERE uid=?", uid).Scan(&token); err != nil {
		t.Fatalf("read remember token: %v", err)
	}
	return token
}

// installUserUpdateFailure makes any UPDATE on users fail so a test can prove a
// path performs no write. The trigger dies with the disposable test database.
func installUserUpdateFailure(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`CREATE TRIGGER m1_fail_remember BEFORE UPDATE ON users
		FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'm1 remember write'`); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}
}
