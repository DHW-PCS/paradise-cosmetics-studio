// Focused checks for the admin reports Actor entries (M4-03),
// including the 2A non-PENDING coverage for delete/ban/reject.
// Every test needs a real database (M2_TEST_DSN); without a DSN the
// fixture skips and nothing is claimed as passed.
package reports_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"blessing-skin-go/internal/closet"
	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/reports"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/testsupport"
	"blessing-skin-go/internal/textures"
)

var (
	errFakeRevoked = errors.New("reports test: credential revoked")
	errFakeScope   = errors.New("reports test: scope not granted")
)

type fakeActor struct {
	store   *database.Store
	uid     int64
	scopes  []string
	revoked bool
}

func (a *fakeActor) UID() int64     { return a.uid }
func (a *fakeActor) Domain() string { return identity.DomainOAuth }
func (a *fakeActor) PrepareTx(context.Context, *sql.Tx) error {
	return nil
}
func (a *fakeActor) RecheckTx(ctx context.Context, tx *sql.Tx, req identity.ScopeRequirement) (*identity.User, error) {
	if a.revoked {
		return nil, errFakeRevoked
	}
	for _, want := range req.AllOf {
		if !containsScope(a.scopes, want) {
			return nil, errFakeScope
		}
	}
	if len(req.AnyOf) > 0 {
		any := false
		for _, want := range req.AnyOf {
			if containsScope(a.scopes, want) {
				any = true
				break
			}
		}
		if !any {
			return nil, errFakeScope
		}
	}
	var user identity.User
	err := tx.QueryRowContext(ctx, "SELECT uid,email,nickname,permission,verified,COALESCE(locale,''),is_dark_mode FROM "+a.store.Table("users")+" WHERE uid=?", a.uid).
		Scan(&user.UID, &user.Email, &user.Nickname, &user.Permission, &user.Verified, &user.Locale, &user.DarkMode)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errFakeRevoked
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// fakeTextureDeleter is the test double for the closet
// TextureDeleteActorTx contract: it deletes the texture row inside
// the borrowed transaction (never committing, never forging a
// BrowserSession) and records the Actor it was called with.
// Production wiring supplies *closet.Service, which implements the
// same method with the real deleteTextureInTx kernel.
type fakeTextureDeleter struct {
	store            *database.Store
	calls            int
	participantCalls int
	lockCalls        int
	lockErr          error
	lockedTx         *sql.Tx
	lastActor        identity.Actor
	lastTID          int64
}

func (f *fakeTextureDeleter) TextureDeleteParticipantsTx(ctx context.Context, tx *sql.Tx, tid int64) (string, []int64, error) {
	f.participantCalls++
	var hash string
	var uploader int64
	if err := tx.QueryRowContext(ctx, "SELECT hash,uploader FROM "+f.store.Table("textures")+" WHERE tid=?", tid).Scan(&hash, &uploader); err != nil {
		return "", nil, err
	}
	return hash, []int64{uploader}, nil
}

func (f *fakeTextureDeleter) LockTextureDeleteResourcesTx(ctx context.Context, tx *sql.Tx, tid int64) error {
	f.lockCalls++
	f.lockedTx = tx
	var locked int64
	if err := tx.QueryRowContext(ctx, "SELECT tid FROM "+f.store.Table("textures")+" WHERE tid=? FOR UPDATE", tid).Scan(&locked); err != nil {
		return err
	}
	return f.lockErr
}

func (f *fakeTextureDeleter) DeleteTextureActorTx(ctx context.Context, tx *sql.Tx, actor identity.Actor, tid int64) error {
	f.calls++
	f.lastActor = actor
	f.lastTID = tid
	if actor == nil || actor.UID() == 0 {
		return errFakeRevoked
	}
	if f.lockedTx != tx {
		return errors.New("reports test: deletion resources not locked in borrowed transaction")
	}
	_, err := tx.ExecContext(ctx, "DELETE FROM "+f.store.Table("textures")+" WHERE tid=?", tid)
	return err
}

func containsScope(scopes []string, want string) bool {
	for _, scope := range scopes {
		if scope == want || scope == "*" {
			return true
		}
	}
	return false
}

type env struct {
	service *reports.Service
	store   *database.Store
	view    *site.Service
	deleter *fakeTextureDeleter
}

func fixture(t *testing.T, modification, reward string) env {
	t.Helper()
	store, id := testsupport.Database(t, "reports-actor-")
	view := &site.Service{Store: store, Location: time.UTC, OptionSnapshot: map[string]string{
		"reporter_score_modification": modification, "reporter_reward_score": reward,
	}}
	tex := textures.New(store, id, view, t.TempDir(), time.Now)
	deleter := &fakeTextureDeleter{store: store}
	return env{service: reports.New(store, id, view, tex, deleter, time.Now), store: store, view: view, deleter: deleter}
}

func actorFor(store *database.Store, uid int64, scopes ...string) *fakeActor {
	return &fakeActor{store: store, uid: uid, scopes: scopes}
}

func seedTexture(t *testing.T, store *database.Store, tid, uploader int64) {
	t.Helper()
	if _, err := store.DB.Exec("INSERT INTO "+store.Table("textures")+" (tid,name,type,hash,size,uploader,public,upload_at) VALUES (?,?, 'steve','hash',100,?,1,NOW())", tid, "Skin", uploader); err != nil {
		t.Fatal(err)
	}
}

func seedReport(t *testing.T, store *database.Store, tid, uploader, reporter int64, status int64) int64 {
	t.Helper()
	res, err := store.DB.Exec("INSERT INTO "+store.Table("reports")+" (tid,uploader,reporter,reason,status,report_at) VALUES (?,?,?,'bad',?,NOW())", tid, uploader, reporter, status)
	if err != nil {
		t.Fatal(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func scoreOf(t *testing.T, store *database.Store, uid int64) int64 {
	t.Helper()
	var score int64
	if err := store.DB.QueryRow("SELECT score FROM "+store.Table("users")+" WHERE uid=?", uid).Scan(&score); err != nil {
		t.Fatal(err)
	}
	return score
}

func permissionOf(t *testing.T, store *database.Store, uid int64) int {
	t.Helper()
	var permission int
	if err := store.DB.QueryRow("SELECT permission FROM "+store.Table("users")+" WHERE uid=?", uid).Scan(&permission); err != nil {
		t.Fatal(err)
	}
	return permission
}

func statusOf(t *testing.T, store *database.Store, id int64) int64 {
	t.Helper()
	var status int64
	if err := store.DB.QueryRow("SELECT status FROM "+store.Table("reports")+" WHERE id=?", id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

func TestManageActorAnyOfAndPermission(t *testing.T) {
	e := fixture(t, "0", "0")
	seedTexture(t, e.store, 10, 1)
	seedReport(t, e.store, 10, 1, 2, reports.Pending)
	for _, scopes := range [][]string{{"ReportsManagement.Read"}, {"ReportsManagement.ReadWrite"}} {
		page, err := e.service.ManageActor(t.Context(), actorFor(e.store, 2, scopes...), 1, "", "http://localhost/admin/reports")
		if err != nil {
			t.Fatalf("any-of %v: %v", scopes, err)
		}
		if page.Total != 1 {
			t.Fatalf("any-of %v total=%d", scopes, page.Total)
		}
		items, ok := page.Data.([]reports.ManageItem)
		if !ok || len(items) != 1 {
			t.Fatalf("any-of %v manage items = %#v", scopes, page.Data)
		}
		// Frozen nested users serialize as full legacy-visible User
		// models (uid plus email/nickname/…), not a uid/nickname brief.
		if items[0].TextureUploader == nil || items[0].TextureUploader.UID != 1 || items[0].TextureUploader.Email != "user@example.invalid" || items[0].TextureUploader.Nickname != "User" {
			t.Fatalf("any-of %v texture_uploader = %#v", scopes, items[0].TextureUploader)
		}
		if items[0].Informer == nil || items[0].Informer.UID != 2 || items[0].Informer.Email != "admin@example.invalid" {
			t.Fatalf("any-of %v informer = %#v", scopes, items[0].Informer)
		}
	}
	if _, err := e.service.ManageActor(t.Context(), actorFor(e.store, 1, "ReportsManagement.ReadWrite"), 1, "", "http://localhost/admin/reports"); !errors.Is(err, reports.ErrNoPermission) {
		t.Fatalf("non-admin err=%v", err)
	}
	if _, err := e.service.ManageActor(t.Context(), actorFor(e.store, 2, "Player.Read"), 1, "", "http://localhost/admin/reports"); !errors.Is(err, errFakeScope) {
		t.Fatalf("wrong scope err=%v", err)
	}
}

func TestReviewActorNonPendingAllActionsChangeNothing(t *testing.T) {
	e := fixture(t, "-10", "5")
	seedTexture(t, e.store, 10, 1)
	id := seedReport(t, e.store, 10, 1, 2, reports.Resolved)
	if _, err := e.store.DB.Exec("UPDATE " + e.store.Table("users") + " SET score=100 WHERE uid=2"); err != nil {
		t.Fatal(err)
	}
	var initialVersion int64
	if err := e.store.DB.QueryRow("SELECT version FROM " + e.store.Table("go_auth_versions") + " WHERE user_uid=1").Scan(&initialVersion); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"delete", "ban", "reject"} {
		result, err := e.service.ReviewActor(t.Context(), actorFor(e.store, 2, "ReportsManagement.ReadWrite"), id, action)
		if err != nil {
			t.Fatalf("%s non-pending: %v", action, err)
		}
		if result.Status != reports.Resolved {
			t.Fatalf("%s non-pending status=%d", action, result.Status)
		}
		if scoreOf(t, e.store, 2) != 100 {
			t.Fatalf("%s changed reporter score to %d", action, scoreOf(t, e.store, 2))
		}
		if permissionOf(t, e.store, 1) != 0 {
			t.Fatalf("%s changed uploader permission to %d", action, permissionOf(t, e.store, 1))
		}
		var textures int
		if err := e.store.DB.QueryRow("SELECT COUNT(*) FROM " + e.store.Table("textures") + " WHERE tid=10").Scan(&textures); err != nil {
			t.Fatal(err)
		}
		if textures != 1 {
			t.Fatalf("%s removed the texture", action)
		}
		if statusOf(t, e.store, id) != reports.Resolved {
			t.Fatalf("%s changed report status", action)
		}
		var version int64
		var modified time.Time
		var outbox int
		if err := e.store.DB.QueryRow("SELECT version FROM " + e.store.Table("go_auth_versions") + " WHERE user_uid=1").Scan(&version); err != nil {
			t.Fatal(err)
		}
		if err := e.store.DB.QueryRow("SELECT last_modified FROM " + e.store.Table("players") + " WHERE uid=1").Scan(&modified); err != nil {
			t.Fatal(err)
		}
		if err := e.store.DB.QueryRow("SELECT COUNT(*) FROM " + e.store.Table("go_outbox")).Scan(&outbox); err != nil {
			t.Fatal(err)
		}
		if version != initialVersion || modified.Year() != 2020 || outbox != 0 || e.deleter.calls != 0 {
			t.Fatalf("%s wrote non-pending state: version=%d modified=%v outbox=%d deletes=%d", action, version, modified, outbox, e.deleter.calls)
		}
	}
	// Resource changes must not turn an already-reviewed report into a
	// failure; operational errors must not be hidden by the no-op either.
	for _, lockErr := range []error{closet.ErrNotFound, closet.ErrConflict} {
		e.deleter.lockErr = lockErr
		result, err := e.service.ReviewActor(t.Context(), actorFor(e.store, 2, "ReportsManagement.ReadWrite"), id, "delete")
		if err != nil || result.Status != reports.Resolved || e.deleter.calls != 0 || scoreOf(t, e.store, 2) != 100 {
			t.Fatalf("non-pending with %v: result=%+v deletes=%d err=%v", lockErr, result, e.deleter.calls, err)
		}
	}
	errLock := errors.New("reports test: resource SQL failure")
	e.deleter.lockErr = errLock
	if _, err := e.service.ReviewActor(t.Context(), actorFor(e.store, 2, "ReportsManagement.ReadWrite"), id, "delete"); !errors.Is(err, errLock) {
		t.Fatalf("non-pending resource SQL failure err=%v", err)
	}
}

func TestReviewActorPendingRejectBanAndDeleteMissingTexture(t *testing.T) {
	// Reject: suspended score is deducted, no reward.
	e := fixture(t, "10", "5")
	seedTexture(t, e.store, 10, 1)
	rejectID := seedReport(t, e.store, 10, 1, 2, reports.Pending)
	if _, err := e.store.DB.Exec("UPDATE " + e.store.Table("users") + " SET score=100 WHERE uid=2"); err != nil {
		t.Fatal(err)
	}
	result, err := e.service.ReviewActor(t.Context(), actorFor(e.store, 2, "ReportsManagement.ReadWrite"), rejectID, "reject")
	if err != nil || result.Status != reports.Rejected || scoreOf(t, e.store, 2) != 90 {
		t.Fatalf("reject result=%+v score=%d err=%v", result, scoreOf(t, e.store, 2), err)
	}
	// Ban: uploader banned, suspended score returned plus reward.
	e2 := fixture(t, "-10", "5")
	seedTexture(t, e2.store, 10, 1)
	banID := seedReport(t, e2.store, 10, 1, 2, reports.Pending)
	if _, err := e2.store.DB.Exec("UPDATE " + e2.store.Table("users") + " SET score=100 WHERE uid=2"); err != nil {
		t.Fatal(err)
	}
	result, err = e2.service.ReviewActor(t.Context(), actorFor(e2.store, 2, "ReportsManagement.ReadWrite"), banID, "ban")
	if err != nil || result.Status != reports.Resolved || scoreOf(t, e2.store, 2) != 115 || permissionOf(t, e2.store, 1) != -1 {
		t.Fatalf("ban result=%+v score=%d permission=%d err=%v", result, scoreOf(t, e2.store, 2), permissionOf(t, e2.store, 1), err)
	}
	var modified time.Time
	var version int64
	if err := e2.store.DB.QueryRow("SELECT last_modified FROM " + e2.store.Table("players") + " WHERE uid=1").Scan(&modified); err != nil {
		t.Fatal(err)
	}
	if err := e2.store.DB.QueryRow("SELECT version FROM " + e2.store.Table("go_auth_versions") + " WHERE user_uid=1").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if modified.Year() == 2020 || version != 2 {
		t.Fatalf("ban did not update player timestamp and revoke: modified=%v version=%d", modified, version)
	}
	// Delete with the texture already gone: score returned, no reward,
	// and no closet Actor Tx is needed.
	e3 := fixture(t, "-10", "5")
	deleteID := seedReport(t, e3.store, 999, 1, 2, reports.Pending)
	if _, err := e3.store.DB.Exec("UPDATE " + e3.store.Table("users") + " SET score=100 WHERE uid=2"); err != nil {
		t.Fatal(err)
	}
	result, err = e3.service.ReviewActor(t.Context(), actorFor(e3.store, 2, "ReportsManagement.ReadWrite"), deleteID, "delete")
	if e3.deleter.calls != 0 || e3.deleter.participantCalls != 0 || e3.deleter.lockCalls != 0 {
		t.Fatalf("deleter calls=%d participants=%d locks=%d for missing texture", e3.deleter.calls, e3.deleter.participantCalls, e3.deleter.lockCalls)
	}
	if err != nil || result.Status != reports.Resolved || !result.TextureAlreadyDeleted || scoreOf(t, e3.store, 2) != 110 {
		t.Fatalf("delete-missing result=%+v score=%d err=%v", result, scoreOf(t, e3.store, 2), err)
	}
}

func TestReviewActorDeleteExistingTextureUsesClosetActorTx(t *testing.T) {
	e := fixture(t, "-10", "5")
	seedTexture(t, e.store, 10, 1)
	id := seedReport(t, e.store, 10, 1, 2, reports.Pending)
	if _, err := e.store.DB.Exec("UPDATE " + e.store.Table("users") + " SET score=100 WHERE uid=2"); err != nil {
		t.Fatal(err)
	}
	result, err := e.service.ReviewActor(t.Context(), actorFor(e.store, 2, "ReportsManagement.ReadWrite"), id, "delete")
	if err != nil || result.Status != reports.Resolved || result.TextureAlreadyDeleted {
		t.Fatalf("delete result=%+v err=%v", result, err)
	}
	if e.deleter.calls != 1 || e.deleter.participantCalls != 1 || e.deleter.lockCalls != 1 || e.deleter.lastTID != 10 || e.deleter.lastActor == nil || e.deleter.lastActor.UID() != 2 {
		t.Fatalf("deleter calls=%d participants=%d locks=%d tid=%d actor=%v", e.deleter.calls, e.deleter.participantCalls, e.deleter.lockCalls, e.deleter.lastTID, e.deleter.lastActor)
	}
	var textures int
	if err := e.store.DB.QueryRow("SELECT COUNT(*) FROM " + e.store.Table("textures") + " WHERE tid=10").Scan(&textures); err != nil {
		t.Fatal(err)
	}
	if textures != 0 {
		t.Fatal("texture still present after delete")
	}
	// Suspended score returned plus reward, in the same transaction.
	if scoreOf(t, e.store, 2) != 115 {
		t.Fatalf("reporter score=%d, want 115", scoreOf(t, e.store, 2))
	}
	if statusOf(t, e.store, id) != reports.Resolved {
		t.Fatal("report not resolved after delete")
	}
}

func TestReviewActorDeleteResourceLockFailureRollsBack(t *testing.T) {
	e := fixture(t, "-10", "5")
	seedTexture(t, e.store, 10, 1)
	id := seedReport(t, e.store, 10, 1, 2, reports.Pending)
	beforeScore := scoreOf(t, e.store, 2)
	errLock := errors.New("reports test: resource lock failed")
	e.deleter.lockErr = errLock
	if _, err := e.service.ReviewActor(t.Context(), actorFor(e.store, 2, "ReportsManagement.ReadWrite"), id, "delete"); !errors.Is(err, errLock) {
		t.Fatalf("resource lock failure err=%v", err)
	}
	if e.deleter.lockCalls != 1 || e.deleter.calls != 0 || statusOf(t, e.store, id) != reports.Pending || scoreOf(t, e.store, 2) != beforeScore {
		t.Fatal("resource lock failure changed report or score, or ran deletion")
	}
	var count int
	if err := e.store.DB.QueryRow("SELECT COUNT(*) FROM " + e.store.Table("textures") + " WHERE tid=10").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("resource lock failure deleted texture")
	}
}

func TestReviewActorDemotionRevokedAndBanRollback(t *testing.T) {
	e := fixture(t, "-10", "5")
	seedTexture(t, e.store, 10, 1)
	id := seedReport(t, e.store, 10, 1, 2, reports.Pending)
	if _, err := e.store.DB.Exec("UPDATE " + e.store.Table("users") + " SET permission=0 WHERE uid=2"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.service.ReviewActor(t.Context(), actorFor(e.store, 2, "ReportsManagement.ReadWrite"), id, "reject"); !errors.Is(err, reports.ErrNoPermission) {
		t.Fatalf("demoted err=%v", err)
	}
	if _, err := e.store.DB.Exec("UPDATE " + e.store.Table("users") + " SET permission=2 WHERE uid=2"); err != nil {
		t.Fatal(err)
	}
	revoked := actorFor(e.store, 2, "ReportsManagement.ReadWrite")
	revoked.revoked = true
	if _, err := e.service.ReviewActor(t.Context(), revoked, id, "reject"); !errors.Is(err, errFakeRevoked) {
		t.Fatalf("revoked err=%v", err)
	}
	// Ban rollback: an uploader who outranks the actor cannot be
	// banned; the report and scores stay unchanged.
	if _, err := e.store.DB.Exec("INSERT INTO " + e.store.Table("users") + " (uid,email,nickname,password,permission,verified,score) VALUES (3,'third@example.invalid','Third','x',2,1,0)"); err != nil {
		t.Fatal(err)
	}
	highID := seedReport(t, e.store, 10, 3, 2, reports.Pending)
	if _, err := e.service.ReviewActor(t.Context(), actorFor(e.store, 2, "ReportsManagement.ReadWrite"), highID, "ban"); !errors.Is(err, reports.ErrBanOutranking) {
		t.Fatalf("ban outranking uploader err=%v", err)
	}
	if statusOf(t, e.store, highID) != reports.Pending || permissionOf(t, e.store, 3) != 2 {
		t.Fatal("failed ban changed state")
	}
	// Failure at the report write rolls back the preceding ban,
	// revocation, timestamp and score writes in the same transaction.
	beforeScore := scoreOf(t, e.store, 2)
	if _, err := e.store.DB.Exec("CREATE TRIGGER reject_review BEFORE UPDATE ON " + e.store.Table("reports") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic report write failure'"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.service.ReviewActor(t.Context(), actorFor(e.store, 2, "ReportsManagement.ReadWrite"), id, "ban"); err == nil {
		t.Fatal("injected report write failure was not returned")
	}
	var modified time.Time
	var version int64
	if err := e.store.DB.QueryRow("SELECT last_modified FROM " + e.store.Table("players") + " WHERE uid=1").Scan(&modified); err != nil {
		t.Fatal(err)
	}
	if err := e.store.DB.QueryRow("SELECT version FROM " + e.store.Table("go_auth_versions") + " WHERE user_uid=1").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if statusOf(t, e.store, id) != reports.Pending || permissionOf(t, e.store, 1) != 0 || scoreOf(t, e.store, 2) != beforeScore || modified.Year() != 2020 || version != 1 {
		t.Fatalf("failed ban leaked writes: modified=%v version=%d", modified, version)
	}
}
