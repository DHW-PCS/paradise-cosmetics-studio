// Focused checks for the notifications Actor entries (M4-03).
// Every test needs a real database (M2_TEST_DSN); without a DSN the
// fixture skips and nothing is claimed as passed.
package notifications_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/notifications"
	"blessing-skin-go/internal/testsupport"
)

var (
	errFakeRevoked = errors.New("notifications test: credential revoked")
	errFakeScope   = errors.New("notifications test: scope not granted")
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

func containsScope(scopes []string, want string) bool {
	for _, scope := range scopes {
		if scope == want || scope == "*" {
			return true
		}
	}
	return false
}

func fixture(t *testing.T) (*notifications.Service, *database.Store) {
	t.Helper()
	store, _ := testsupport.Database(t, "notify-actor-")
	return notifications.New(store, time.Now), store
}

func actorFor(store *database.Store, uid int64, scopes ...string) *fakeActor {
	return &fakeActor{store: store, uid: uid, scopes: scopes}
}

func seedNotification(t *testing.T, store *database.Store, id string, uid int64) {
	t.Helper()
	if _, err := store.DB.Exec("INSERT INTO "+store.Table("notifications")+" (id,notifiable_type,notifiable_id,data,created_at) VALUES (?,?,?,?,?)", id, "App\\Models\\User", uid, `{"title":"Hello","content":"Body"}`, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func countNotifications(t *testing.T, store *database.Store, uid int64) int {
	t.Helper()
	var count int
	if err := store.DB.QueryRow("SELECT COUNT(*) FROM "+store.Table("notifications")+" WHERE notifiable_id=?", uid).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestUnreadAndReadActorOwnOnly(t *testing.T) {
	s, store := fixture(t)
	seedNotification(t, store, "11111111-1111-4111-8111-111111111111", 1)
	seedNotification(t, store, "22222222-2222-4222-8222-222222222222", 2)
	list, err := s.UnreadActor(t.Context(), actorFor(store, 1, "Notification.Read"))
	if err != nil || len(list) != 1 || list[0].ID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("unread = %v err=%v", list, err)
	}
	// Cross-user read is not found and does not mark the row read.
	if _, err := s.ReadActor(t.Context(), actorFor(store, 1, "Notification.Read"), "22222222-2222-4222-8222-222222222222"); !errors.Is(err, notifications.ErrNotFound) {
		t.Fatalf("cross-user read err=%v", err)
	}
	var readAt sql.NullTime
	if err := store.DB.QueryRow("SELECT read_at FROM " + store.Table("notifications") + " WHERE id='22222222-2222-4222-8222-222222222222'").Scan(&readAt); err != nil {
		t.Fatal(err)
	}
	if readAt.Valid {
		t.Fatal("cross-user read marked the notification read")
	}
	read, err := s.ReadActor(t.Context(), actorFor(store, 1, "Notification.Read"), "11111111-1111-4111-8111-111111111111")
	if err != nil || read.Title != "Hello" || read.Content != "<p>Body</p>\n" {
		t.Fatalf("read = %+v err=%v", read, err)
	}
	if _, err := s.UnreadActor(t.Context(), actorFor(store, 1, "Notification.ReadWrite")); !errors.Is(err, errFakeScope) {
		t.Fatalf("readwrite-only unread err=%v", err)
	}
}

func TestReadReturnsGFMHTML(t *testing.T) {
	const source = "~~old~~ **new**\n\n[Details](https://example.invalid)\n\n<span>Raw HTML</span>\n"
	const want = "<p><del>old</del> <strong>new</strong></p>\n<p><a href=\"https://example.invalid\">Details</a></p>\n<p><span>Raw HTML</span></p>\n"
	for _, entry := range []string{"browser", "actor"} {
		t.Run(entry, func(t *testing.T) {
			s, store := fixture(t)
			const id = "33333333-3333-4333-8333-333333333333"
			createdAt := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
			data, err := json.Marshal(map[string]string{"title": "Notice", "content": source})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.DB.Exec("INSERT INTO "+store.Table("notifications")+" (id,notifiable_type,notifiable_id,data,created_at) VALUES (?,?,?,?,?)", id, "App\\Models\\User", 1, string(data), createdAt); err != nil {
				t.Fatal(err)
			}
			var read *notifications.Read
			if entry == "browser" {
				read, err = s.Read(t.Context(), 1, id)
			} else {
				read, err = s.ReadActor(t.Context(), actorFor(store, 1, "Notification.Read"), id)
			}
			if err != nil {
				t.Fatal(err)
			}
			if read.Title != "Notice" || read.Content != want || read.Time != "2026-11-04 12:00:00" {
				t.Fatalf("read = %+v, want GFM HTML %q", read, want)
			}
			var stored string
			var readAt sql.NullTime
			if err := store.DB.QueryRow("SELECT data,read_at FROM "+store.Table("notifications")+" WHERE id=?", id).Scan(&stored, &readAt); err != nil {
				t.Fatal(err)
			}
			if stored != string(data) || !readAt.Valid {
				t.Fatalf("read changed stored Markdown or did not mark read: data=%q read_at=%v", stored, readAt)
			}
		})
	}
}

func TestSendActorAdminReceiverAndRollback(t *testing.T) {
	s, store := fixture(t)
	admin := actorFor(store, 2, "Notification.ReadWrite")
	if err := s.SendActor(t.Context(), admin, notifications.SendInput{Receiver: "uid", UID: "1", Title: "Notice", Content: "Hi"}); err != nil {
		t.Fatal(err)
	}
	if countNotifications(t, store, 1) != 1 || countNotifications(t, store, 2) != 0 {
		t.Fatalf("uid send counts uid1=%d uid2=%d", countNotifications(t, store, 1), countNotifications(t, store, 2))
	}
	// Scoped non-admin is forbidden and inserts nothing.
	if err := s.SendActor(t.Context(), actorFor(store, 1, "Notification.ReadWrite"), notifications.SendInput{Receiver: "all", Title: "X"}); !errors.Is(err, notifications.ErrNoPermission) {
		t.Fatalf("non-admin send err=%v", err)
	}
	if countNotifications(t, store, 1) != 1 {
		t.Fatal("forbidden send inserted a notification")
	}
	// Wrong scope inserts nothing.
	if err := s.SendActor(t.Context(), actorFor(store, 2, "Notification.Read"), notifications.SendInput{Receiver: "all", Title: "X"}); !errors.Is(err, errFakeScope) {
		t.Fatalf("wrong scope send err=%v", err)
	}
	// Revoked credential inserts nothing (rollback, not a partial send).
	revoked := actorFor(store, 2, "Notification.ReadWrite")
	revoked.revoked = true
	if err := s.SendActor(t.Context(), revoked, notifications.SendInput{Receiver: "all", Title: "X"}); !errors.Is(err, errFakeRevoked) {
		t.Fatalf("revoked send err=%v", err)
	}
	if countNotifications(t, store, 1) != 1 || countNotifications(t, store, 2) != 0 {
		t.Fatal("revoked send inserted a notification")
	}
	// Broadcast to all keeps its target semantics in one transaction.
	if err := s.SendActor(t.Context(), admin, notifications.SendInput{Receiver: "all", Title: "All"}); err != nil {
		t.Fatal(err)
	}
	if countNotifications(t, store, 1) != 2 || countNotifications(t, store, 2) != 1 {
		t.Fatalf("broadcast counts uid1=%d uid2=%d", countNotifications(t, store, 1), countNotifications(t, store, 2))
	}
	// No target is ErrNoTarget.
	if err := s.SendActor(t.Context(), admin, notifications.SendInput{Receiver: "uid", UID: "9999", Title: "X"}); !errors.Is(err, notifications.ErrNoTarget) {
		t.Fatalf("no-target send err=%v", err)
	}
}
