package notifications

import (
	"database/sql"
	"testing"
	"time"

	"blessing-skin-go/internal/testsupport"
	"github.com/google/uuid"
)

func TestNotificationDecodeBeforeRead(t *testing.T) {
	store, _ := testsupport.Database(t, "notify-")
	s := New(store, time.Now)
	if _, err := store.DB.Exec("INSERT INTO "+store.Table("notifications")+" (id,notifiable_type,notifiable_id,data,created_at) VALUES (?,?,?,?,?)", "broken", "App\\Models\\User", 1, `{"title":`, time.Now()); err != nil {
		t.Fatal(err)
	}
	if list, err := s.Unread(t.Context(), 1); err == nil || list != nil {
		t.Fatalf("malformed notification listed: %v err=%v", list, err)
	}
	if read, err := s.Read(t.Context(), 1, "broken"); err == nil || read != nil {
		t.Fatalf("malformed notification read: %v err=%v", read, err)
	}
	var readAt sql.NullTime
	if err := store.DB.QueryRow("SELECT read_at FROM " + store.Table("notifications") + " WHERE id='broken'").Scan(&readAt); err != nil || readAt.Valid {
		t.Fatalf("failed read marked notification read: %v err=%v", readAt, err)
	}
	if _, err := store.DB.Exec("UPDATE "+store.Table("notifications")+" SET data=? WHERE id='broken'", `{"title":"Hello","content":null}`); err != nil {
		t.Fatal(err)
	}
	read, err := s.Read(t.Context(), 1, "broken")
	if err != nil || read.Title != "Hello" || read.Content != "" {
		t.Fatalf("nullable content rejected: %v err=%v", read, err)
	}
}

func TestSendUUIDFormat(t *testing.T) {
	store, _ := testsupport.Database(t, "notify-")
	s := New(store, time.Now)
	if err := s.Send(t.Context(), SendInput{Receiver: "uid", UID: "1", Title: "Notice"}); err != nil {
		t.Fatal(err)
	}
	list, err := s.Unread(t.Context(), 1)
	if err != nil || len(list) != 1 {
		t.Fatalf("sent notifications: %v err=%v", list, err)
	}
	id, err := uuid.Parse(list[0].ID)
	if err != nil || id.Version() != 4 || id.String() != list[0].ID {
		t.Fatalf("notification UUID: %q err=%v", list[0].ID, err)
	}
}
