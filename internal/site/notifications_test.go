package site

import (
	"blessing-skin-go/internal/testsupport"
	"testing"
)

func TestUnreadNotificationOwnership(t *testing.T) {
	store, _ := testsupport.Database(t, "notice_")
	for _, uid := range []int{1, 2} {
		_, err := store.DB.Exec("INSERT INTO "+store.Table("notifications")+" (id,notifiable_type,notifiable_id,data,created_at) VALUES (?,?,?,?,NOW())", uid, "App\\Models\\User", uid, `{"title":"Original notice"}`)
		if err != nil {
			t.Fatal(err)
		}
	}
	s := &Service{Store: store}
	notifications, err := s.UnreadNotifications(t.Context(), 1)
	if err != nil || len(notifications) != 1 || notifications[0].ID != "1" || notifications[0].Title != "Original notice" {
		t.Fatalf("unread owner query failed: %v", err)
	}
}
