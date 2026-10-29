package site

import (
	"context"
	"encoding/json"
)

type NotificationSummary struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

func (s *Service) UnreadNotifications(ctx context.Context, uid int64) ([]NotificationSummary, error) {
	rows, err := s.Store.DB.QueryContext(ctx, "SELECT id,data FROM "+s.Store.Table("notifications")+" WHERE notifiable_type=? AND notifiable_id=? AND read_at IS NULL ORDER BY created_at DESC", `App\Models\User`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []NotificationSummary{}
	for rows.Next() {
		var notification NotificationSummary
		var raw string
		if err = rows.Scan(&notification.ID, &raw); err != nil {
			return nil, err
		}
		var data struct {
			Title string `json:"title"`
		}
		if err = json.Unmarshal([]byte(raw), &data); err != nil {
			return nil, err
		}
		notification.Title = data.Title
		result = append(result, notification)
	}
	return result, rows.Err()
}
