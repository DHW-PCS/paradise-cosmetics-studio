// Package notifications owns site messages, unread lists and read marking.
package notifications

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"blessing-skin-go/internal/database"
	"github.com/google/uuid"
)

var (
	ErrNotFound = errors.New("notifications: notification not found")
	ErrNoTarget = errors.New("notifications: target user not found")
)

type Service struct {
	Store *database.Store
	Now   func() time.Time
}

func New(store *database.Store, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{Store: store, Now: now}
}

type Unread struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// Unread lists the current user's unread notification titles.
func (s *Service) Unread(ctx context.Context, uid int64) ([]Unread, error) {
	rows, err := s.Store.DB.QueryContext(ctx, "SELECT id,data FROM "+s.Store.Table("notifications")+" WHERE notifiable_type='App\\\\Models\\\\User' AND notifiable_id=? AND read_at IS NULL ORDER BY created_at DESC", uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Unread{}
	for rows.Next() {
		var id, data string
		if err = rows.Scan(&id, &data); err != nil {
			return nil, err
		}
		var payload struct {
			Title string `json:"title"`
		}
		if err = json.Unmarshal([]byte(data), &payload); err != nil {
			return nil, err
		}
		out = append(out, Unread{ID: id, Title: payload.Title})
	}
	return out, rows.Err()
}

type Read struct {
	Title   string `json:"title"`
	Content string `json:"content"`
	Time    string `json:"time"`
}

// Read marks one unread notification as read and returns its GFM content.
func (s *Service) Read(ctx context.Context, uid int64, id string) (*Read, error) {
	var data string
	var createdAt time.Time
	err := s.Store.DB.QueryRowContext(ctx, "SELECT data,created_at FROM "+s.Store.Table("notifications")+" WHERE id=? AND notifiable_type='App\\\\Models\\\\User' AND notifiable_id=? AND read_at IS NULL", id, uid).Scan(&data, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var payload struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	if err = json.Unmarshal([]byte(data), &payload); err != nil {
		return nil, err
	}
	if _, err = s.Store.DB.ExecContext(ctx, "UPDATE "+s.Store.Table("notifications")+" SET read_at=? WHERE id=? AND read_at IS NULL", s.Now(), id); err != nil {
		return nil, err
	}
	return &Read{Title: payload.Title, Content: payload.Content, Time: createdAt.Format("2006-01-02 15:04:05")}, nil
}

type SendInput struct {
	Receiver, UID, Email, Title, Content string
}

// Send creates one site message per target user (admin broadcast).
func (s *Service) Send(ctx context.Context, in SendInput) error {
	query := "SELECT uid FROM " + s.Store.Table("users")
	args := []any{}
	switch in.Receiver {
	case "all":
	case "normal":
		query += " WHERE permission=0"
	case "uid":
		query += " WHERE uid=?"
		args = append(args, in.UID)
	case "email":
		query += " WHERE email=?"
		args = append(args, in.Email)
	}
	rows, err := s.Store.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	var uids []int64
	for rows.Next() {
		var uid int64
		if err = rows.Scan(&uid); err != nil {
			rows.Close()
			return err
		}
		uids = append(uids, uid)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	if len(uids) == 0 {
		return ErrNoTarget
	}
	payload, err := json.Marshal(map[string]string{"title": in.Title, "content": in.Content})
	if err != nil {
		return err
	}
	for _, uid := range uids {
		if _, err = s.Store.DB.ExecContext(ctx, "INSERT INTO "+s.Store.Table("notifications")+" (id,notifiable_type,notifiable_id,data,created_at) VALUES (?,?,?,?,?)", uuid.NewString(), "App\\Models\\User", uid, string(payload), s.Now()); err != nil {
			return err
		}
	}
	return nil
}
