// Package notifications owns site messages, unread lists and read marking.
package notifications

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	renderer "github.com/yuin/goldmark/renderer/html"
	"paradise-cosmetics-studio/internal/database"
)

var (
	ErrNotFound = errors.New("notifications: notification not found")
	ErrNoTarget = errors.New("notifications: target user not found")
)

// Notifications are administrator-authored GFM with raw HTML.
var notificationMarkdown = goldmark.New(goldmark.WithExtensions(extension.GFM), goldmark.WithRendererOptions(renderer.WithUnsafe()))

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

// Unread lists the current user's unread notification titles. It
// shares the unreadTx kernel with UnreadActor; the browser HTTP
// layer passes the session UID for this entry, as before.
func (s *Service) Unread(ctx context.Context, uid int64) ([]Unread, error) {
	var out []Unread
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		var err error
		out, err = s.unreadTx(ctx, tx, uid)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) unreadTx(ctx context.Context, tx *sql.Tx, uid int64) ([]Unread, error) {
	rows, err := tx.QueryContext(ctx, "SELECT id,data FROM "+s.Store.Table("notifications")+" WHERE notifiable_type='App\\\\Models\\\\User' AND notifiable_id=? AND read_at IS NULL ORDER BY created_at DESC", uid)
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

// Read marks one unread notification as read and returns its GFM
// content as HTML. It shares the readTx kernel with ReadActor; the browser
// HTTP layer passes the session UID for this entry, as before.
func (s *Service) Read(ctx context.Context, uid int64, id string) (*Read, error) {
	var out *Read
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		var err error
		out, err = s.readTx(ctx, tx, uid, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) readTx(ctx context.Context, tx *sql.Tx, uid int64, id string) (*Read, error) {
	var data string
	var createdAt time.Time
	err := tx.QueryRowContext(ctx, "SELECT data,created_at FROM "+s.Store.Table("notifications")+" WHERE id=? AND notifiable_type='App\\\\Models\\\\User' AND notifiable_id=? AND read_at IS NULL", id, uid).Scan(&data, &createdAt)
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
	var content bytes.Buffer
	if err = notificationMarkdown.Convert([]byte(payload.Content), &content); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("notifications")+" SET read_at=? WHERE id=? AND read_at IS NULL", s.Now(), id); err != nil {
		return nil, err
	}
	return &Read{Title: payload.Title, Content: content.String(), Time: createdAt.Format("2006-01-02 15:04:05")}, nil
}

type SendInput struct {
	Receiver, UID, Email, Title, Content string
}

// Send creates one site message per target user (admin broadcast).
// It shares the resolve/send Tx kernels with SendActor; the browser
// HTTP layer gates admin access for this entry, as before.
func (s *Service) Send(ctx context.Context, in SendInput) error {
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		targets, err := s.resolveTargetsTx(ctx, tx, in)
		if err != nil {
			return err
		}
		return s.sendToTx(ctx, tx, in, targets)
	})
}

// resolveTargetsTx applies the frozen receiver semantics
// (all/normal/uid/email) inside tx.
func (s *Service) resolveTargetsTx(ctx context.Context, tx *sql.Tx, in SendInput) ([]int64, error) {
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
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	var uids []int64
	for rows.Next() {
		var uid int64
		if err = rows.Scan(&uid); err != nil {
			rows.Close()
			return nil, err
		}
		uids = append(uids, uid)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return uids, nil
}

// sendToTx inserts one notification per resolved target inside tx.
// An empty target set reports ErrNoTarget, as the frozen entry does.
func (s *Service) sendToTx(ctx context.Context, tx *sql.Tx, in SendInput, uids []int64) error {
	if len(uids) == 0 {
		return ErrNoTarget
	}
	payload, err := json.Marshal(map[string]string{"title": in.Title, "content": in.Content})
	if err != nil {
		return err
	}
	for _, uid := range uids {
		if _, err = tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("notifications")+" (id,notifiable_type,notifiable_id,data,created_at) VALUES (?,?,?,?,?)", uuid.NewString(), "App\\Models\\User", uid, string(payload), s.Now()); err != nil {
			return err
		}
	}
	return nil
}
