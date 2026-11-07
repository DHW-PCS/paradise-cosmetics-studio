// Package closet owns normal/admin closet entries and texture mutations,
// including the frozen score and player-reference side effects.
package closet

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/players"
	"blessing-skin-go/internal/searchstring"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/textures"
)

var (
	ErrNotFound       = errors.New("closet: object not found")
	ErrTargetNotFound = errors.New("closet: target user not found")
	ErrNoPermission   = errors.New("closet: no permission")
	ErrLackScore      = errors.New("closet: not enough score")
	ErrRepeated       = errors.New("closet: already in closet")
	ErrInvalidName    = errors.New("closet: invalid name")
	ErrConflict       = errors.New("closet: concurrent change; retry")
	ErrPrivate        = errors.New("closet: private texture")
)

// DuplicateTexture reports a public same-hash conflict when publishing.
type DuplicateTexture struct{ TID int64 }

func (e *DuplicateTexture) Error() string { return "closet: duplicate texture hash" }

type Service struct {
	Store    *database.Store
	Identity *identity.Service
	Site     *site.Service
	Textures *textures.Service
	Players  *players.Service
	Now      func() time.Time
}

func New(store *database.Store, id *identity.Service, view *site.Service, tex *textures.Service, pl *players.Service, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{Store: store, Identity: id, Site: view, Textures: tex, Players: pl, Now: now}
}

type Pivot struct {
	UserUID    int64   `json:"user_uid"`
	TextureTID int64   `json:"texture_tid"`
	ItemName   *string `json:"item_name"`
}

type Item struct {
	TID      int64  `json:"tid"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Hash     string `json:"hash"`
	Size     int64  `json:"size"`
	Uploader int64  `json:"uploader"`
	Public   bool   `json:"public"`
	UploadAt string `json:"upload_at"`
	Likes    int64  `json:"likes"`
	Pivot    Pivot  `json:"pivot"`
}

// Page is the shared Laravel-shaped paginator.
type Page = searchstring.Paginator

type lockedUser struct {
	UID        int64
	Permission int
	Score      int64
	Found      bool
}

func lockUsers(ctx context.Context, tx *sql.Tx, store *database.Store, uids ...int64) (map[int64]lockedUser, error) {
	unique := map[int64]bool{}
	list := []int64{}
	for _, uid := range uids {
		if uid != 0 && !unique[uid] {
			unique[uid] = true
			list = append(list, uid)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	out := map[int64]lockedUser{}
	for _, uid := range list {
		user := lockedUser{UID: uid}
		if err := tx.QueryRowContext(ctx, "SELECT permission,score FROM "+store.Table("users")+" WHERE uid=? FOR UPDATE", uid).Scan(&user.Permission, &user.Score); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				// Deleted uploaders/participants are tolerated by the frozen
				// listeners: rewards and refunds are simply skipped.
				out[uid] = user
				continue
			}
			return nil, err
		}
		user.Found = true
		out[uid] = user
	}
	return out, nil
}

func (s *Service) options(ctx context.Context) (map[string]any, error) { return s.Site.Options(ctx) }

// List is the browser wrapper for ListActor; it shares the same business
// transaction kernel and never forges a browser session for an OAuth actor.
func (s *Service) List(ctx context.Context, b *identity.BrowserSession, category, query string, page, perPage int, path string) (*Page, error) {
	actor, err := s.Identity.NewBrowserActor(b)
	if err != nil {
		return nil, err
	}
	return s.ListActor(ctx, actor, category, query, page, perPage, path)
}

// IDs returns the frozen all-ids array.
func (s *Service) IDs(ctx context.Context, b *identity.BrowserSession) ([]int64, error) {
	rows, err := s.Store.DB.QueryContext(ctx, "SELECT texture_tid FROM "+s.Store.Table("user_closet")+" WHERE user_uid=? ORDER BY texture_tid", b.User.UID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []int64{}
	for rows.Next() {
		var tid int64
		if err = rows.Scan(&tid); err != nil {
			return nil, err
		}
		ids = append(ids, tid)
	}
	return ids, rows.Err()
}

func (s *Service) textureUploaderLocked(ctx context.Context, tx *sql.Tx, tid int64) (uploader, size int64, hash string, public bool, kind string, err error) {
	return s.textureUploaderQuery(ctx, tx, tid, true)
}

func (s *Service) textureUploaderQuery(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, tid int64, lock bool) (uploader, size int64, hash string, public bool, kind string, err error) {
	query := "SELECT uploader,size,hash,public,type FROM " + s.Store.Table("textures") + " WHERE tid=?"
	if lock {
		query += " FOR UPDATE"
	}
	err = q.QueryRowContext(ctx, query, tid).Scan(&uploader, &size, &hash, &public, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, "", false, "", ErrNotFound
	}
	return
}

func (s *Service) pivotExistsLocked(ctx context.Context, tx *sql.Tx, uid, tid int64) (bool, error) {
	var marker int64
	err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("user_closet")+" WHERE user_uid=? AND texture_tid=? FOR UPDATE", uid, tid).Scan(&marker)
	if err != nil {
		return false, err
	}
	return marker > 0, nil
}

func (s *Service) textureUploader(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, tid int64) (uploader, size int64, hash string, public bool, kind string, err error) {
	err = q.QueryRowContext(ctx, "SELECT uploader,size,hash,public,type FROM "+s.Store.Table("textures")+" WHERE tid=?", tid).Scan(&uploader, &size, &hash, &public, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, "", false, "", ErrNotFound
	}
	return
}

func (s *Service) pivotExists(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, uid, tid int64) (bool, error) {
	var count int64
	if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("user_closet")+" WHERE user_uid=? AND texture_tid=?", uid, tid).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// activeReward reads the Go reward record (if any) for a pair.
func (s *Service) activeReward(ctx context.Context, tx *sql.Tx, uid, tid int64) (uploader, amount int64, active bool, err error) {
	err = tx.QueryRowContext(ctx, "SELECT uploader_uid,amount,active FROM "+s.Store.Table("go_closet_rewards")+" WHERE user_uid=? AND texture_tid=? FOR UPDATE", uid, tid).Scan(&uploader, &amount, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, false, nil
	}
	return
}

func (s *Service) recordReward(ctx context.Context, tx *sql.Tx, uid, tid, uploader, amount int64) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("go_closet_rewards")+" (user_uid,texture_tid,uploader_uid,amount,active) VALUES (?,?,?,?,1) ON DUPLICATE KEY UPDATE uploader_uid=VALUES(uploader_uid),amount=VALUES(amount),active=1", uid, tid, uploader, amount)
	return err
}

func (s *Service) consumeReward(ctx context.Context, tx *sql.Tx, uid, tid int64) error {
	_, err := tx.ExecContext(ctx, "UPDATE "+s.Store.Table("go_closet_rewards")+" SET active=0 WHERE user_uid=? AND texture_tid=? AND active=1", uid, tid)
	return err
}

func (s *Service) permittedAdmin(actor *identity.User, target *lockedUser) bool {
	if actor.Permission < 1 || !target.Found {
		return false
	}
	return actor.UID == target.UID || target.Permission < actor.Permission
}

// Add is the browser wrapper for AddActor, sharing the same business
// transaction kernel (fees, likes, and uploader reward are not duplicated).
func (s *Service) Add(ctx context.Context, b *identity.BrowserSession, tid int64, name string) error {
	actor, err := s.Identity.NewBrowserActor(b)
	if err != nil {
		return err
	}
	return s.AddActor(ctx, actor, tid, name)
}

// Rename is the browser wrapper for RenameActor.
func (s *Service) Rename(ctx context.Context, b *identity.BrowserSession, tid int64, name string) error {
	actor, err := s.Identity.NewBrowserActor(b)
	if err != nil {
		return err
	}
	return s.RenameActor(ctx, actor, tid, name)
}

// Remove is the browser wrapper for RemoveActor, sharing the same business
// transaction kernel (refund, likes, reward revocation, and slot clearing
// are not duplicated).
func (s *Service) Remove(ctx context.Context, b *identity.BrowserSession, tid int64) error {
	actor, err := s.Identity.NewBrowserActor(b)
	if err != nil {
		return err
	}
	return s.RemoveActor(ctx, actor, tid)
}

// AdminAdd is the browser wrapper for AdminAddActor.
func (s *Service) AdminAdd(ctx context.Context, b *identity.BrowserSession, target, tid int64) (map[string]any, error) {
	actor, err := s.Identity.NewBrowserActor(b)
	if err != nil {
		return nil, err
	}
	return s.AdminAddActor(ctx, actor, target, tid)
}

// AdminRemove is the browser wrapper for AdminRemoveActor.
func (s *Service) AdminRemove(ctx context.Context, b *identity.BrowserSession, target, tid int64) (map[string]any, error) {
	actor, err := s.Identity.NewBrowserActor(b)
	if err != nil {
		return nil, err
	}
	return s.AdminRemoveActor(ctx, actor, target, tid)
}

func (s *Service) textureName(ctx context.Context, tx *sql.Tx, tid int64) (string, error) {
	var name string
	err := tx.QueryRowContext(ctx, "SELECT name FROM "+s.Store.Table("textures")+" WHERE tid=?", tid).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return name, err
}
