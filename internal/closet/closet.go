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
	ErrNotFound     = errors.New("closet: object not found")
	ErrNoPermission = errors.New("closet: no permission")
	ErrLackScore    = errors.New("closet: not enough score")
	ErrRepeated     = errors.New("closet: already in closet")
	ErrInvalidName  = errors.New("closet: invalid name")
	ErrConflict     = errors.New("closet: concurrent change; retry")
	ErrPrivate      = errors.New("closet: private texture")
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

// List returns the frozen closet paginator with the texture + pivot shape.
func (s *Service) List(ctx context.Context, b *identity.BrowserSession, category, query string, page, perPage int, path string) (*Page, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 6
	}
	where := " WHERE uc.user_uid=?"
	args := []any{b.User.UID}
	if category == "cape" {
		where += " AND t.type='cape'"
	} else {
		where += " AND t.type IN ('steve','alex')"
	}
	if query != "" {
		where += " AND uc.item_name LIKE ?"
		args = append(args, "%"+query+"%")
	}
	from := " FROM " + s.Store.Table("user_closet") + " uc JOIN " + s.Store.Table("textures") + " t ON t.tid=uc.texture_tid"
	var total int
	if err := s.Store.DB.QueryRowContext(ctx, "SELECT COUNT(*)"+from+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := s.Store.DB.QueryContext(ctx, "SELECT t.tid,t.name,t.type,t.hash,t.size,t.uploader,t.public,t.upload_at,t.likes,uc.user_uid,uc.texture_tid,uc.item_name"+from+where+" ORDER BY uc.texture_tid DESC LIMIT ? OFFSET ?",
		append(args, perPage, (page-1)*perPage)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Item{}
	for rows.Next() {
		var item Item
		var uploadAt time.Time
		var itemName sql.NullString
		if err = rows.Scan(&item.TID, &item.Name, &item.Type, &item.Hash, &item.Size, &item.Uploader, &item.Public, &uploadAt, &item.Likes, &item.Pivot.UserUID, &item.Pivot.TextureTID, &itemName); err != nil {
			return nil, err
		}
		item.UploadAt = uploadAt.In(s.Site.Location).Format("2006-01-02 15:04:05")
		if itemName.Valid {
			name := itemName.String
			item.Pivot.ItemName = &name
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return searchstring.NewPaginator(items, page, perPage, total, path), nil
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

// Add implements the frozen normal closet add with fee, likes and uploader reward.
func (s *Service) Add(ctx context.Context, b *identity.BrowserSession, tid int64, name string) error {
	if name == "" {
		return ErrInvalidName
	}
	options, err := s.options(ctx)
	if err != nil {
		return err
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		uploader, _, _, _, _, err := s.textureUploader(ctx, tx, tid)
		if err != nil {
			return err
		}
		locked, err := lockUsers(ctx, tx, s.Store, b.User.UID, uploader)
		if err != nil {
			return err
		}
		actor, err := s.Identity.CheckBrowserTx(ctx, tx, b)
		if err != nil {
			return err
		}
		// Current read after the user locks: stale snapshots must not admit a
		// private texture or a duplicate closet entry.
		var public bool
		if uploader, _, _, public, _, err = s.textureUploaderLocked(ctx, tx, tid); err != nil {
			return err
		}
		if !locked[uploader].Found {
			uploader = 0
		}
		if !public && uploader != actor.UID && actor.Permission < 1 {
			return ErrPrivate
		}
		repeated, err := s.pivotExistsLocked(ctx, tx, actor.UID, tid)
		if err != nil {
			return err
		}
		if repeated {
			return ErrRepeated
		}
		cost := site.Number(options["score_per_closet_item"])
		var score int64
		if err = tx.QueryRowContext(ctx, "SELECT score FROM "+s.Store.Table("users")+" WHERE uid=? FOR UPDATE", actor.UID).Scan(&score); err != nil {
			return err
		}
		if score < cost {
			return ErrLackScore
		}
		result, err := tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("user_closet")+" (user_uid,texture_tid,item_name) VALUES (?,?,?)", actor.UID, tid, name)
		if err != nil {
			return err
		}
		if affected, err := result.RowsAffected(); err != nil || affected == 0 {
			return ErrRepeated
		}
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("textures")+" SET likes=likes+1 WHERE tid=?", tid); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score-? WHERE uid=?", cost, actor.UID); err != nil {
			return err
		}
		award := site.Number(options["score_award_per_like"])
		if uploader != 0 && uploader != actor.UID {
			if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score+? WHERE uid=?", award, uploader); err != nil {
				return err
			}
			if award != 0 {
				if err = s.recordReward(ctx, tx, actor.UID, tid, uploader, award); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// Rename changes only the closet item name, never the texture name.
func (s *Service) Rename(ctx context.Context, b *identity.BrowserSession, tid int64, name string) error {
	if name == "" {
		return ErrInvalidName
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err := s.Identity.CheckBrowserTx(ctx, tx, b); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, "UPDATE "+s.Store.Table("user_closet")+" SET item_name=? WHERE user_uid=? AND texture_tid=?", name, b.User.UID, tid)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			exists, err := s.pivotExists(ctx, tx, b.User.UID, tid)
			if err != nil {
				return err
			}
			if !exists {
				return ErrNotFound
			}
		}
		return nil
	})
}

// Remove detaches the item, refunds the closet fee, updates likes, revokes the
// recorded Go reward once and clears the owner's player slots.
func (s *Service) Remove(ctx context.Context, b *identity.BrowserSession, tid int64) error {
	options, err := s.options(ctx)
	if err != nil {
		return err
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		uploader, _, _, _, kind, err := s.textureUploader(ctx, tx, tid)
		if err != nil {
			return err
		}
		locked, err := lockUsers(ctx, tx, s.Store, b.User.UID, uploader)
		if err != nil {
			return err
		}
		if _, err = s.Identity.CheckBrowserTx(ctx, tx, b); err != nil {
			return err
		}
		if _, _, _, _, _, err = s.textureUploaderLocked(ctx, tx, tid); err != nil {
			return err
		}
		if !locked[uploader].Found {
			uploader = 0
		}
		exists, err := s.pivotExistsLocked(ctx, tx, b.User.UID, tid)
		if err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		deleted, err := tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("user_closet")+" WHERE user_uid=? AND texture_tid=?", b.User.UID, tid)
		if err != nil {
			return err
		}
		affected, err := deleted.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			return ErrNotFound
		}
		if site.Truth(options["return_score"]) {
			if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score+? WHERE uid=?", site.Number(options["score_per_closet_item"]), b.User.UID); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("textures")+" SET likes=likes-1 WHERE tid=?", tid); err != nil {
			return err
		}
		_ = kind
		rewardUploader, amount, active, err := s.activeReward(ctx, tx, b.User.UID, tid)
		if err != nil {
			return err
		}
		if active {
			if rewardUploader != 0 {
				if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score-? WHERE uid=?", amount, rewardUploader); err != nil {
					return err
				}
			}
			if err = s.consumeReward(ctx, tx, b.User.UID, tid); err != nil {
				return err
			}
		}
		_, err = s.Players.ClearTexturesTx(ctx, tx, b.User.UID, []int64{tid})
		return err
	})
}

// AdminAdd attaches idempotently without fees, likes or reward changes.
func (s *Service) AdminAdd(ctx context.Context, b *identity.BrowserSession, target, tid int64) (map[string]any, error) {
	var result map[string]any
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		targets, err := lockUsers(ctx, tx, s.Store, b.User.UID, target)
		if err != nil {
			return err
		}
		actor, err := s.Identity.CheckBrowserTx(ctx, tx, b)
		if err != nil {
			return err
		}
		user := targets[target]
		if !s.permittedAdmin(actor, &user) {
			return ErrNoPermission
		}
		name, err := s.textureName(ctx, tx, tid)
		if err != nil {
			return err
		}
		exists, err := s.pivotExists(ctx, tx, target, tid)
		if err != nil {
			return err
		}
		if !exists {
			if _, err = tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("user_closet")+" (user_uid,texture_tid,item_name) VALUES (?,?,?)", target, tid, name); err != nil {
				return err
			}
		}
		result = map[string]any{"user": target, "texture": tid}
		return nil
	})
	return result, err
}

// AdminRemove detaches idempotently, clears the target's slots and consumes any
// recorded Go reward without moving balances or likes.
func (s *Service) AdminRemove(ctx context.Context, b *identity.BrowserSession, target, tid int64) (map[string]any, error) {
	var result map[string]any
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		targets, err := lockUsers(ctx, tx, s.Store, b.User.UID, target)
		if err != nil {
			return err
		}
		actor, err := s.Identity.CheckBrowserTx(ctx, tx, b)
		if err != nil {
			return err
		}
		user := targets[target]
		if !s.permittedAdmin(actor, &user) {
			return ErrNoPermission
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("user_closet")+" WHERE user_uid=? AND texture_tid=?", target, tid); err != nil {
			return err
		}
		if err = s.consumeReward(ctx, tx, target, tid); err != nil {
			return err
		}
		if _, err = s.Players.ClearTexturesTx(ctx, tx, target, []int64{tid}); err != nil {
			return err
		}
		result = map[string]any{"user": target, "texture": tid}
		return nil
	})
	return result, err
}

func (s *Service) textureName(ctx context.Context, tx *sql.Tx, tid int64) (string, error) {
	var name string
	err := tx.QueryRowContext(ctx, "SELECT name FROM "+s.Store.Table("textures")+" WHERE tid=?", tid).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return name, err
}
