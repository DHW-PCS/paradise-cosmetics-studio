// M4-03 closet business Actor entries.
//
// Normal and admin closet operations share one business transaction kernel
// between the browser wrappers in closet.go and these Actor entries. An
// Actor is never turned into a forged BrowserSession: every entry below
// authorizes and reads inside the owner's transaction in the frozen lock
// order (discovery -> client PrepareTx -> users ascending pre-lock ->
// RecheckTx -> texture/closet/reward/player current reads and writes).
// Scope spelling equivalence for the frozen alias pair is interpreted
// centrally by the Actor base and is not repeated here.
package closet

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/searchstring"
	"paradise-cosmetics-studio/internal/site"
	"paradise-cosmetics-studio/internal/textures"
	"paradise-cosmetics-studio/internal/users"
)

// Scope requirements for the closet core APIs. Reads accept either the
// read or the read-write scope; writes require the read-write scope.
// Admin operations additionally recheck the current admin permission and
// the target permission/owner relationship inside the transaction.
func closetReadRequirement() identity.ScopeRequirement {
	return identity.ScopeRequirement{AnyOf: []string{"Closet.Read", "Closet.ReadWrite"}}
}

func closetWriteRequirement() identity.ScopeRequirement {
	return identity.ScopeRequirement{AllOf: []string{"Closet.ReadWrite"}}
}

func closetManagementReadRequirement() identity.ScopeRequirement {
	return identity.ScopeRequirement{AnyOf: []string{"ClosetManagement.Read", "ClosetManagement.ReadWrite"}}
}

func closetManagementWriteRequirement() identity.ScopeRequirement {
	return identity.ScopeRequirement{AllOf: []string{"ClosetManagement.ReadWrite"}}
}

// userExists is a non-authorizing discovery probe for a third-party
// participant (the texture uploader). A deleted uploader is tolerated by
// the frozen closet semantics (no reward, no refund target), so a missing
// uploader row is not added to the mandatory ascending pre-lock set; an
// existing uploader is pre-locked like every other participant.
func (s *Service) userExists(ctx context.Context, tx *sql.Tx, uid int64) (bool, error) {
	if uid == 0 {
		return false, nil
	}
	var marker int64
	err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("users")+" WHERE uid=?", uid).Scan(&marker)
	if err != nil {
		return false, err
	}
	return marker > 0, nil
}

// participants returns the mandatory pre-lock participant set: the actor
// and, when present, an explicit target and/or texture uploader. The
// actor and target must exist; LockUsersTx reports a missing row as
// stale, and the caller maps that participant change to a rollback
// without retrying.
func (s *Service) participants(ctx context.Context, tx *sql.Tx, actorUID, target, uploader int64) ([]int64, error) {
	uids := []int64{actorUID}
	if target != 0 && target != actorUID {
		uids = append(uids, target)
	}
	if uploader != 0 && uploader != actorUID && uploader != target {
		exists, err := s.userExists(ctx, tx, uploader)
		if err != nil {
			return nil, err
		}
		if exists {
			uids = append(uids, uploader)
		}
	}
	return uids, nil
}

// adminTargetUIDs is the discovery step for admin closet writes: the
// frozen route-model binding maps a missing target to 404, so this
// probe returns ErrTargetNotFound (kept distinct from ErrNoPermission
// and from the ErrStale that LockUsersTx reports when a participant
// changes after discovery). The probe runs before the mandatory
// pre-lock and the missing target never reaches LockUsersTx as
// ErrStale. An existing target is returned for the usual ascending
// pre-lock; a target deleted after this probe is a participant change
// and rolls back via LockUsersTx.
func (s *Service) adminTargetUIDs(ctx context.Context, tx *sql.Tx, actorUID, target int64) ([]int64, error) {
	exists, err := s.userExists(ctx, tx, target)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrTargetNotFound
	}
	return []int64{actorUID, target}, nil
}

// runActorTx executes the frozen lock sequence for one closet operation:
// discovery has already produced the participant set, then the client
// lock (PrepareTx) precedes the ascending users pre-lock, followed by the
// credential recheck. It returns the current actor user as rechecked in
// this transaction. Discovery reads are non-authorizing; any participant
// change after discovery surfaces as ErrConflict and rolls back.
func (s *Service) runActorTx(ctx context.Context, tx *sql.Tx, actor identity.Actor, uids []int64, req identity.ScopeRequirement) (*identity.User, error) {
	if actor == nil {
		return nil, identity.ErrSession
	}
	if err := actor.PrepareTx(ctx, tx); err != nil {
		return nil, err
	}
	if err := s.Identity.LockUsersTx(ctx, tx, uids); err != nil {
		if errors.Is(err, identity.ErrStale) {
			return nil, ErrConflict
		}
		return nil, err
	}
	current, err := actor.RecheckTx(ctx, tx, req)
	if err != nil {
		return nil, err
	}
	if current == nil || current.UID != actor.UID() {
		return nil, identity.ErrSession
	}
	return current, nil
}

// listTx reads one frozen closet paginator for ownerUID inside tx. The
// shape (category, q, texture_tid DESC order, defaults) matches the
// legacy closet list; no pagination limit is invented here.
func (s *Service) listTx(ctx context.Context, tx *sql.Tx, ownerUID int64, category, query string, page, perPage int, path string) (*Page, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 6
	}
	where := " WHERE uc.user_uid=?"
	args := []any{ownerUID}
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
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*)"+from+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT t.tid,t.name,t.type,t.hash,t.size,t.uploader,t.public,t.upload_at,t.likes,uc.user_uid,uc.texture_tid,uc.item_name"+from+where+" ORDER BY uc.texture_tid DESC LIMIT ? OFFSET ?",
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

// ListActor returns the actor's own closet paginator, authorized and read
// inside the business transaction.
func (s *Service) ListActor(ctx context.Context, actor identity.Actor, category, query string, page, perPage int, path string) (*Page, error) {
	var result *Page
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if actor == nil {
			return identity.ErrSession
		}
		current, err := s.runActorTx(ctx, tx, actor, []int64{actor.UID()}, closetReadRequirement())
		if err != nil {
			return err
		}
		result, err = s.listTx(ctx, tx, current.UID, category, query, page, perPage, path)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// AdminListActor returns the target user's closet as the frozen bare
// collection ($user->closet): every item, no category/q filter and no
// pagination. It additionally rechecks the current admin permission and
// target permission/owner relationship in the same transaction.
func (s *Service) AdminListActor(ctx context.Context, actor identity.Actor, target int64) ([]Item, error) {
	var result []Item
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if actor == nil {
			return identity.ErrSession
		}
		// Discovery (non-authorizing): a deterministically missing
		// target is ErrTargetNotFound (route-model-binding 404), kept
		// distinct from ErrNoPermission and from the ErrStale that
		// LockUsersTx reports when a participant changes after
		// discovery. The probe runs before the mandatory pre-lock.
		exists, err := s.userExists(ctx, tx, target)
		if err != nil {
			return err
		}
		if !exists {
			return ErrTargetNotFound
		}
		current, err := s.runActorTx(ctx, tx, actor, []int64{actor.UID(), target}, closetManagementReadRequirement())
		if err != nil {
			return err
		}
		locked, err := lockUsers(ctx, tx, s.Store, actor.UID(), target)
		if err != nil {
			return err
		}
		targetUser := locked[target]
		if !s.permittedAdmin(current, &targetUser) {
			return ErrNoPermission
		}
		result, err = s.adminListTx(ctx, tx, target)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// adminListTx reads the full frozen closet collection for ownerUID
// inside tx without pagination or filters: the shape matches the
// frozen $user->closet belongsToMany collection serialized with the
// texture row and the pivot (user_uid, texture_tid, item_name).
func (s *Service) adminListTx(ctx context.Context, tx *sql.Tx, ownerUID int64) ([]Item, error) {
	rows, err := tx.QueryContext(ctx, "SELECT t.tid,t.name,t.type,t.hash,t.size,t.uploader,t.public,t.upload_at,t.likes,uc.user_uid,uc.texture_tid,uc.item_name FROM "+s.Store.Table("user_closet")+" uc JOIN "+s.Store.Table("textures")+" t ON t.tid=uc.texture_tid WHERE uc.user_uid=? ORDER BY uc.texture_tid DESC", ownerUID)
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
	return items, nil
}

// AddActor implements the frozen normal closet add with fee, likes and
// uploader reward for an Actor.
func (s *Service) AddActor(ctx context.Context, actor identity.Actor, tid int64, name string) error {
	if name == "" {
		return ErrInvalidName
	}
	options, err := s.options(ctx)
	if err != nil {
		return err
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if actor == nil {
			return identity.ErrSession
		}
		// Discovery (non-authorizing): the texture's current uploader
		// defines the participant set.
		discoveredUploader, _, _, _, _, err := s.textureUploader(ctx, tx, tid)
		if err != nil {
			return err
		}
		uids, err := s.participants(ctx, tx, actor.UID(), 0, discoveredUploader)
		if err != nil {
			return err
		}
		current, err := s.runActorTx(ctx, tx, actor, uids, closetWriteRequirement())
		if err != nil {
			return err
		}
		// Current read after the credential recheck: stale snapshots
		// must not admit a private texture or a duplicate entry, and a
		// changed participant rolls back without retry.
		uploader, _, _, public, _, err := s.textureUploaderLocked(ctx, tx, tid)
		if err != nil {
			return err
		}
		if uploader != discoveredUploader {
			return ErrConflict
		}
		locked, err := lockUsers(ctx, tx, s.Store, current.UID, uploader)
		if err != nil {
			return err
		}
		if !locked[uploader].Found {
			uploader = 0
		}
		if !public && uploader != current.UID && current.Permission < 1 {
			return ErrPrivate
		}
		repeated, err := s.pivotExistsLocked(ctx, tx, current.UID, tid)
		if err != nil {
			return err
		}
		if repeated {
			return ErrRepeated
		}
		cost := site.Number(options["score_per_closet_item"])
		if locked[current.UID].Score < cost {
			return ErrLackScore
		}
		result, err := tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("user_closet")+" (user_uid,texture_tid,item_name) VALUES (?,?,?)", current.UID, tid, name)
		if err != nil {
			return err
		}
		if affected, err := result.RowsAffected(); err != nil || affected == 0 {
			return ErrRepeated
		}
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("textures")+" SET likes=likes+1 WHERE tid=?", tid); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score-? WHERE uid=?", cost, current.UID); err != nil {
			return err
		}
		award := site.Number(options["score_award_per_like"])
		if uploader != 0 && uploader != current.UID {
			if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score+? WHERE uid=?", award, uploader); err != nil {
				return err
			}
			if award != 0 {
				if err = s.recordReward(ctx, tx, current.UID, tid, uploader, award); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// RenameActor changes only the closet item name, never the texture name.
func (s *Service) RenameActor(ctx context.Context, actor identity.Actor, tid int64, name string) error {
	if name == "" {
		return ErrInvalidName
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if actor == nil {
			return identity.ErrSession
		}
		current, err := s.runActorTx(ctx, tx, actor, []int64{actor.UID()}, closetWriteRequirement())
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, "UPDATE "+s.Store.Table("user_closet")+" SET item_name=? WHERE user_uid=? AND texture_tid=?", name, current.UID, tid)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			exists, err := s.pivotExists(ctx, tx, current.UID, tid)
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

// RemoveActor detaches the item, refunds the closet fee, updates likes,
// revokes the recorded Go reward once and clears the owner's player
// slots for an Actor.
func (s *Service) RemoveActor(ctx context.Context, actor identity.Actor, tid int64) error {
	options, err := s.options(ctx)
	if err != nil {
		return err
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if actor == nil {
			return identity.ErrSession
		}
		discoveredUploader, _, _, _, _, err := s.textureUploader(ctx, tx, tid)
		if err != nil {
			return err
		}
		uids, err := s.participants(ctx, tx, actor.UID(), 0, discoveredUploader)
		if err != nil {
			return err
		}
		current, err := s.runActorTx(ctx, tx, actor, uids, closetWriteRequirement())
		if err != nil {
			return err
		}
		uploader, _, _, _, _, err := s.textureUploaderLocked(ctx, tx, tid)
		if err != nil {
			return err
		}
		if uploader != discoveredUploader {
			return ErrConflict
		}
		locked, err := lockUsers(ctx, tx, s.Store, current.UID, uploader)
		if err != nil {
			return err
		}
		if !locked[uploader].Found {
			uploader = 0
		}
		_ = uploader
		exists, err := s.pivotExistsLocked(ctx, tx, current.UID, tid)
		if err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		deleted, err := tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("user_closet")+" WHERE user_uid=? AND texture_tid=?", current.UID, tid)
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
			if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score+? WHERE uid=?", site.Number(options["score_per_closet_item"]), current.UID); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("textures")+" SET likes=likes-1 WHERE tid=?", tid); err != nil {
			return err
		}
		rewardUploader, amount, active, err := s.activeReward(ctx, tx, current.UID, tid)
		if err != nil {
			return err
		}
		if active {
			if rewardUploader != 0 {
				if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score-? WHERE uid=?", amount, rewardUploader); err != nil {
					return err
				}
			}
			if err = s.consumeReward(ctx, tx, current.UID, tid); err != nil {
				return err
			}
		}
		_, err = s.Players.ClearTexturesTx(ctx, tx, current.UID, []int64{tid})
		return err
	})
}

// AdminAddActor attaches idempotently without fees, likes or reward
// changes, for an admin Actor and an explicit target user.
func (s *Service) AdminAddActor(ctx context.Context, actor identity.Actor, target, tid int64) (map[string]any, error) {
	var result map[string]any
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if actor == nil {
			return identity.ErrSession
		}
		uids, err := s.adminTargetUIDs(ctx, tx, actor.UID(), target)
		if err != nil {
			return err
		}
		current, err := s.runActorTx(ctx, tx, actor, uids, closetManagementWriteRequirement())
		if err != nil {
			return err
		}
		locked, err := lockUsers(ctx, tx, s.Store, actor.UID(), target)
		if err != nil {
			return err
		}
		targetUser := locked[target]
		if !s.permittedAdmin(current, &targetUser) {
			return ErrNoPermission
		}
		texture, err := s.textureRowTx(ctx, tx, tid)
		if err != nil {
			return err
		}
		exists, err := s.pivotExists(ctx, tx, target, tid)
		if err != nil {
			return err
		}
		if !exists {
			if _, err = tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("user_closet")+" (user_uid,texture_tid,item_name) VALUES (?,?,?)", target, tid, texture.Name); err != nil {
				return err
			}
		}
		user, err := s.userRowTx(ctx, tx, target)
		if err != nil {
			return err
		}
		result = map[string]any{"user": user, "texture": texture}
		return nil
	})
	return result, err
}

// AdminRemoveActor detaches idempotently, clears the target's slots and
// consumes any recorded Go reward without moving balances or likes, for
// an admin Actor and an explicit target user.
func (s *Service) AdminRemoveActor(ctx context.Context, actor identity.Actor, target, tid int64) (map[string]any, error) {
	var result map[string]any
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if actor == nil {
			return identity.ErrSession
		}
		uids, err := s.adminTargetUIDs(ctx, tx, actor.UID(), target)
		if err != nil {
			return err
		}
		current, err := s.runActorTx(ctx, tx, actor, uids, closetManagementWriteRequirement())
		if err != nil {
			return err
		}
		locked, err := lockUsers(ctx, tx, s.Store, actor.UID(), target)
		if err != nil {
			return err
		}
		targetUser := locked[target]
		if !s.permittedAdmin(current, &targetUser) {
			return ErrNoPermission
		}
		texture, err := s.textureRowTx(ctx, tx, tid)
		if err != nil {
			return err
		}
		user, err := s.userRowTx(ctx, tx, target)
		if err != nil {
			return err
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
		result = map[string]any{"user": user, "texture": texture}
		return nil
	})
	return result, err
}

// userRowTx reads one user row for the frozen full-model serialization.
// Legacy hidden fields (password, remember_token) are never selected.
func (s *Service) userRowTx(ctx context.Context, tx *sql.Tx, uid int64) (*users.User, error) {
	var user users.User
	var lastSign, registered time.Time
	var locale sql.NullString
	err := tx.QueryRowContext(ctx, "SELECT uid,email,nickname,avatar,score,permission,ip,is_dark_mode,last_sign_at,register_at,verified,locale FROM "+s.Store.Table("users")+" WHERE uid=?", uid).
		Scan(&user.UID, &user.Email, &user.Nickname, &user.Avatar, &user.Score, &user.Permission, &user.IP, &user.IsDarkMode, &lastSign, &registered, &user.Verified, &locale)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if locale.Valid {
		value := locale.String
		user.Locale = &value
	}
	user.LastSignAt = lastSign.UTC().Format("2006-01-02T15:04:05.000000Z")
	user.RegisterAt = registered.UTC().Format("2006-01-02T15:04:05.000000Z")
	return &user, nil
}

// textureRowTx reads one texture row for the frozen full-model
// serialization in the same column order as the legacy Texture model.
func (s *Service) textureRowTx(ctx context.Context, tx *sql.Tx, tid int64) (*textures.Texture, error) {
	var row textures.Texture
	var uploadAt time.Time
	err := tx.QueryRowContext(ctx, "SELECT tid,name,type,hash,size,uploader,public,upload_at,likes FROM "+s.Store.Table("textures")+" WHERE tid=?", tid).
		Scan(&row.TID, &row.Name, &row.Type, &row.Hash, &row.Size, &row.Uploader, &row.Public, &uploadAt, &row.Likes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	row.UploadAt = uploadAt.In(s.Site.Location).Format("2006-01-02 15:04:05")
	return &row, nil
}
