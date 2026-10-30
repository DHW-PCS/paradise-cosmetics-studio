package closet

import (
	"context"
	"database/sql"
	"errors"
	"strconv"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/legacy/rules"
	"blessing-skin-go/internal/site"
)

func (s *Service) permitTexture(actor *identity.User, uploader int64) error {
	if actor.Permission >= 1 || (uploader != 0 && actor.UID == uploader) {
		return nil
	}
	return ErrNoPermission
}

func (s *Service) textureRow(ctx context.Context, tx *sql.Tx, tid int64, lock bool) (uploader, size int64, hash, kind string, public bool, err error) {
	query := "SELECT uploader,size,hash,type,public FROM " + s.Store.Table("textures") + " WHERE tid=?"
	if lock {
		query += " FOR UPDATE"
	}
	err = tx.QueryRowContext(ctx, query, tid).Scan(&uploader, &size, &hash, &kind, &public)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, "", "", false, ErrNotFound
	}
	return
}

func (s *Service) actorLock(ctx context.Context, tx *sql.Tx, b *identity.BrowserSession) (*identity.User, error) {
	return s.Identity.CheckBrowserTx(ctx, tx, b)
}

// RenameTexture updates the texture name only (closet item names stay).
func (s *Service) RenameTexture(ctx context.Context, b *identity.BrowserSession, tid int64, name string) error {
	if name == "" {
		return ErrInvalidName
	}
	options, err := s.options(ctx)
	if err != nil {
		return err
	}
	pattern, _ := options["texture_name_regexp"].(string)
	if matched, err := rules.MatchTexture(pattern, name); err != nil {
		return err
	} else if !matched {
		return ErrInvalidName
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		uploader, _, _, _, _, err := s.textureRow(ctx, tx, tid, false)
		if err != nil {
			return err
		}
		locked, err := lockUsers(ctx, tx, s.Store, b.User.UID, uploader)
		if err != nil {
			return err
		}
		if !locked[uploader].Found {
			uploader = 0
		}
		actor, err := s.actorLock(ctx, tx, b)
		if err != nil {
			return err
		}
		uploader, _, _, _, _, err = s.textureRow(ctx, tx, tid, true)
		if err != nil {
			return err
		}
		if err = s.permitTexture(actor, uploader); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("textures")+" SET name=? WHERE tid=?", name, tid)
		return err
	})
}

// SetTextureType changes the applicable model and refreshes referencing player
// timestamps (derived representation changes for cached profiles).
func (s *Service) SetTextureType(ctx context.Context, b *identity.BrowserSession, tid int64, kind string) error {
	if kind != "steve" && kind != "alex" && kind != "cape" {
		return errors.New("closet: invalid texture type")
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		uploader, _, _, _, _, err := s.textureRow(ctx, tx, tid, false)
		if err != nil {
			return err
		}
		locked, err := lockUsers(ctx, tx, s.Store, b.User.UID, uploader)
		if err != nil {
			return err
		}
		if !locked[uploader].Found {
			uploader = 0
		}
		actor, err := s.actorLock(ctx, tx, b)
		if err != nil {
			return err
		}
		if _, _, _, _, _, err = s.textureRow(ctx, tx, tid, true); err != nil {
			return err
		}
		if err = s.permitTexture(actor, uploader); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("textures")+" SET type=? WHERE tid=?", kind, tid); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("players")+" SET last_modified=? WHERE tid_skin=? OR tid_cape=?", s.Now().In(s.Site.Location), tid, tid)
		return err
	})
}

// Privacy toggles the public flag with the frozen price/award difference and
// cleans other users' closets/players when turning private.
func (s *Service) SetPrivacy(ctx context.Context, b *identity.BrowserSession, tid int64) (bool, error) {
	options, err := s.options(ctx)
	if err != nil {
		return false, err
	}
	var becamePublic bool
	err = s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		uploader, size, hash, _, public, err := s.textureRow(ctx, tx, tid, false)
		if err != nil {
			return err
		}
		if _, err = s.Textures.LockHash(ctx, tx, hash); err != nil {
			return err
		}
		affected, err := affectedCloseters(ctx, tx, s.Store, tid, uploader)
		if err != nil {
			return err
		}
		ids := append([]int64{b.User.UID, uploader}, affected...)
		locked, err := lockUsers(ctx, tx, s.Store, ids...)
		if err != nil {
			return err
		}
		actor, err := s.actorLock(ctx, tx, b)
		if err != nil {
			return err
		}
		uploader, size, hash, _, public, err = s.textureRow(ctx, tx, tid, true)
		if err != nil {
			return err
		}
		if err = s.permitTexture(actor, uploader); err != nil {
			return err
		}
		publicRate := site.Number(options["score_per_storage"])
		privateRate := site.Number(options["private_score_per_storage"])
		diff := size * (privateRate - publicRate)
		if public {
			diff = -diff
			if site.Truth(options["take_back_scores_after_deletion"]) {
				diff -= site.Number(options["score_award_per_texture"])
			}
		}
		uploaderUser := locked[uploader]
		if uploaderUser.Score+diff < 0 {
			return ErrLackScore
		}
		if !public {
			var publicCopy int64
			err = tx.QueryRowContext(ctx, "SELECT tid FROM "+s.Store.Table("textures")+" WHERE hash=? AND public=1 AND tid<>? ORDER BY tid LIMIT 1", hash, tid).Scan(&publicCopy)
			if err == nil {
				return &DuplicateTexture{TID: publicCopy}
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		if diff != 0 {
			if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score+? WHERE uid=?", diff, uploader); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("textures")+" SET public=? WHERE tid=?", !public, tid); err != nil {
			return err
		}
		becamePublic = !public
		if becamePublic {
			return nil
		}
		// Turning private: detach other users, refund their closet fee and
		// clear their player references. The uploader keeps using it.
		rows, err := tx.QueryContext(ctx, "SELECT DISTINCT user_uid FROM "+s.Store.Table("user_closet")+" WHERE texture_tid=? AND user_uid<>? ORDER BY user_uid FOR UPDATE", tid, uploader)
		if err != nil {
			return err
		}
		var users []int64
		for rows.Next() {
			var uid int64
			if err = rows.Scan(&uid); err != nil {
				rows.Close()
				return err
			}
			users = append(users, uid)
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return err
		}
		if !sameIDs(users, affected) {
			return ErrConflict
		}
		refund := int64(0)
		if site.Truth(options["return_score"]) {
			refund = site.Number(options["score_per_closet_item"])
		}
		for _, uid := range users {
			if _, err = tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("user_closet")+" WHERE user_uid=? AND texture_tid=?", uid, tid); err != nil {
				return err
			}
			if refund != 0 {
				if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score+? WHERE uid=?", refund, uid); err != nil {
					return err
				}
			}
			if err = s.consumeReward(ctx, tx, uid, tid); err != nil {
				return err
			}
			if _, err = s.Players.ClearTexturesTx(ctx, tx, uid, []int64{tid}); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("textures")+" SET likes=likes-? WHERE tid=?", len(users), tid)
		return err
	})
	return becamePublic, err
}

func sameIDs(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func existingCloseters(ctx context.Context, tx *sql.Tx, store *database.Store, tid int64) ([]int64, error) {
	rows, err := tx.QueryContext(ctx, "SELECT DISTINCT user_uid FROM "+store.Table("user_closet")+" WHERE texture_tid=? ORDER BY user_uid", tid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var uid int64
		if err = rows.Scan(&uid); err != nil {
			return nil, err
		}
		out = append(out, uid)
	}
	return out, rows.Err()
}

func affectedCloseters(ctx context.Context, tx *sql.Tx, store *database.Store, tid, uploader int64) ([]int64, error) {
	rows, err := tx.QueryContext(ctx, "SELECT DISTINCT user_uid FROM "+store.Table("user_closet")+" WHERE texture_tid=? AND user_uid<>? ORDER BY user_uid", tid, uploader)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var uid int64
		if err = rows.Scan(&uid); err != nil {
			return nil, err
		}
		out = append(out, uid)
	}
	return out, rows.Err()
}

// DeleteTexture is the single deletion service used by users, admins and
// report review. It keeps the file until the collector observes zero refs.
func (s *Service) DeleteTexture(ctx context.Context, b *identity.BrowserSession, tid int64) error {
	options, err := s.options(ctx)
	if err != nil {
		return err
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		return s.deleteTextureInTx(ctx, tx, b, tid, options)
	})
}

// DeleteTextureTx runs the same deletion inside the caller's transaction; M3-07
// report review uses it so accounting stays single-sourced.
func (s *Service) DeleteTextureTx(ctx context.Context, tx *sql.Tx, b *identity.BrowserSession, tid int64) error {
	options, err := s.options(ctx)
	if err != nil {
		return err
	}
	return s.deleteTextureInTx(ctx, tx, b, tid, options)
}

func (s *Service) deleteTextureInTx(ctx context.Context, tx *sql.Tx, b *identity.BrowserSession, tid int64, options map[string]any) error {
	{
		uploader, size, hash, _, public, err := s.textureRow(ctx, tx, tid, false)
		if err != nil {
			return err
		}
		if _, err = s.Textures.LockHash(ctx, tx, hash); err != nil {
			return err
		}
		closeters, err := existingCloseters(ctx, tx, s.Store, tid)
		if err != nil {
			return err
		}
		owners, err := playerOwners(ctx, tx, s.Store, tid)
		if err != nil {
			return err
		}
		ids := append([]int64{b.User.UID, uploader}, closeters...)
		ids = append(ids, owners...)
		locked, err := lockUsers(ctx, tx, s.Store, ids...)
		if err != nil {
			return err
		}
		if !locked[uploader].Found {
			uploader = 0
		}
		actor, err := s.actorLock(ctx, tx, b)
		if err != nil {
			return err
		}
		uploader, size, hash, _, public, err = s.textureRow(ctx, tx, tid, true)
		if err != nil {
			return err
		}
		if err = s.permitTexture(actor, uploader); err != nil {
			return err
		}
		// Uploader storage refund / take-back.
		if uploader != 0 {
			refund := int64(0)
			if site.Truth(options["return_score"]) {
				rate := site.Number(options["score_per_storage"])
				if !public {
					rate = site.Number(options["private_score_per_storage"])
				}
				refund += size * rate
			}
			if public && site.Truth(options["take_back_scores_after_deletion"]) {
				refund -= site.Number(options["score_award_per_texture"])
			}
			if refund != 0 {
				if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score+? WHERE uid=?", refund, uploader); err != nil {
					return err
				}
			}
		}
		// Clear every closet association; other users get the closet fee back.
		refundCloset := int64(0)
		if site.Truth(options["return_score"]) {
			refundCloset = site.Number(options["score_per_closet_item"])
		}
		rows, err := tx.QueryContext(ctx, "SELECT DISTINCT user_uid FROM "+s.Store.Table("user_closet")+" WHERE texture_tid=? ORDER BY user_uid FOR UPDATE", tid)
		if err != nil {
			return err
		}
		var users []int64
		for rows.Next() {
			var uid int64
			if err = rows.Scan(&uid); err != nil {
				rows.Close()
				return err
			}
			users = append(users, uid)
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return err
		}
		if !sameIDs(users, closeters) {
			return ErrConflict
		}
		currentOwners, err := playerOwnersLocked(ctx, tx, s.Store, tid)
		if err != nil {
			return err
		}
		if !sameIDs(currentOwners, owners) {
			return ErrConflict
		}
		others := 0
		for _, uid := range users {
			if uid != uploader {
				others++
				if refundCloset != 0 {
					if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score+? WHERE uid=?", refundCloset, uid); err != nil {
						return err
					}
				}
			}
			if err = s.consumeReward(ctx, tx, uid, tid); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("user_closet")+" WHERE texture_tid=?", tid); err != nil {
			return err
		}
		// Clear all player references, including the uploader's own players.
		for _, uid := range owners {
			if _, err = s.Players.ClearTexturesTx(ctx, tx, uid, []int64{tid}); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("textures")+" WHERE tid=?", tid); err != nil {
			return err
		}
		_ = others
		return s.Textures.EnqueueCollect(ctx, tx, "texture.collect:"+strconv.FormatInt(tid, 10), hash)
	}
}

func playerOwners(ctx context.Context, tx *sql.Tx, store *database.Store, tid int64) ([]int64, error) {
	return playerOwnersQuery(ctx, tx, store, tid, false)
}

func playerOwnersLocked(ctx context.Context, tx *sql.Tx, store *database.Store, tid int64) ([]int64, error) {
	return playerOwnersQuery(ctx, tx, store, tid, true)
}

func playerOwnersQuery(ctx context.Context, tx *sql.Tx, store *database.Store, tid int64, lock bool) ([]int64, error) {
	query := "SELECT DISTINCT uid FROM " + store.Table("players") + " WHERE tid_skin=? OR tid_cape=? ORDER BY uid"
	if lock {
		query += " FOR UPDATE"
	}
	rows, err := tx.QueryContext(ctx, query, tid, tid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var uid int64
		if err = rows.Scan(&uid); err != nil {
			return nil, err
		}
		out = append(out, uid)
	}
	return out, rows.Err()
}
