package players

import (
	"context"
	"database/sql"
	"errors"
	"os"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/textures"
)

// Authorizer rechecks a synthetic game credential inside the business
// transaction. M3 supplies controlled test doubles; M4 installs the real
// verifier. A nil authorizer is rejected, never treated as a bypass.
type Authorizer interface {
	Recheck(ctx context.Context, tx *sql.Tx, creds GameAuth, pid int64) error
}

// GameAuth is the verified credential context handed to M3 business code.
type GameAuth struct {
	UID        int64
	Version    int64
	Permission int
	Banned     bool
	Profile    string
}

var (
	ErrStaleCredential = errors.New("players: credential no longer owns this profile")
	ErrTypeMismatch    = errors.New("players: texture type does not match the slot")
	ErrNotAuthorized   = errors.New("players: game credential rejected")
)

type textureInfo struct {
	TID      int64
	Uploader int64
	Kind     string
	Hash     string
	Size     int64
	Public   bool
}

func (s *Service) textureInfo(ctx context.Context, q queryer, tid int64) (textureInfo, error) {
	var info textureInfo
	err := q.QueryRowContext(ctx, "SELECT tid,uploader,type,hash,size,public FROM "+s.Store.Table("textures")+" WHERE tid=?", tid).
		Scan(&info.TID, &info.Uploader, &info.Kind, &info.Hash, &info.Size, &info.Public)
	if errors.Is(err, sql.ErrNoRows) {
		return textureInfo{}, ErrNotFound
	}
	return info, err
}

func slotMatches(kind, slot string) bool {
	if slot == "cape" {
		return kind == "cape"
	}
	return kind == "steve" || kind == "alex"
}

func (s *Service) inCloset(ctx context.Context, q queryer, uid, tid int64) (bool, error) {
	var count int64
	if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("user_closet")+" WHERE user_uid=? AND texture_tid=?", uid, tid).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// SetTextures validates both slots and their closet membership before writing
// either one, so a failing second slot leaves the first untouched.
func (s *Service) SetTextures(ctx context.Context, b *identity.BrowserSession, pid int64, skin, cape *int64) (Player, error) {
	var out Player
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		owner, err := s.playerOwner(ctx, tx, pid)
		if err != nil {
			return err
		}
		locked, err := s.lockUsers(ctx, tx, b.User.UID, owner)
		if err != nil {
			return err
		}
		actor, err := s.Identity.CheckBrowserTx(ctx, tx, b)
		if err != nil {
			return err
		}
		player, err := s.lockedPlayer(ctx, tx, pid)
		if err != nil {
			return err
		}
		if player.UID != owner {
			return ErrConflict
		}
		if err = s.permitted(Normal, actor, owner, locked[owner].Permission); err != nil {
			return err
		}
		for _, slot := range []struct {
			name string
			tid  *int64
		}{{"skin", skin}, {"cape", cape}} {
			if slot.tid == nil || *slot.tid == 0 {
				continue
			}
			info, err := s.textureInfo(ctx, tx, *slot.tid)
			if err != nil {
				return err
			}
			if !slotMatches(info.Kind, slot.name) {
				return ErrTypeMismatch
			}
			member, err := s.inCloset(ctx, tx, actor.UID, *slot.tid)
			if err != nil {
				return err
			}
			if !member {
				return ErrNotFound
			}
		}
		skinValue, capeValue := player.TIDSkin, player.TIDCape
		if skin != nil && *skin != 0 {
			skinValue = *skin
		}
		if cape != nil && *cape != 0 {
			capeValue = *cape
		}
		modified := s.now()
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("players")+" SET tid_skin=?,tid_cape=?,last_modified=? WHERE pid=?", skinValue, capeValue, modified, pid); err != nil {
			return err
		}
		player.TIDSkin, player.TIDCape = skinValue, capeValue
		player.LastModified = modified.Format("2006-01-02 15:04:05")
		out = player
		return nil
	})
	return out, err
}

// ClearTextures clears the requested slots (the frozen request accepts either
// a type array or the presence of skin/cape parameters).
func (s *Service) ClearTextures(ctx context.Context, b *identity.BrowserSession, pid int64, slotSkin, slotCape bool) (Player, error) {
	var out Player
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		owner, err := s.playerOwner(ctx, tx, pid)
		if err != nil {
			return err
		}
		locked, err := s.lockUsers(ctx, tx, b.User.UID, owner)
		if err != nil {
			return err
		}
		actor, err := s.Identity.CheckBrowserTx(ctx, tx, b)
		if err != nil {
			return err
		}
		player, err := s.lockedPlayer(ctx, tx, pid)
		if err != nil {
			return err
		}
		if player.UID != owner {
			return ErrConflict
		}
		if err = s.permitted(Normal, actor, owner, locked[owner].Permission); err != nil {
			return err
		}
		if !slotSkin && !slotCape {
			out = player
			return nil
		}
		skin, cape := player.TIDSkin, player.TIDCape
		if slotSkin {
			skin = 0
		}
		if slotCape {
			cape = 0
		}
		modified := s.now()
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("players")+" SET tid_skin=?,tid_cape=?,last_modified=? WHERE pid=?", skin, cape, modified, pid); err != nil {
			return err
		}
		player.TIDSkin, player.TIDCape = skin, cape
		player.LastModified = modified.Format("2006-01-02 15:04:05")
		out = player
		return nil
	})
	return out, err
}

// AdminSetTexture keeps the frozen direct-TID admin ability with permission and
// existence checks; tid 0 clears the slot.
func (s *Service) AdminSetTexture(ctx context.Context, b *identity.BrowserSession, pid, tid int64, slot string) error {
	if slot != "skin" && slot != "cape" {
		return ErrTypeMismatch
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		owner, err := s.playerOwner(ctx, tx, pid)
		if err != nil {
			return err
		}
		locked, err := s.lockUsers(ctx, tx, b.User.UID, owner)
		if err != nil {
			return err
		}
		actor, err := s.Identity.CheckBrowserTx(ctx, tx, b)
		if err != nil {
			return err
		}
		player, err := s.lockedPlayer(ctx, tx, pid)
		if err != nil {
			return err
		}
		if player.UID != owner {
			return ErrConflict
		}
		if err = s.permitted(Admin, actor, owner, locked[owner].Permission); err != nil {
			return err
		}
		if tid != 0 {
			info, err := s.textureInfo(ctx, tx, tid)
			if err != nil {
				return err
			}
			if !slotMatches(info.Kind, slot) {
				return ErrTypeMismatch
			}
		}
		column := "tid_" + slot
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("players")+" SET "+column+"=?,last_modified=? WHERE pid=?", tid, s.now(), pid); err != nil {
			return err
		}
		return nil
	})
}

// GameUploadResult is the M3 business outcome consumed by the M4 protocol
// adapter (real Yggdrasil wire responses are out of scope here).
type GameUploadResult struct {
	TID    int64
	Closet bool
}

// GameUpload applies the frozen Yggdrasil upload policy: private texture, no
// web award, own same-hash reuse without storage fee, closet fee only once,
// and type/model conflicts rejected. Authorization is rechecked in-transaction.
func (s *Service) GameUpload(ctx context.Context, creds GameAuth, authorizer Authorizer, slot, model, name, stagingPath string, bytes int64) (GameUploadResult, error) {
	if authorizer == nil {
		return GameUploadResult{}, ErrNotAuthorized
	}
	if s.Textures == nil {
		return GameUploadResult{}, ErrNotAuthorized
	}
	if slot != "skin" && slot != "cape" {
		return GameUploadResult{}, ErrTypeMismatch
	}
	options, err := s.Site.Options(ctx)
	if err != nil {
		return GameUploadResult{}, err
	}
	kind := "steve"
	if slot == "cape" {
		kind = "cape"
	} else if model == "slim" {
		kind = "alex"
	}
	hash, err := textures.HashFile(stagingPath)
	if err != nil {
		return GameUploadResult{}, textures.ErrNotPNG
	}
	info, err := os.Stat(stagingPath)
	if err != nil || !info.Mode().IsRegular() {
		return GameUploadResult{}, textures.ErrNotPNG
	}
	bytes = info.Size()
	width, height, err := s.Textures.ProbePNG(stagingPath)
	if err != nil {
		return GameUploadResult{}, err
	}
	ratio := float64(width) / float64(height)
	if slot == "cape" {
		if ratio != 2 {
			return GameUploadResult{}, ErrTypeMismatch
		}
	} else {
		if ratio != 1 && ratio != 2 {
			return GameUploadResult{}, ErrTypeMismatch
		}
		if kind == "alex" && ratio != 1 {
			return GameUploadResult{}, ErrTypeMismatch
		}
		if width%64 != 0 || height%32 != 0 {
			return GameUploadResult{}, ErrTypeMismatch
		}
	}
	var result GameUploadResult
	err = s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if err = database.LockNamespaces(ctx, tx, s.Store, "player-name", "uuid"); err != nil {
			return err
		}
		if _, err = s.Textures.LockHash(ctx, tx, hash); err != nil {
			return err
		}
		pid, owner, err := s.resolveProfile(ctx, tx, creds.Profile)
		if err != nil {
			return err
		}
		locked, err := s.lockUsers(ctx, tx, creds.UID, owner)
		if err != nil {
			return err
		}
		if err = s.lockProfileRow(ctx, tx, pid, owner); err != nil {
			return err
		}
		if err = authorizer.Recheck(ctx, tx, creds, pid); err != nil {
			return err
		}
		if creds.Banned || creds.UID != owner {
			return ErrStaleCredential
		}
		user := locked[creds.UID]
		privateRate := site.Number(options["private_score_per_storage"])
		closetCost := site.Number(options["score_per_closet_item"])
		rows, err := tx.QueryContext(ctx, "SELECT tid,uploader,type,hash,size,public FROM "+s.Store.Table("textures")+" WHERE hash=? AND uploader=? ORDER BY tid LIMIT 1 FOR UPDATE", hash, creds.UID)
		if err != nil {
			return err
		}
		found := false
		var existing textureInfo
		if rows.Next() {
			found = true
			if err = rows.Scan(&existing.TID, &existing.Uploader, &existing.Kind, &existing.Hash, &existing.Size, &existing.Public); err != nil {
				rows.Close()
				return err
			}
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return err
		}
		if found {
			if existing.Kind != kind {
				return ErrTypeMismatch
			}
			member, err := s.inCloset(ctx, tx, creds.UID, existing.TID)
			if err != nil {
				return err
			}
			if !member {
				if user.Score < closetCost {
					return ErrLackScore
				}
				if _, err = tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("user_closet")+" (user_uid,texture_tid,item_name) VALUES (?,?,?)", creds.UID, existing.TID, name); err != nil {
					return err
				}
				if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score-? WHERE uid=?", closetCost, creds.UID); err != nil {
					return err
				}
			}
			result = GameUploadResult{TID: existing.TID, Closet: true}
		} else {
			size := (bytes + 1023) / 1024
			cost := privateRate*size + closetCost
			if user.Score < cost {
				return ErrLackScore
			}
			now := s.now()
			insert, err := tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("textures")+" (name,type,hash,size,uploader,public,likes,upload_at) VALUES (?,?,?,?,?,0,1,?)", name, kind, hash, size, creds.UID, now)
			if err != nil {
				return err
			}
			tid, err := insert.LastInsertId()
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("user_closet")+" (user_uid,texture_tid,item_name) VALUES (?,?,?)", creds.UID, tid, name); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score-? WHERE uid=?", cost, creds.UID); err != nil {
				return err
			}
			if err = s.Textures.PublishLocked(hash, stagingPath); err != nil {
				return err
			}
			if err = s.Textures.BumpGeneration(ctx, tx, hash); err != nil {
				return err
			}
			result = GameUploadResult{TID: tid}
		}
		column := "tid_" + slot
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("players")+" SET "+column+"=?,last_modified=? WHERE pid=?", result.TID, s.now(), pid); err != nil {
			return err
		}
		return nil
	})
	return result, err
}

// GameReset clears one slot for a verified game credential.
func (s *Service) GameReset(ctx context.Context, creds GameAuth, authorizer Authorizer, slot string) error {
	if authorizer == nil {
		return ErrNotAuthorized
	}
	if slot != "skin" && slot != "cape" {
		return ErrTypeMismatch
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		pid, owner, err := s.resolveProfile(ctx, tx, creds.Profile)
		if err != nil {
			return err
		}
		if _, err = s.lockUsers(ctx, tx, creds.UID, owner); err != nil {
			return err
		}
		if err = s.lockProfileRow(ctx, tx, pid, owner); err != nil {
			return err
		}
		if err = authorizer.Recheck(ctx, tx, creds, pid); err != nil {
			return err
		}
		if creds.Banned || creds.UID != owner {
			return ErrStaleCredential
		}
		column := "tid_" + slot
		_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("players")+" SET "+column+"=0,last_modified=? WHERE pid=?", s.now(), pid)
		return err
	})
}

// resolveProfile performs the unlocked name lookup used only to discover the
// participant set; the locking read happens after the shared users locks.
func (s *Service) resolveProfile(ctx context.Context, tx *sql.Tx, profile string) (int64, int64, error) {
	var pid, owner int64
	if err := tx.QueryRowContext(ctx, "SELECT pid,uid FROM "+s.Store.Table("players")+" WHERE name=?", profile).Scan(&pid, &owner); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, 0, ErrNotFound
		}
		return 0, 0, err
	}
	return pid, owner, nil
}

// lockProfileRow re-reads and locks the profile after users, preserving the
// design lock order and detecting participant changes.
func (s *Service) lockProfileRow(ctx context.Context, tx *sql.Tx, pid, expectedOwner int64) error {
	var currentOwner int64
	if err := tx.QueryRowContext(ctx, "SELECT uid FROM "+s.Store.Table("players")+" WHERE pid=? FOR UPDATE", pid).Scan(&currentOwner); err != nil {
		return err
	}
	if currentOwner != expectedOwner {
		return ErrConflict
	}
	return nil
}
