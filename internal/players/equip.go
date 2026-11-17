package players

import (
	"context"
	"database/sql"
	"errors"
	"os"

	"paradise-cosmetics-studio/internal/database"
	"paradise-cosmetics-studio/internal/gameauth"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/site"
	"paradise-cosmetics-studio/internal/textures"
)

// Authorizer rechecks a synthetic game credential inside the business
// transaction. The canonical definitions live in internal/gameauth so
// the Yggdrasil verifier can implement them without an import cycle;
// these aliases preserve the M3 names.
type Authorizer = gameauth.Authorizer
type CredentialAuthorizer = gameauth.CredentialAuthorizer
type ProfileAuthorizer = gameauth.ProfileAuthorizer
type GameAuth = gameauth.GameAuth

var (
	ErrStaleCredential = errors.New("players: credential no longer owns this profile")
	ErrTypeMismatch    = errors.New("players: texture type does not match the slot")
	ErrNotAuthorized   = errors.New("players: game credential rejected")
	// ErrNotInCloset reports an existing texture absent from the current user's closet.
	ErrNotInCloset = errors.New("players: texture is not in the user's closet")
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
func (s *Service) SetTexturesActor(ctx context.Context, actor identity.Actor, pid int64, skin, cape *int64) (Player, error) {
	var out Player
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		owner, err := s.playerOwner(ctx, tx, pid)
		if err != nil {
			return err
		}
		current, locked, err := s.recheckActor(ctx, tx, actor, playerWriteScope, owner)
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
		if err = s.permitted(Normal, current, owner, locked[owner].Permission); err != nil {
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
			member, err := s.inCloset(ctx, tx, current.UID, *slot.tid)
			if err != nil {
				return err
			}
			if !member {
				return ErrNotInCloset
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
func (s *Service) ClearTexturesActor(ctx context.Context, actor identity.Actor, pid int64, slotSkin, slotCape bool) (Player, error) {
	var out Player
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		owner, err := s.playerOwner(ctx, tx, pid)
		if err != nil {
			return err
		}
		current, locked, err := s.recheckActor(ctx, tx, actor, playerWriteScope, owner)
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
		if err = s.permitted(Normal, current, owner, locked[owner].Permission); err != nil {
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
func (s *Service) AdminSetTextureActor(ctx context.Context, actor identity.Actor, pid, tid int64, slot string) error {
	if slot != "skin" && slot != "cape" {
		return ErrTypeMismatch
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		owner, err := s.playerOwner(ctx, tx, pid)
		if err != nil {
			return err
		}
		current, locked, err := s.recheckActor(ctx, tx, actor, playersAdminWriteScope, owner)
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
		if err = s.permitted(Admin, current, owner, locked[owner].Permission); err != nil {
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
		// Lock order (integration-design section 3): player-name/uuid
		// namespaces -> hash coordination -> module-state shared lock (held
		// by the caller/HTTP layer) -> users -> version/token (credential
		// stage) -> existing texture/closet current reads -> player/binding
		// (profile stage) -> final balance check -> publish/write -> commit.
		// Nothing is published to the texture store before the profile
		// stage succeeds.
		if err = database.LockNamespaces(ctx, tx, s.Store, "player-name", "uuid"); err != nil {
			return err
		}
		if _, err = s.Textures.LockHash(ctx, tx, hash); err != nil {
			return err
		}
		// Module-state shared lock (wired by the HTTP composition root)
		// sits before the user locks, matching the writer order.
		if s.ModuleLock != nil {
			if err := s.ModuleLock(ctx, tx); err != nil {
				return err
			}
		}
		pid, owner, err := s.resolveGameProfile(ctx, tx, creds)
		if err != nil {
			return err
		}
		locked, err := s.lockUsers(ctx, tx, creds.UID, owner)
		if err != nil {
			return err
		}
		twoStage := false
		if credential, ok := authorizer.(CredentialAuthorizer); ok {
			if err = credential.RecheckCredentialTx(ctx, tx, creds); err != nil {
				return err
			}
			twoStage = true
		}
		user := locked[creds.UID]
		privateRate := site.Number(options["private_score_per_storage"])
		closetCost := site.Number(options["score_per_closet_item"])
		// Texture/closet plan: current reads only. Writes are deferred
		// until after the profile stage, so a failed target recheck
		// leaves no texture, closet, score, or file change behind.
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
		planCost := int64(0)
		needCloset := false
		isNew := false
		if found {
			if existing.Kind != kind {
				return ErrTypeMismatch
			}
			member, err := s.inCloset(ctx, tx, creds.UID, existing.TID)
			if err != nil {
				return err
			}
			if !member {
				needCloset = true
				planCost = closetCost
			}
		} else {
			isNew = true
			size := (bytes + 1023) / 1024
			planCost = privateRate*size + closetCost
		}
		if err = s.lockProfileRow(ctx, tx, pid, owner); err != nil {
			return err
		}
		if twoStage {
			if profile, ok := authorizer.(ProfileAuthorizer); ok {
				if err = profile.RecheckProfileTx(ctx, tx, creds, pid); err != nil {
					return err
				}
			} else if err = authorizer.Recheck(ctx, tx, creds, pid); err != nil {
				return err
			}
		} else if err = authorizer.Recheck(ctx, tx, creds, pid); err != nil {
			return err
		}
		if creds.Banned || creds.UID != owner {
			return ErrStaleCredential
		}
		if user.Score < planCost {
			return ErrLackScore
		}
		if found {
			if needCloset {
				if _, err = tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("user_closet")+" (user_uid,texture_tid,item_name) VALUES (?,?,?)", creds.UID, existing.TID, name); err != nil {
					return err
				}
				if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score-? WHERE uid=?", planCost, creds.UID); err != nil {
					return err
				}
			}
			result = GameUploadResult{TID: existing.TID, Closet: true}
		} else if isNew {
			size := (bytes + 1023) / 1024
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
			if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score-? WHERE uid=?", planCost, creds.UID); err != nil {
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
		// Lock order: module-state shared lock -> users ->
		// version/token (credential stage) -> player/binding (profile
		// stage). No hash lock is taken for a reset.
		if s.ModuleLock != nil {
			if err := s.ModuleLock(ctx, tx); err != nil {
				return err
			}
		}
		pid, owner, err := s.resolveGameProfile(ctx, tx, creds)
		if err != nil {
			return err
		}
		if _, err = s.lockUsers(ctx, tx, creds.UID, owner); err != nil {
			return err
		}
		twoStage := false
		if credential, ok := authorizer.(CredentialAuthorizer); ok {
			if err = credential.RecheckCredentialTx(ctx, tx, creds); err != nil {
				return err
			}
			twoStage = true
		}
		if err = s.lockProfileRow(ctx, tx, pid, owner); err != nil {
			return err
		}
		if twoStage {
			if profile, ok := authorizer.(ProfileAuthorizer); ok {
				if err = profile.RecheckProfileTx(ctx, tx, creds, pid); err != nil {
					return err
				}
			} else if err = authorizer.Recheck(ctx, tx, creds, pid); err != nil {
				return err
			}
		} else if err = authorizer.Recheck(ctx, tx, creds, pid); err != nil {
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
// A ProfileUUID target resolves through the current UUID binding; a plain
// Profile resolves by player name, falling back to a UUID-form value so a
// protocol adapter may pass the request UUID directly as Profile.
func (s *Service) resolveProfile(ctx context.Context, tx *sql.Tx, profile string) (int64, int64, error) {
	return s.resolveGameProfile(ctx, tx, GameAuth{Profile: profile})
}

func (s *Service) resolveGameProfile(ctx context.Context, tx *sql.Tx, creds GameAuth) (int64, int64, error) {
	if hex, ok := uuidHexForm(creds.ProfileUUID); ok {
		var pid, owner int64
		err := tx.QueryRowContext(ctx, "SELECT p.pid,p.uid FROM "+s.Store.Table("go_uuid_bindings")+" b JOIN "+s.Store.Table("players")+" p ON p.pid=b.pid WHERE b.uuid=?", hex).Scan(&pid, &owner)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, 0, ErrNotFound
		}
		if err != nil {
			return 0, 0, err
		}
		return pid, owner, nil
	}
	var pid, owner int64
	if err := tx.QueryRowContext(ctx, "SELECT pid,uid FROM "+s.Store.Table("players")+" WHERE name=?", creds.Profile).Scan(&pid, &owner); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if hex, formOK := uuidHexForm(creds.Profile); formOK {
				return s.resolveGameProfile(ctx, tx, GameAuth{ProfileUUID: hex})
			}
			return 0, 0, ErrNotFound
		}
		return 0, 0, err
	}
	return pid, owner, nil
}

// uuidHexForm normalizes a dashed or hex UUID to its 32-char lowercase hex
// binding form, reporting whether the value has UUID form at all.
func uuidHexForm(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	clean := make([]byte, 0, 32)
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '-' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			clean = append(clean, c)
			continue
		}
		return "", false
	}
	if len(clean) != 32 {
		return "", false
	}
	return string(clean), true
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
