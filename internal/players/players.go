// Package players owns the player lifecycle and the persistent UUID/binding
// state introduced for Yggdrasil compatibility.
package players

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"
	"unicode/utf8"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/legacy/rules"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/textures"
)

var (
	ErrNotFound      = errors.New("players: player not found")
	ErrPlayerUsed    = errors.New("players: player name already exists")
	ErrNoPermission  = errors.New("players: no permission")
	ErrLackScore     = errors.New("players: not enough score")
	ErrInvalidName   = errors.New("players: invalid player name")
	ErrConflict      = errors.New("players: concurrent state change; retry")
	ErrTargetMissing = errors.New("players: target user not found")
)

// Intent separates the strict owner-only user commands from admin commands.
type Intent int

const (
	Normal Intent = iota
	Admin
)

// Player is the frozen player row shape serialized to browsers.
type Player struct {
	PID          int64  `json:"pid"`
	Name         string `json:"name"`
	UID          int64  `json:"uid"`
	TIDSkin      int64  `json:"tid_skin"`
	TIDCape      int64  `json:"tid_cape"`
	LastModified string `json:"last_modified"`
}

type Service struct {
	Store    *database.Store
	Identity *identity.Service
	Site     *site.Service
	Textures *textures.Service
	Now      func() time.Time
	// ModuleLock, when set, installs the module-state shared current read
	// inside GameUpload/GameReset transactions before the user locks. The
	// HTTP composition root wires it to the module manager; a nil hook
	// disables the gate (direct service tests).
	ModuleLock func(ctx context.Context, tx *sql.Tx) error
}

// WithTextures wires the shared texture service used by the game upload intent.
func (s *Service) WithTextures(tex *textures.Service) *Service {
	s.Textures = tex
	return s
}

func New(store *database.Store, id *identity.Service, view *site.Service, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{Store: store, Identity: id, Site: view, Now: now}
}

type lockedUser struct {
	UID        int64
	Permission int
	Score      int64
	Nickname   string
}

// lockUsers takes users rows in ascending UID order (the frozen lock order
// below namespaces and above auth versions).
func (s *Service) lockUsers(ctx context.Context, tx *sql.Tx, uids ...int64) (map[int64]lockedUser, error) {
	unique := map[int64]bool{}
	var list []int64
	for _, uid := range uids {
		if !unique[uid] {
			unique[uid] = true
			list = append(list, uid)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	locked := map[int64]lockedUser{}
	for _, uid := range list {
		var user lockedUser
		user.UID = uid
		if err := tx.QueryRowContext(ctx, "SELECT permission,score,nickname FROM "+s.Store.Table("users")+" WHERE uid=? FOR UPDATE", uid).Scan(&user.Permission, &user.Score, &user.Nickname); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrNotFound
			}
			return nil, err
		}
		locked[uid] = user
	}
	return locked, nil
}

func (s *Service) playerOwner(ctx context.Context, q queryer, pid int64) (int64, error) {
	var uid int64
	if err := q.QueryRowContext(ctx, "SELECT uid FROM "+s.Store.Table("players")+" WHERE pid=?", pid).Scan(&uid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	return uid, nil
}

func (s *Service) lockedPlayer(ctx context.Context, tx *sql.Tx, pid int64) (Player, error) {
	var out Player
	var modified time.Time
	err := tx.QueryRowContext(ctx, "SELECT pid,uid,name,tid_skin,tid_cape,last_modified FROM "+s.Store.Table("players")+" WHERE pid=? FOR UPDATE", pid).
		Scan(&out.PID, &out.UID, &out.Name, &out.TIDSkin, &out.TIDCape, &modified)
	if errors.Is(err, sql.ErrNoRows) {
		return Player{}, ErrNotFound
	}
	if err != nil {
		return Player{}, err
	}
	out.LastModified = modified.In(s.Site.Location).Format("2006-01-02 15:04:05")
	return out, nil
}

func (s *Service) permitted(intent Intent, actor *identity.User, owner int64, ownerPermission int) error {
	switch intent {
	case Normal:
		if owner != actor.UID {
			return ErrNoPermission
		}
	default:
		if actor.Permission < 1 {
			return ErrNoPermission
		}
		if owner != actor.UID && ownerPermission >= actor.Permission {
			return ErrNoPermission
		}
	}
	return nil
}

func (s *Service) validateName(options map[string]any, name string) error {
	min := int(site.Number(options["player_name_length_min"]))
	max := int(site.Number(options["player_name_length_max"]))
	length := utf8.RuneCountInString(name)
	if length < min || (max > 0 && length > max) {
		return ErrInvalidName
	}
	rule, _ := options["player_name_rule"].(string)
	custom, _ := options["custom_player_name_regexp"].(string)
	ok, err := rules.MatchPlayer(rule, custom, name)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidName
	}
	return nil
}

func (s *Service) nameTaken(ctx context.Context, q queryer, name string, ignorePID int64) (bool, error) {
	var count int64
	if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("players")+" WHERE name=? AND pid<>?", name, ignorePID).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// Authorize mirrors the frozen route middleware: the player binding must exist
// and the actor must be allowed before request-field validation runs.
func (s *Service) Authorize(ctx context.Context, b *identity.BrowserSession, pid int64, intent Intent) error {
	if b.User == nil {
		return ErrNoPermission
	}
	owner, err := s.playerOwner(ctx, s.Store.DB, pid)
	if err != nil {
		return err
	}
	var permission int
	if err = s.Store.DB.QueryRowContext(ctx, "SELECT permission FROM "+s.Store.Table("users")+" WHERE uid=?", owner).Scan(&permission); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	return s.permitted(intent, b.User, owner, permission)
}

// AddActor creates a player for the actor and charges the frozen
// score_per_player fee. UUID allocation stays lazy (frozen behaviour).
func (s *Service) AddActor(ctx context.Context, actor identity.Actor, name string) (Player, error) {
	var out Player
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if err := database.LockNamespaces(ctx, tx, s.Store, "player-name", "uuid"); err != nil {
			return err
		}
		current, _, err := s.recheckActor(ctx, tx, actor, playerWriteScope)
		if err != nil {
			return err
		}
		var addErr error
		out, addErr = s.AddTx(ctx, tx, current.UID, name, false)
		return addErr
	})
	return out, err
}

// AddTx is the transaction-scoped lifecycle used by registration (free) and by
// Add. The caller must hold player-name and uuid namespaces.
func (s *Service) AddTx(ctx context.Context, tx *sql.Tx, uid int64, name string, free bool) (Player, error) {
	options, err := s.Site.Options(ctx)
	if err != nil {
		return Player{}, err
	}
	if err = s.validateName(options, name); err != nil {
		return Player{}, err
	}
	var user lockedUser
	user.UID = uid
	if err = tx.QueryRowContext(ctx, "SELECT permission,score FROM "+s.Store.Table("users")+" WHERE uid=? FOR UPDATE", uid).Scan(&user.Permission, &user.Score); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Player{}, ErrNotFound
		}
		return Player{}, err
	}
	taken, err := s.nameTaken(ctx, tx, name, 0)
	if err != nil {
		return Player{}, err
	}
	if taken {
		return Player{}, ErrPlayerUsed
	}
	cost := int64(0)
	if !free {
		cost = site.Number(options["score_per_player"])
		if user.Score < cost {
			return Player{}, ErrLackScore
		}
	}
	now := s.now()
	result, err := tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("players")+" (uid,name,tid_skin,tid_cape,last_modified) VALUES (?,?,0,0,?)", uid, name, now)
	if err != nil {
		return Player{}, err
	}
	pid, err := result.LastInsertId()
	if err != nil {
		return Player{}, err
	}
	if cost > 0 {
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score-? WHERE uid=?", cost, uid); err != nil {
			return Player{}, err
		}
	}
	return Player{PID: pid, Name: name, UID: uid, LastModified: now.Format("2006-01-02 15:04:05")}, nil
}

// ListActor returns the players of the actor's account. The read is
// rechecked in the same transaction (Player.Read or Player.ReadWrite).
func (s *Service) ListActor(ctx context.Context, actor identity.Actor) ([]Player, error) {
	out := []Player{}
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		current, _, err := s.recheckActor(ctx, tx, actor, playerReadScope)
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, "SELECT pid,uid,name,tid_skin,tid_cape,last_modified FROM "+s.Store.Table("players")+" WHERE uid=?", current.UID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var player Player
			var modified time.Time
			if err = rows.Scan(&player.PID, &player.UID, &player.Name, &player.TIDSkin, &player.TIDCape, &modified); err != nil {
				return err
			}
			player.LastModified = modified.In(s.Site.Location).Format("2006-01-02 15:04:05")
			out = append(out, player)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Count returns the number of players of an account for the player page.
func (s *Service) Count(ctx context.Context, uid int64) (int64, error) {
	var count int64
	err := s.Store.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("players")+" WHERE uid=?", uid).Scan(&count)
	return count, err
}

// Rename renames a player and keeps UUID/binding consistent in the same
// transaction (frozen v4 rename keeps the UUID, v3 follows the name).
func (s *Service) RenameActor(ctx context.Context, actor identity.Actor, pid int64, name string, intent Intent) (Player, string, error) {
	options, err := s.Site.Options(ctx)
	if err != nil {
		return Player{}, "", err
	}
	var out Player
	var oldName string
	err = s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if err = database.LockNamespaces(ctx, tx, s.Store, "player-name", "uuid"); err != nil {
			return err
		}
		owner, err := s.playerOwner(ctx, tx, pid)
		if err != nil {
			return err
		}
		current, locked, err := s.recheckActor(ctx, tx, actor, scopeForIntent(intent, true), owner)
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
		oldName = player.Name
		if err = s.permitted(intent, current, owner, locked[owner].Permission); err != nil {
			return err
		}
		if err = s.validateName(options, name); err != nil {
			return err
		}
		ignore := pid
		if intent == Admin {
			// The frozen admin endpoint does not ignore the current row.
			ignore = 0
		}
		taken, err := s.nameTaken(ctx, tx, name, ignore)
		if err != nil {
			return err
		}
		if taken {
			return ErrPlayerUsed
		}
		_, warning, err := s.renameUUIDLocked(ctx, tx, pid, player.Name, name, algorithmOption(options))
		if err != nil {
			return err
		}
		_ = warning // recorded by the package record; player row still changes
		modified := s.now()
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("players")+" SET name=?,last_modified=? WHERE pid=?", name, modified, pid); err != nil {
			return err
		}
		player.Name = name
		player.LastModified = modified.Format("2006-01-02 15:04:05")
		out = player
		return nil
	})
	return out, oldName, err
}

// Transfer changes the owner of a player (admin only) and bumps the binding
// version when the owner actually changes.
func (s *Service) TransferActor(ctx context.Context, actor identity.Actor, pid, target int64) (TransferResult, error) {
	options, err := s.Site.Options(ctx)
	if err != nil {
		return TransferResult{}, err
	}
	var result TransferResult
	err = s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if err = database.LockNamespaces(ctx, tx, s.Store, "player-name", "uuid"); err != nil {
			return err
		}
		owner, err := s.playerOwner(ctx, tx, pid)
		if err != nil {
			return err
		}
		var exists int64
		if err = tx.QueryRowContext(ctx, "SELECT uid FROM "+s.Store.Table("users")+" WHERE uid=?", target).Scan(&exists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrTargetMissing
			}
			return err
		}
		current, locked, err := s.recheckActor(ctx, tx, actor, playersAdminWriteScope, owner, target)
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
		if owner == target {
			_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("players")+" SET last_modified=? WHERE pid=?", s.now(), pid)
			result.PlayerName = player.Name
			result.OwnerNickname = locked[target].Nickname
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("players")+" SET uid=?,last_modified=? WHERE pid=?", target, s.now(), pid); err != nil {
			return err
		}
		result.PlayerName = player.Name
		result.OwnerNickname = locked[target].Nickname
		binding, err := s.bindingTx(ctx, tx, pid)
		if err != nil {
			return err
		}
		if binding != nil {
			return s.bumpBinding(ctx, tx, pid)
		}
		_, typed := s.ensureUUIDLocked(ctx, tx, pid, player.Name, algorithmOption(options))
		if typed != nil {
			if errors.Is(typed, ErrUUIDUnavailable) || errors.Is(typed, ErrUUIDAmbiguous) ||
				errors.Is(typed, ErrUUIDConflict) || errors.Is(typed, ErrUUIDMalformed) {
				return nil
			}
			return typed
		}
		return nil
	})
	return result, err
}

// TransferResult carries the browser success-message fields.
type TransferResult struct {
	PlayerName    string
	OwnerNickname string
}

// Delete removes a player. Owner deletion refunds score_per_player when
// return_score is enabled (including free registration players); admin deletes
// never refund.
func (s *Service) DeleteActor(ctx context.Context, actor identity.Actor, pid int64, intent Intent) (string, error) {
	options, err := s.Site.Options(ctx)
	if err != nil {
		return "", err
	}
	var deleted string
	err = s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if err = database.LockNamespaces(ctx, tx, s.Store, "player-name", "uuid"); err != nil {
			return err
		}
		owner, err := s.playerOwner(ctx, tx, pid)
		if err != nil {
			return err
		}
		current, locked, err := s.recheckActor(ctx, tx, actor, scopeForIntent(intent, true), owner)
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
		if err = s.permitted(intent, current, owner, locked[owner].Permission); err != nil {
			return err
		}
		deleted = player.Name
		if err = s.deleteBinding(ctx, tx, pid); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("players")+" WHERE pid=?", pid); err != nil {
			return err
		}
		if intent == Normal && site.Truth(options["return_score"]) {
			if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score+? WHERE uid=?", site.Number(options["score_per_player"]), owner); err != nil {
				return err
			}
		}
		return nil
	})
	return deleted, err
}

// DeleteAllTx removes every player of an account and its bindings. The caller
// (account delete) already holds the namespaces and the users lock.
func (s *Service) DeleteAllTx(ctx context.Context, tx *sql.Tx, uid int64) error {
	rows, err := tx.QueryContext(ctx, "SELECT pid FROM "+s.Store.Table("players")+" WHERE uid=? ORDER BY pid FOR UPDATE", uid)
	if err != nil {
		return err
	}
	var pids []int64
	for rows.Next() {
		var pid int64
		if err = rows.Scan(&pid); err != nil {
			rows.Close()
			return err
		}
		pids = append(pids, pid)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, pid := range pids {
		if err = s.deleteBinding(ctx, tx, pid); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("players")+" WHERE uid=?", uid)
	return err
}

// ClearTexturesTx clears the given texture ids from an account's players. It
// is the downstream primitive for M3-04; callers must already hold the
// shared-classification locks and never change binding versions here.
func (s *Service) ClearTexturesTx(ctx context.Context, tx *sql.Tx, uid int64, tids []int64) (int64, error) {
	if len(tids) == 0 {
		return 0, nil
	}
	wanted := map[int64]bool{}
	marks := make([]any, 0, len(tids))
	for _, tid := range tids {
		if !wanted[tid] {
			wanted[tid] = true
			marks = append(marks, tid)
		}
	}
	placeholders := ""
	for i := 0; i < len(wanted); i++ {
		if i > 0 {
			placeholders += ","
		}
		placeholders += "?"
	}
	rows, err := tx.QueryContext(ctx, "SELECT pid,tid_skin,tid_cape FROM "+s.Store.Table("players")+" WHERE uid=? AND (tid_skin IN ("+placeholders+") OR tid_cape IN ("+placeholders+")) ORDER BY pid FOR UPDATE", append(append([]any{uid}, marks...), marks...)...)
	if err != nil {
		return 0, err
	}
	type hit struct {
		pid  int64
		skin int64
		cape int64
	}
	var hits []hit
	for rows.Next() {
		var h hit
		if err = rows.Scan(&h.pid, &h.skin, &h.cape); err != nil {
			rows.Close()
			return 0, err
		}
		hits = append(hits, h)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	var changed int64
	for _, h := range hits {
		skin, cape := h.skin, h.cape
		if wanted[skin] {
			skin = 0
		}
		if wanted[cape] {
			cape = 0
		}
		if skin == h.skin && cape == h.cape {
			continue
		}
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("players")+" SET tid_skin=?,tid_cape=?,last_modified=? WHERE pid=?", skin, cape, s.now(), h.pid); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}
