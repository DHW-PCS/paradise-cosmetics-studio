// Actor entry points for M4-03 core APIs (account slice).
//
// The browser AdminChange entry is a thin wrapper: it builds a real
// browser Actor and delegates to AdminChangeActor, which owns the single
// business transaction. CurrentActor is the User.Read current-read for
// GET /user. An Actor is never turned into a forged BrowserSession.
//
// Lock order in each transaction: namespaces (where the operation
// already held them) -> Actor.PrepareTx (OAuth client row) ->
// users ascending (identity.LockUsersTx) -> Actor.RecheckTx
// (version, credential and current user row, with the scope below)
// -> business rows. Scope spelling is interpreted centrally by the
// Actor base; browser actors ignore it while the current permission
// rules still run for them. No verified check is added: the frozen
// core API routes never had the browser verified middleware.
package account

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/legacy/password"
)

var (
	userReadScope             = identity.ScopeRequirement{AllOf: []string{"User.Read"}}
	usersManagementWriteScope = identity.ScopeRequirement{AllOf: []string{"UsersManagement.ReadWrite"}}
)

// CurrentUser is the frozen UserController@user serialization: the
// user row with password, ip, remember_token and verification_token
// hidden. Dates use Carbon's default JSON format, matching the admin
// users list.
type CurrentUser struct {
	UID        int64   `json:"uid"`
	Email      string  `json:"email"`
	Nickname   string  `json:"nickname"`
	Locale     *string `json:"locale"`
	Avatar     int64   `json:"avatar"`
	Score      int64   `json:"score"`
	Permission int     `json:"permission"`
	IsDarkMode bool    `json:"is_dark_mode"`
	LastSignAt string  `json:"last_sign_at"`
	RegisterAt string  `json:"register_at"`
	Verified   bool    `json:"verified"`
}

// recheckActor runs PrepareTx -> LockUsersTx -> RecheckTx in the
// caller's transaction and returns the current user. participants is
// the complete set besides the actor; the actor UID is always
// included. A missing participant reports identity.ErrStale.
func (s *Service) recheckActor(ctx context.Context, tx *sql.Tx, actor identity.Actor, req identity.ScopeRequirement, participants ...int64) (*identity.User, error) {
	if actor == nil || actor.UID() == 0 {
		return nil, identity.ErrSession
	}
	if err := actor.PrepareTx(ctx, tx); err != nil {
		return nil, err
	}
	all := append([]int64{actor.UID()}, participants...)
	if err := s.Identity.LockUsersTx(ctx, tx, all); err != nil {
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

// CurrentActor returns the actor's own current user row, authorized
// and read inside the single business transaction. The scope is
// exactly User.Read from the frozen api.php entry.
func (s *Service) CurrentActor(ctx context.Context, actor identity.Actor) (*CurrentUser, error) {
	var out *CurrentUser
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err := s.recheckActor(ctx, tx, actor, userReadScope); err != nil {
			return err
		}
		var user CurrentUser
		var lastSign, registered time.Time
		var locale sql.NullString
		err := tx.QueryRowContext(ctx, "SELECT uid,email,nickname,locale,avatar,score,permission,is_dark_mode,last_sign_at,register_at,verified FROM "+s.Store.Table("users")+" WHERE uid=?", actor.UID()).
			Scan(&user.UID, &user.Email, &user.Nickname, &locale, &user.Avatar, &user.Score, &user.Permission, &user.IsDarkMode, &lastSign, &registered, &user.Verified)
		if errors.Is(err, sql.ErrNoRows) {
			return identity.ErrSession
		}
		if err != nil {
			return err
		}
		if locale.Valid {
			value := locale.String
			user.Locale = &value
		}
		user.LastSignAt = lastSign.UTC().Format("2006-01-02T15:04:05.000000Z")
		user.RegisterAt = registered.UTC().Format("2006-01-02T15:04:05.000000Z")
		out = &user
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AdminChangeActor is the Actor form of AdminChange for the seven
// frozen UsersManagement.ReadWrite actions (email, verification,
// nickname, password, score, permission, delete). It rechecks the
// current admin permission from the rechecked user and the original
// target permission rule (target must not outrank the actor) inside
// the same transaction; the business delete/ban/revocation kernels
// are the existing ones, not copies.
func (s *Service) AdminChangeActor(ctx context.Context, actor identity.Actor, target int64, action, value string) error {
	var hash string
	var err error
	if action == "password" {
		if err = password.ValidateAdminReset(value); err != nil {
			return err
		}
		hash, err = s.hash(ctx, value)
		if err != nil {
			return err
		}
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		switch action {
		case "email":
			if err := database.LockNamespaces(ctx, tx, s.Store, "email"); err != nil {
				return err
			}
		case "delete":
			if err := database.LockNamespaces(ctx, tx, s.Store, "email", "mail", "player-name", "registration", "uuid"); err != nil {
				return err
			}
		}
		if actor == nil {
			return identity.ErrSession
		}
		participants := []int64{}
		if target != actor.UID() {
			participants = append(participants, target)
		}
		current, err := s.recheckActor(ctx, tx, actor, usersManagementWriteScope, participants...)
		if err != nil {
			if errors.Is(err, identity.ErrStale) {
				return ErrNotFound
			}
			return err
		}
		// The target row is already locked by the ascending pre-lock;
		// read its current permission for the frozen rule.
		var permission int
		if err := tx.QueryRowContext(ctx, "SELECT permission FROM "+s.Store.Table("users")+" WHERE uid=?", target).Scan(&permission); errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if current.Permission < 1 || (target != current.UID && permission >= current.Permission) {
			return ErrForbidden
		}
		switch action {
		case "password":
			if err = s.Identity.RevokeUID(ctx, tx, target); err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET password=? WHERE uid=?", hash, target)
		case "permission":
			p, parseErr := strconv.ParseInt(value, 10, 64)
			if parseErr != nil || (p != -1 && p != 0 && p != 1) {
				return ErrForbidden
			}
			if target == current.UID || (p == 1 && current.Permission < 2) {
				return ErrForbidden
			}
			if p == -1 {
				if err = s.Identity.RevokeUID(ctx, tx, target); err != nil {
					return err
				}
				// Keep the profile Last-Modified visible to clients when the
				// owner is banned (M3 design: ban updates player timestamps).
				if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("players")+" SET last_modified=? WHERE uid=?", s.Now().In(s.Site.Location), target); err != nil {
					return err
				}
			}
			_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET permission=? WHERE uid=?", p, target)
		case "delete":
			err = s.deleteUser(ctx, tx, target)
		case "email":
			if err = s.emailAvailable(ctx, tx, value, target); err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET email=? WHERE uid=?", value, target)
		case "score":
			score, parseErr := strconv.ParseInt(value, 10, 64)
			if parseErr != nil {
				return parseErr
			}
			_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=? WHERE uid=?", score, target)
		case "nickname":
			_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET nickname=? WHERE uid=?", value, target)
		case "verification":
			_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET verified=NOT verified WHERE uid=?", target)
		default:
			return ErrForbidden
		}
		return err
	})
}
