// Actor entry points for M4-03 core APIs (players slice).
//
// The original BrowserSession methods are thin wrappers: they build a
// real browser Actor with identity.NewBrowserActor and delegate to the
// *Actor methods, which own the single business transaction. The
// OAuth flavor is supplied by the oauthserver package as an
// identity.Actor; it is never wrapped in a BrowserSession and this
// package never calls a Begin/Commit Validate path.
//
// Lock plan inside every *Actor transaction (discovery only fixes the
// participant set; it never authorizes):
//
//	namespaces (player-name/uuid, where the operation already held
//	them) -> Actor.PrepareTx (OAuth client row) -> users ascending
//	(identity.LockUsersTx) -> Actor.RecheckTx (version, credential
//	and current user row, with the scope requirement below) ->
//	business resource rows.
//
// A participant changed after discovery (owner no longer matches, a
// participant row vanished) reports ErrConflict; there is no automatic
// retry. Browser actors ignore the scope requirement in RecheckTx;
// the current permission and owner checks still run for them. No
// verified check is added here: core API routes never had the browser
// `verified` middleware.
package players

import (
	"context"
	"database/sql"
	"errors"

	"paradise-cosmetics-studio/internal/identity"
)

// Scope requirements fixed by the M4-03 core API contract. The OAuth
// adapter interprets them; browser actors ignore them.
var (
	playerReadScope        = identity.ScopeRequirement{AnyOf: []string{"Player.Read", "Player.ReadWrite"}}
	playerWriteScope       = identity.ScopeRequirement{AllOf: []string{"Player.ReadWrite"}}
	playersAdminReadScope  = identity.ScopeRequirement{AnyOf: []string{"PlayersManagement.Read", "PlayersManagement.ReadWrite"}}
	playersAdminWriteScope = identity.ScopeRequirement{AllOf: []string{"PlayersManagement.ReadWrite"}}
)

// scopeForIntent selects the requirement for Rename/Delete/Authorize,
// which carry an Intent: normal uses the Player scopes, admin uses the
// PlayersManagement scopes.
func scopeForIntent(intent Intent, write bool) identity.ScopeRequirement {
	if intent == Admin {
		if write {
			return playersAdminWriteScope
		}
		return playersAdminReadScope
	}
	if write {
		return playerWriteScope
	}
	return playerReadScope
}

// browserActor builds the real browser Actor for a BrowserSession.
// Anonymous sessions are rejected by NewBrowserActor.
func (s *Service) browserActor(b *identity.BrowserSession) (identity.Actor, error) {
	return s.Identity.NewBrowserActor(b)
}

// recheckActor runs PrepareTx -> LockUsersTx -> RecheckTx in the
// caller's transaction and returns the current user plus the locked
// participant rows (permission/score/nickname) for permitted checks.
// participants must be the complete discovery set besides the actor;
// the actor UID is always included. It never begins or commits.
func (s *Service) recheckActor(ctx context.Context, tx *sql.Tx, actor identity.Actor, req identity.ScopeRequirement, participants ...int64) (*identity.User, map[int64]lockedUser, error) {
	if actor == nil || actor.UID() == 0 {
		return nil, nil, ErrNoPermission
	}
	if err := actor.PrepareTx(ctx, tx); err != nil {
		return nil, nil, err
	}
	all := append([]int64{actor.UID()}, participants...)
	if err := s.Identity.LockUsersTx(ctx, tx, all); err != nil {
		if errors.Is(err, identity.ErrStale) {
			return nil, nil, ErrConflict
		}
		return nil, nil, err
	}
	current, err := actor.RecheckTx(ctx, tx, req)
	if err != nil {
		return nil, nil, err
	}
	if current == nil || current.UID != actor.UID() {
		return nil, nil, ErrConflict
	}
	locked, err := s.lockUsers(ctx, tx, all...)
	if err != nil {
		return nil, nil, err
	}
	return current, locked, nil
}

// AuthorizeActor is the Actor form of Authorize: same owner/admin
// check, rechecked in one transaction with the write scope for the
// intent (every current Authorize call site precedes a write). The
// business *Actor method rechecks again inside its own transaction;
// this entry only preserves the frozen middleware-before-validation
// ordering for HTTP callers.
func (s *Service) AuthorizeActor(ctx context.Context, actor identity.Actor, pid int64, intent Intent) error {
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		owner, err := s.playerOwner(ctx, tx, pid)
		if err != nil {
			return err
		}
		current, locked, err := s.recheckActor(ctx, tx, actor, scopeForIntent(intent, true), owner)
		if err != nil {
			return err
		}
		return s.permitted(intent, current, owner, locked[owner].Permission)
	})
}

// Browser wrappers. Each preserves the original BrowserSession
// signature and result shape and shares the *Actor kernel below.

func (s *Service) Add(ctx context.Context, b *identity.BrowserSession, name string) (Player, error) {
	actor, err := s.browserActor(b)
	if err != nil {
		return Player{}, err
	}
	return s.AddActor(ctx, actor, name)
}

func (s *Service) Rename(ctx context.Context, b *identity.BrowserSession, pid int64, name string, intent Intent) (Player, string, error) {
	actor, err := s.browserActor(b)
	if err != nil {
		return Player{}, "", err
	}
	return s.RenameActor(ctx, actor, pid, name, intent)
}

func (s *Service) Delete(ctx context.Context, b *identity.BrowserSession, pid int64, intent Intent) (string, error) {
	actor, err := s.browserActor(b)
	if err != nil {
		return "", err
	}
	return s.DeleteActor(ctx, actor, pid, intent)
}

func (s *Service) Transfer(ctx context.Context, b *identity.BrowserSession, pid, target int64) (TransferResult, error) {
	actor, err := s.browserActor(b)
	if err != nil {
		return TransferResult{}, err
	}
	return s.TransferActor(ctx, actor, pid, target)
}

func (s *Service) List(ctx context.Context, b *identity.BrowserSession) ([]Player, error) {
	actor, err := s.browserActor(b)
	if err != nil {
		return nil, err
	}
	return s.ListActor(ctx, actor)
}

func (s *Service) SetTextures(ctx context.Context, b *identity.BrowserSession, pid int64, skin, cape *int64) (Player, error) {
	actor, err := s.browserActor(b)
	if err != nil {
		return Player{}, err
	}
	return s.SetTexturesActor(ctx, actor, pid, skin, cape)
}

func (s *Service) ClearTextures(ctx context.Context, b *identity.BrowserSession, pid int64, slotSkin, slotCape bool) (Player, error) {
	actor, err := s.browserActor(b)
	if err != nil {
		return Player{}, err
	}
	return s.ClearTexturesActor(ctx, actor, pid, slotSkin, slotCape)
}

func (s *Service) AdminSetTexture(ctx context.Context, b *identity.BrowserSession, pid, tid int64, slot string) error {
	actor, err := s.browserActor(b)
	if err != nil {
		return err
	}
	return s.AdminSetTextureActor(ctx, actor, pid, tid, slot)
}
