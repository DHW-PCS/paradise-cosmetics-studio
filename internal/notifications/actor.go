// Actor entry points for M4-03 core APIs (notifications slice).
//
// UnreadActor/ReadActor are the frozen Notification.Read entries;
// SendActor is the frozen admin Notification.ReadWrite entry and
// additionally rechecks the current admin permission from the
// rechecked user. The original UID-only entries keep their
// signatures and semantics (the browser HTTP layer passes the
// session UID) and share the Tx kernels below; they never forge a
// BrowserSession and SendActor never validates first and then writes
// unauthenticated: target resolution, the ascending users pre-lock,
// RecheckTx and every insert share the one business transaction.
//
// The ascending users pre-lock uses the shared identity.LockUsersTx
// helper; the Actor interface supplies PrepareTx and RecheckTx.
// Lock order:
// discovery (target resolution) -> Actor.PrepareTx -> users
// ascending -> Actor.RecheckTx -> notification rows. No verified
// check is added.
package notifications

import (
	"context"
	"database/sql"
	"errors"

	"paradise-cosmetics-studio/internal/identity"
)

var (
	notificationReadScope      = identity.ScopeRequirement{AllOf: []string{"Notification.Read"}}
	notificationReadWriteScope = identity.ScopeRequirement{AllOf: []string{"Notification.ReadWrite"}}
)

// ErrNoPermission reports a non-admin actor attempting the admin
// send entry.
var ErrNoPermission = errors.New("notifications: no permission")

// recheckActor runs PrepareTx -> identity.LockUsersTx -> RecheckTx in the
// caller's transaction and returns the current user.
func (s *Service) recheckActor(ctx context.Context, tx *sql.Tx, actor identity.Actor, req identity.ScopeRequirement, participants ...int64) (*identity.User, error) {
	if actor == nil || actor.UID() == 0 {
		return nil, identity.ErrSession
	}
	if err := actor.PrepareTx(ctx, tx); err != nil {
		return nil, err
	}
	all := append([]int64{actor.UID()}, participants...)
	if err := identity.LockUsersTx(ctx, tx, s.Store, all); err != nil {
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

// UnreadActor lists the actor's own unread notifications.
func (s *Service) UnreadActor(ctx context.Context, actor identity.Actor) ([]Unread, error) {
	var out []Unread
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		current, err := s.recheckActor(ctx, tx, actor, notificationReadScope)
		if err != nil {
			return err
		}
		out, err = s.unreadTx(ctx, tx, current.UID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ReadActor marks one of the actor's own unread notifications as
// read and returns its content. Another user's notification id is
// ErrNotFound, never a cross-user read.
func (s *Service) ReadActor(ctx context.Context, actor identity.Actor, id string) (*Read, error) {
	var out *Read
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		current, err := s.recheckActor(ctx, tx, actor, notificationReadScope)
		if err != nil {
			return err
		}
		out, err = s.readTx(ctx, tx, current.UID, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SendActor creates one site message per target user for an admin
// Actor, keeping the frozen receiver semantics (all/normal/uid/email)
// inside the same business transaction as the recheck.
func (s *Service) SendActor(ctx context.Context, actor identity.Actor, in SendInput) error {
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if actor == nil {
			return identity.ErrSession
		}
		// Discovery only fixes the participant set; it never authorizes.
		targets, err := s.resolveTargetsTx(ctx, tx, in)
		if err != nil {
			return err
		}
		current, err := s.recheckActor(ctx, tx, actor, notificationReadWriteScope, targets...)
		if err != nil {
			return err
		}
		if current.Permission < 1 {
			return ErrNoPermission
		}
		return s.sendToTx(ctx, tx, in, targets)
	})
}
