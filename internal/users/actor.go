// Actor entry points for M4-03 core APIs (admin users slice).
//
// ListActor is the frozen GET /admin/users entry: scope is
// UsersManagement.Read or UsersManagement.ReadWrite (AnyOf), and the
// current admin permission is rechecked from the rechecked user in
// the same transaction. The original List entry keeps its signature
// and semantics (the browser HTTP layer gates admin) and shares the
// listTx kernel below; it does not forge a BrowserSession.
//
// The ascending users pre-lock uses the shared identity.LockUsersTx
// helper; the Actor interface supplies PrepareTx and RecheckTx.
// Lock order:
// Actor.PrepareTx -> users ascending -> Actor.RecheckTx -> list
// read. No verified check is added.
package users

import (
	"context"
	"database/sql"
	"errors"

	"paradise-cosmetics-studio/internal/identity"
)

var usersManagementReadScope = identity.ScopeRequirement{AnyOf: []string{"UsersManagement.Read", "UsersManagement.ReadWrite"}}

var ErrNoPermission = errors.New("users: no permission")

// ListActor returns the frozen admin users paginator for an admin
// Actor, authorized and read inside the single business transaction.
func (s *Service) ListActor(ctx context.Context, actor identity.Actor, page int, query, path string) (*Page, error) {
	var result *Page
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if actor == nil || actor.UID() == 0 {
			return identity.ErrSession
		}
		if err := actor.PrepareTx(ctx, tx); err != nil {
			return err
		}
		if err := identity.LockUsersTx(ctx, tx, s.Store, []int64{actor.UID()}); err != nil {
			return err
		}
		current, err := actor.RecheckTx(ctx, tx, usersManagementReadScope)
		if err != nil {
			return err
		}
		if current == nil || current.UID != actor.UID() {
			return identity.ErrSession
		}
		if current.Permission < 1 {
			return ErrNoPermission
		}
		result, err = s.listTx(ctx, tx, page, query, path)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
