package oauthserver

import (
	"context"
	"database/sql"

	"blessing-skin-go/internal/database"
)

// LoadScopeSnapshots reads the effective scope facts at startup: the frozen
// base names first, then the custom rows in original id order (the shape of
// the original AuthServiceProvider array merge).
func LoadScopeSnapshots(ctx context.Context, store *database.Store) (Snapshot, error) {
	return loadScopeSnapshotsRowNames(func() (*sql.Rows, error) {
		return store.DB.QueryContext(ctx, "SELECT name FROM "+store.Table("scopes")+" ORDER BY id")
	})
}

// loadScopeSnapshotsTx builds the candidate snapshot inside the update
// transaction, so the post-commit publish carries exactly the committed
// scope facts with no second read that could diverge.
func loadScopeSnapshotsTx(ctx context.Context, tx *sql.Tx, store *database.Store) (Snapshot, error) {
	return loadScopeSnapshotsRowNames(func() (*sql.Rows, error) {
		return tx.QueryContext(ctx, "SELECT name FROM "+store.Table("scopes")+" ORDER BY id")
	})
}

func loadScopeSnapshotsRowNames(query func() (*sql.Rows, error)) (Snapshot, error) {
	names := append([]string(nil), DefaultScopes...)
	seen := map[string]bool{}
	for _, scope := range names {
		seen[scope] = true
	}
	rows, err := query()
	if err != nil {
		return Snapshot{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			return Snapshot{}, err
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return Snapshot{Names: names}, rows.Err()
}

type snapshotKey struct{}

// withSnapshot binds the caller's pinned snapshot to the flow context so the
// storage reads one scope set for the flow's whole lifetime.
func withSnapshot(ctx context.Context, snapshot Snapshot) context.Context {
	return context.WithValue(ctx, snapshotKey{}, snapshot)
}

func currentSnapshot(ctx context.Context) (Snapshot, bool) {
	value, ok := ctx.Value(snapshotKey{}).(Snapshot)
	return value, ok
}

// runLeased wraps one flow in a commit-bounded read lease. The caller holds
// no user-row locks at acquire time; password computation happens before it.
func (s *storage) runLeased(ctx context.Context, db *sql.DB, lease *ReadLease, f func(context.Context) error) error {
	defer lease.Release()
	return s.runOn(ctx, db, func(flowCtx context.Context) error {
		return f(withSnapshot(flowCtx, lease.Snapshot()))
	})
}
