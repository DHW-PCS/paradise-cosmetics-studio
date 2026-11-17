package modules

import (
	"context"
	"database/sql"

	"paradise-cosmetics-studio/internal/database"
	"paradise-cosmetics-studio/internal/identity"
)

// InstallationCheck supplies one module's own enable precondition. Reasons are
// original-translated strings meant for the manage response; an unmet check
// fails the whole enable transaction without half updates.
type InstallationCheck = func(context.Context, *sql.Tx) ([]string, error)

// rowUpdate writes one option row back; runtime owns only the two module value
// columns and never deletes or recreates their rows.
type rowUpdate struct {
	key   string
	value string
}

type mutator func(ctx context.Context, tx *sql.Tx, current *State) ([]rowUpdate, error)

// modify runs one admin module-state change: registration coordination, the
// discovered row ids locked by ascending id, re-verified key names, then the
// browser identity and administrator permission.
func (m *Manager) modify(ctx context.Context, b *identity.BrowserSession, mutate mutator) error {
	return m.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if err := database.LockNamespaces(ctx, tx, m.Store, "registration"); err != nil {
			return err
		}
		rows, err := m.plan(ctx, tx)
		if err != nil {
			return err
		}
		current, err := m.lockModuleRows(ctx, tx, rows, "FOR UPDATE")
		if err != nil {
			return err
		}
		u, err := m.Identity.CheckBrowserTx(ctx, tx, b)
		if err != nil {
			return err
		}
		if u.Permission < 1 {
			return ErrForbidden
		}
		state, err := parseState(current)
		if err != nil {
			return err
		}
		updates, err := mutate(ctx, tx, state)
		if err != nil {
			return err
		}
		for _, update := range updates {
			if _, err = tx.ExecContext(ctx, "UPDATE "+m.Store.Table("options")+" SET option_value=? WHERE id=?", update.value, rows[update.key].id); err != nil {
				return err
			}
		}
		return nil
	})
}

// Enable validates the station's install fact, runs the module's own check
// hooks and appends the original entry shape. An already enabled module keeps
// idempotent success, a version change is registered through migration, not
// silently rewritten here.
func (m *Manager) Enable(ctx context.Context, b *identity.BrowserSession, name string) error {
	metaVersion, ok := meta(name)
	if !ok {
		return ErrUnknownModule
	}
	return m.modify(ctx, b, func(ctx context.Context, tx *sql.Tx, current *State) ([]rowUpdate, error) {
		if !current.HasInstalled(name) {
			return nil, ErrNotFound
		}
		if current.HasEnabled(name) {
			return nil, nil
		}
		if check, ok := m.checks[name]; ok {
			reasons, err := check(ctx, tx)
			if err != nil {
				return nil, err
			}
			if len(reasons) > 0 {
				// The owner checked and the module is not ready to enable.
				return nil, &NotReady{Reasons: reasons}
			}
		}
		entries := append([]Entry(nil), current.Enabled...)
		entries = append(entries, Entry{Name: name, Version: metaVersion.Version})
		value, err := encodeEntries(entries)
		if err != nil {
			return nil, err
		}
		return []rowUpdate{{key: enableOptionKey, value: value}}, nil
	})
}

// Disable removes the enable entry, idempotent like the original operation,
// and keeps every other entry including legacy strings.
func (m *Manager) Disable(ctx context.Context, b *identity.BrowserSession, name string) error {
	if _, ok := meta(name); !ok {
		return ErrUnknownModule
	}
	return m.modify(ctx, b, func(ctx context.Context, tx *sql.Tx, current *State) ([]rowUpdate, error) {
		if !current.HasInstalled(name) {
			return nil, ErrNotFound
		}
		if !current.HasEnabled(name) {
			return nil, nil
		}
		kept := make([]Entry, 0, len(current.Enabled))
		for _, entry := range current.Enabled {
			if entry.Name != name {
				kept = append(kept, entry)
			}
		}
		value, err := encodeEntries(kept)
		if err != nil {
			return nil, err
		}
		return []rowUpdate{{key: enableOptionKey, value: value}}, nil
	})
}

// Uninstall removes the station install registration and disables the module
// inside one transaction. Compiled code and business data stay untouched;
// reinstalling is an explicit offline operation.
func (m *Manager) Uninstall(ctx context.Context, b *identity.BrowserSession, name string) error {
	if _, ok := meta(name); !ok {
		return ErrUnknownModule
	}
	return m.modify(ctx, b, func(ctx context.Context, tx *sql.Tx, current *State) ([]rowUpdate, error) {
		if !current.HasInstalled(name) {
			return nil, ErrNotFound
		}
		var updates []rowUpdate
		if current.HasEnabled(name) {
			kept := make([]Entry, 0, len(current.Enabled))
			for _, entry := range current.Enabled {
				if entry.Name != name {
					kept = append(kept, entry)
				}
			}
			value, err := encodeEntries(kept)
			if err != nil {
				return nil, err
			}
			updates = append(updates, rowUpdate{key: enableOptionKey, value: value})
		}
		kept := make([]Entry, 0, len(current.Installed))
		for _, entry := range current.Installed {
			if entry.Name != name {
				kept = append(kept, entry)
			}
		}
		value, err := encodeEntries(kept)
		if err != nil {
			return nil, err
		}
		updates = append(updates, rowUpdate{key: installOptionKey, value: value})
		return updates, nil
	})
}
