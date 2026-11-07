package oauthserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"unicode/utf8"

	"blessing-skin-go/internal/identity"
	"github.com/go-sql-driver/mysql"
)

// The custom scope endpoints keep the frozen admin permission chain: the
// write steps recheck the browser session and the current administrator
// permission inside their update transaction under the policy write lease.
var ErrAdmin = errors.New("oauth scopes: administrator required")

// ScopeToken reports whether the candidate is an RFC6749 §3.3 scope-token:
// each byte is %x21 / %x23-5B / %x5D-7E (no space, no DQUOTE, no backslash).
func ScopeToken(candidate string) bool {
	if candidate == "" {
		return false
	}
	for _, r := range candidate {
		if r > 0x7E {
			return false
		}
		switch {
		case r == 0x21:
		case r >= 0x23 && r <= 0x5B:
		case r >= 0x5D && r <= 0x7E:
		default:
			return false
		}
	}
	return true
}

var (
	ErrInvalidInput = errors.New("oauth scopes: invalid request input")
	ErrScopeName    = fmt.Errorf("%w: name must be an RFC6749 scope-token", ErrInvalidInput)
	ErrScopeLength  = fmt.Errorf("%w: name and description are limited to 255 bytes", ErrInvalidInput)
	ErrConflict     = errors.New("oauth scopes: name already exists")
	ErrMissingRow   = errors.New("oauth scopes: scope row not found")
)

// ScopeRow mirrors one custom table row for the admin page and endpoints.
type ScopeRow struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// CustomScopes lists the custom rows in original id order for display only.
func (s *Server) CustomScopes(ctx context.Context) ([]ScopeRow, error) {
	rows, err := s.cfg.Store.DB.QueryContext(ctx, "SELECT id,name,description FROM "+s.cfg.Store.Table("scopes")+" ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScopeRow{}
	for rows.Next() {
		var row ScopeRow
		if err = rows.Scan(&row.ID, &row.Name, &row.Description); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// CreateScope inserts name/description under the write lease and publishes
// the committed snapshot; a row on a default name is a description override.
func (s *Server) CreateScope(ctx context.Context, b *identity.BrowserSession, name, description string) (ScopeRow, error) {
	return s.mutate(ctx, b, func(ctx context.Context, tx *sql.Tx) (ScopeRow, error) {
		if err := validateScopeInput(name, description); err != nil {
			return ScopeRow{}, err
		}
		result, err := tx.ExecContext(ctx, "INSERT INTO "+s.cfg.Store.Table("scopes")+" (name,description) VALUES (?,?)", name, description)
		if err != nil {
			if isUniqueViolation(err) {
				return ScopeRow{}, ErrConflict
			}
			return ScopeRow{}, err
		}
		id, err := result.LastInsertId()
		if err != nil {
			return ScopeRow{}, err
		}
		return ScopeRow{ID: id, Name: name, Description: description}, nil
	})
}

// UpdateScope renames or re-describes the row; renaming into another name
// collides like any duplicate.
func (s *Server) UpdateScope(ctx context.Context, b *identity.BrowserSession, id int64, name, description string) (ScopeRow, error) {
	if id < 1 {
		return ScopeRow{}, ErrMissingRow
	}
	return s.mutate(ctx, b, func(ctx context.Context, tx *sql.Tx) (ScopeRow, error) {
		var current ScopeRow
		if err := tx.QueryRowContext(ctx, "SELECT id,name,description FROM "+s.cfg.Store.Table("scopes")+" WHERE id=? FOR UPDATE", id).Scan(&current.ID, &current.Name, &current.Description); errors.Is(err, sql.ErrNoRows) {
			return ScopeRow{}, ErrMissingRow
		} else if err != nil {
			return ScopeRow{}, err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE "+s.cfg.Store.Table("scopes")+" SET name=?,description=? WHERE id=?", name, description, id); err != nil {
			if isUniqueViolation(err) {
				return ScopeRow{}, ErrConflict
			}
			return ScopeRow{}, err
		}
		row := ScopeRow{ID: id, Name: name, Description: description}
		return row, nil
	})
}

// DeleteScope removes the custom row by id; a default name loses only the
// custom node (the frozen base set keeps its identifier and descriptions).
func (s *Server) DeleteScope(ctx context.Context, b *identity.BrowserSession, id int64) error {
	_, err := s.mutate(ctx, b, func(ctx context.Context, tx *sql.Tx) (ScopeRow, error) {
		result, err := tx.ExecContext(ctx, "DELETE FROM "+s.cfg.Store.Table("scopes")+" WHERE id=?", id)
		if err != nil {
			return ScopeRow{}, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return ScopeRow{}, err
		}
		if n != 1 {
			return ScopeRow{}, ErrMissingRow
		}
		return ScopeRow{}, nil
	})
	return err
}

// validateScopeInput carries the RFC6749 scope-token name rule and the
// original VARCHAR(255) bounds; case is kept exactly as submitted.
func validateScopeInput(name, description string) error {
	if utf8.RuneCountInString(name) == 0 || utf8.RuneCountInString(description) == 0 {
		return ErrInvalidInput
	}
	if len(name) > 255 || len(description) > 255 {
		return ErrScopeLength
	}
	if !ScopeToken(name) {
		return ErrScopeName
	}
	return nil
}

// mutate owns one update: write lease before the transaction, the identity
// recheck and the row work inside, the candidate snapshot built inside the
// same transaction, then publish after the verified commit so other readers
// never see an uncommitted scope set. A commit that cannot be confirmed
// poisons this process's issuance until the next authoritative rebuild.
func (s *Server) mutate(ctx context.Context, b *identity.BrowserSession, specify func(context.Context, *sql.Tx) (ScopeRow, error)) (ScopeRow, error) {
	lease, err := s.policy.AcquireWrite(ctx)
	if err != nil {
		return ScopeRow{}, err
	}
	defer lease.Release()
	row, _, err := func() (ScopeRow, Snapshot, error) {
		tx, err := s.cfg.Store.DB.BeginTx(ctx, nil)
		if err != nil {
			return ScopeRow{}, Snapshot{}, err
		}
		row, snapshot, err := func() (ScopeRow, Snapshot, error) {
			u, err := s.cfg.Identity.CheckBrowserTx(ctx, tx, b)
			if err != nil {
				return ScopeRow{}, Snapshot{}, err
			}
			if u.Permission < 1 {
				return ScopeRow{}, Snapshot{}, ErrAdmin
			}
			row, err := specify(ctx, tx)
			if err != nil {
				return ScopeRow{}, Snapshot{}, err
			}
			snapshot, err := loadScopeSnapshotsTx(ctx, tx, s.cfg.Store)
			if err != nil {
				return ScopeRow{}, Snapshot{}, err
			}
			return row, snapshot, nil
		}()
		if err != nil {
			_ = tx.Rollback()
			return ScopeRow{}, Snapshot{}, err
		}
		if err := tx.Commit(); err != nil {
			// The commit state is unknown: stop issuing until the next
			// authoritative rebuild per the design's commit-ambiguity rule.
			s.policy.Poison()
			return ScopeRow{}, Snapshot{}, err
		}
		if err := lease.Publish(snapshot); err != nil {
			return ScopeRow{}, Snapshot{}, err
		}
		return row, snapshot, nil
	}()
	if err != nil {
		return ScopeRow{}, err
	}
	return row, nil
}

// isUniqueViolation reports MySQL duplicate-key errors for 409 mapping.
func isUniqueViolation(err error) bool {
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		return mysqlErr.Number == 1062
	}
	return false
}
