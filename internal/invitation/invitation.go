// Package invitation owns the invitation-codes module: the original table
// contract (id, code, generated_at, used_by, used_at), unique-record atomic
// consumption inside the registration transaction and code generation.
package invitation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"paradise-cosmetics-studio/internal/database"
	"paradise-cosmetics-studio/internal/modules"
)

var (
	// ErrEmpty matches the original empty-code rejection.
	ErrEmpty = errors.New("invitation: code is empty")
	// ErrUnavailable matches zero rows or an already used code.
	ErrUnavailable = errors.New("invitation: code is unavailable")
	// ErrAmbiguous reports duplicate code rows; the rows stay and a
	// diagnostic is recorded, no row is chosen or rewritten.
	ErrAmbiguous = errors.New("invitation: duplicate rows for one code")
	// ErrGeneration reports a generation conflict: nothing is inserted.
	ErrGeneration = errors.New("invitation: generation conflict")
	// ErrConsumed reports the locked row changed owners before the
	// registration transaction could mark the consumption.
	ErrConsumed = errors.New("invitation: code consumed by another account")
	// ErrAmount matches the frozen generate validation chain's min rule.
	ErrAmount = errors.New("invitation: amount must be positive")
)

// Service stores the module's business surface.
type Service struct {
	Store *database.Store
	Now   func() time.Time
	// Codes is replaceable for fixed-input checks; production draws 16
	// random bytes from crypto/rand and hex-encodes them into the original
	// lowercase md5 shape.
	Codes func(int) ([]string, error)
}

func New(store *database.Store, now func() time.Time) *Service {
	return &Service{Store: store, Now: now, Codes: randomCodes}
}

// Reservation holds one locked, still-unused invitation row inside the
// registration transaction that produced it.
type Reservation struct {
	Service *Service
	id      int64
}

// CheckReady reports the module's enable precondition: the original schema
// exists (migrate owns the additive DDL, enabling only verifies it).
func (s *Service) CheckReady(ctx context.Context, tx *sql.Tx) ([]string, error) {
	if _, err := tx.ExecContext(ctx, "SELECT id FROM "+s.Store.Table("invitation_codes")+" LIMIT 0"); err != nil {
		return []string{"invitation_codes schema is missing; run offline migrate"}, nil
	}
	return nil, nil
}

// ReserveTx is the registration consumer. Comparison keeps the table
// collation; nulls and rewrites of historical codes never happen.
func (s *Service) ReserveTx(ctx context.Context, tx *sql.Tx, code string) (modules.Reservation, error) {
	if code == "" {
		return nil, ErrEmpty
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,used_by FROM "+s.Store.Table("invitation_codes")+" WHERE code = ? ORDER BY id FOR UPDATE", code)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	used := false
	var ids []int64
	for rows.Next() {
		var id int64
		var owner int64
		if err = rows.Scan(&id, &owner); err != nil {
			return nil, err
		}
		if owner != 0 {
			used = true
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	switch {
	case len(ids) == 0, used:
		return nil, ErrUnavailable
	case len(ids) > 1:
		// Duplicates are historical facts: keep every row alive and refuse
		// the code with a diagnosable log instead of choosing one.
		summary := fmt.Sprintf("invitation: duplicate code rows %v; registration refused, rows kept", ids)
		slog.Error(summary)
		return nil, ErrAmbiguous
	}
	return &Reservation{Service: s, id: ids[0]}, nil
}

// ConsumeTx marks the locked record inside the owning registration
// transaction and verifies the affected-row count.
func (r *Reservation) ConsumeTx(ctx context.Context, tx *sql.Tx, uid int64) error {
	result, err := tx.ExecContext(ctx, "UPDATE "+r.Service.Store.Table("invitation_codes")+" SET used_by=?,used_at=? WHERE id=? AND used_by=0", uid, r.Service.Now(), r.id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConsumed
	}
	return nil
}
