package invitation

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log/slog"
	"time"

	"blessing-skin-go/internal/database"
)

// Generate creates amount fresh codes inside one transaction guarded by the
// registration coordination. A collision with any existing code fails the
// whole batch without inserting, without retrying and without a historical
// unique index; the original md5 hex shape is kept for the visual form.
func (s *Service) Generate(ctx context.Context, store *database.Store, amount int64) error {
	if amount < 1 {
		return ErrAmount
	}
	codes, err := s.Codes(int(amount))
	if err != nil {
		return err
	}
	return store.Transaction(ctx, func(tx *sql.Tx) error {
		if err := database.LockNamespaces(ctx, tx, store, "registration"); err != nil {
			return err
		}
		// The original table carries no uniqueness on code; a collision is a
		// reported whole-batch failure, never a merged or overwritten row.
		quoted := ""
		args := make([]any, 0, len(codes))
		for i, code := range codes {
			if i > 0 {
				quoted += ","
			}
			quoted += "?"
			args = append(args, code)
		}
		rows, err := tx.QueryContext(ctx, "SELECT 1 FROM "+store.Table("invitation_codes")+" WHERE code IN ("+quoted+") LIMIT 1", args...)
		if err != nil {
			return err
		}
		clash := rows.Next()
		if err = rows.Err(); err != nil {
			return err
		}
		_ = rows.Close()
		if clash {
			// One existing code cancels the whole batch; nothing is inserted
			// and the run is diagnosable.
			slog.Error("invitation: generation refused, an existing code matched the batch")
			return ErrGeneration
		}
		now := s.Now()
		for _, code := range codes {
			if _, err = tx.ExecContext(ctx, "INSERT INTO "+store.Table("invitation_codes")+" (code,generated_at) VALUES (?,?)", code, now); err != nil {
				return err
			}
		}
		return nil
	})
}

func randomCodes(amount int) ([]string, error) {
	batch := make([]string, 0, amount)
	for range amount {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		batch = append(batch, hex.EncodeToString(buf))
	}
	return batch, nil
}

// List returns the original two admin groups in source order.
type List struct {
	Free []Code
	Used []Code
}

// Code mirrors one table row; used_by=0 is the free group's sentinel.
type Code struct {
	ID          int64      `json:"id"`
	Code        string     `json:"code"`
	GeneratedAt *time.Time `json:"generated_at"`
	UsedBy      int64      `json:"used_by"`
	UsedAt      *time.Time `json:"used_at"`
}

func (s *Service) List(ctx context.Context) (*List, error) {
	codes := func(where string) ([]Code, error) {
		rows, err := s.Store.DB.QueryContext(ctx, "SELECT id,code,generated_at,used_by,used_at FROM "+s.Store.Table("invitation_codes")+" WHERE "+where)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []Code{}
		for rows.Next() {
			var code Code
			var generatedAt time.Time
			var usedAt sql.NullTime
			if err = rows.Scan(&code.ID, &code.Code, &generatedAt, &code.UsedBy, &usedAt); err != nil {
				return nil, err
			}
			code.GeneratedAt = &generatedAt
			if usedAt.Valid {
				code.UsedAt = &usedAt.Time
			}
			out = append(out, code)
		}
		return out, rows.Err()
	}
	free, err := codes("used_by = 0")
	if err != nil {
		return nil, err
	}
	used, err := codes("used_by <> 0")
	if err != nil {
		return nil, err
	}
	return &List{Free: free, Used: used}, nil
}

// Migrate owns the additive DDL of the invitation table on the offline
// ledger; run inside the explicit offline takeover.
func Migrate(ctx context.Context, store *database.Store) error {
	ddl := "CREATE TABLE IF NOT EXISTS " + store.Table("invitation_codes") + ` (
id INT UNSIGNED NOT NULL PRIMARY KEY AUTO_INCREMENT,
code VARCHAR(255) NOT NULL,
generated_at DATETIME NOT NULL,
used_by INT NOT NULL DEFAULT 0,
used_at DATETIME NULL
) ENGINE=InnoDB`
	return store.ApplyMigration(ctx, "020_invitation_codes", ddl)
}
