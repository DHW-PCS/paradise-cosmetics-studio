package players

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"blessing-skin-go/internal/database"
	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
)

// Binding is the persistent UUID link of one real player. Version changes when
// the player is transferred or when a v3 rename changes the UUID.
type Binding struct {
	PID       int64
	UUIDRowID int64
	UUID      string
	Version   int64
}

var (
	ErrUUIDUnavailable = errors.New("players: uuid state unavailable")
	ErrUUIDAmbiguous   = errors.New("players: uuid mapping is ambiguous")
	ErrUUIDConflict    = errors.New("players: uuid mapping conflict")
	ErrUUIDMalformed   = errors.New("players: uuid mapping is malformed")
)

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func isCharsetError(err error) bool {
	var mysqlErr *mysql.MySQLError
	return errors.As(err, &mysqlErr) && (mysqlErr.Number == 1366 || mysqlErr.Number == 1406)
}

func isMissingTable(err error) bool {
	var mysqlErr *mysql.MySQLError
	return errors.As(err, &mysqlErr) && mysqlErr.Number == 1146
}

func normalizeUUID(value string) (string, error) {
	if err := uuid.Validate(value); err != nil {
		return "", ErrUUIDMalformed
	}
	parsed := uuid.MustParse(value)
	return hex.EncodeToString(parsed[:]), nil
}

// UUID3 mirrors the frozen Yggdrasil v3 algorithm (OfflinePlayer:<name>).
func UUID3(name string) string {
	b := md5.Sum([]byte("OfflinePlayer:" + name))
	b[6] = (b[6] & 0x0f) | 0x30
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[:])
}

func uuid4() (string, error) {
	value, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

type uuidRow struct {
	ID  int64
	Val string
}

func (s *Service) uuidRows(ctx context.Context, q queryer, name string) ([]uuidRow, error) {
	rows, err := q.QueryContext(ctx, "SELECT id,uuid FROM "+s.Store.Table("uuid")+" WHERE name=? ORDER BY id", name)
	if err != nil {
		if isMissingTable(err) {
			return nil, ErrUUIDUnavailable
		}
		return nil, err
	}
	defer rows.Close()
	var out []uuidRow
	for rows.Next() {
		var row uuidRow
		if err = rows.Scan(&row.ID, &row.Val); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// bindingTx reads the binding of a player inside the caller's transaction.
func (s *Service) bindingTx(ctx context.Context, q queryer, pid int64) (*Binding, error) {
	b := &Binding{PID: pid}
	err := q.QueryRowContext(ctx, "SELECT uuid_row_id,uuid,version FROM "+s.Store.Table("go_uuid_bindings")+" WHERE pid=?", pid).Scan(&b.UUIDRowID, &b.UUID, &b.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

// BindingTx exposes the current binding to protocol adapters (M4) without
// allocating UUIDs; missing bindings are a typed absence.
func (s *Service) BindingTx(ctx context.Context, tx *sql.Tx, pid int64) (*Binding, error) {
	return s.bindingTx(ctx, tx, pid)
}

// LockBindingTx is the locking current read for protocol adapters: it takes
// the binding row FOR UPDATE inside the caller's transaction so a later
// rename or transfer cannot interleave between discovery and use. A missing
// binding is a typed absence (nil, nil).
func (s *Service) LockBindingTx(ctx context.Context, tx *sql.Tx, pid int64) (*Binding, error) {
	b := &Binding{PID: pid}
	err := tx.QueryRowContext(ctx, "SELECT uuid_row_id,uuid,version FROM "+s.Store.Table("go_uuid_bindings")+" WHERE pid=? FOR UPDATE", pid).Scan(&b.UUIDRowID, &b.UUID, &b.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

// PlayersOfUIDTx returns the current player rows of one user in ascending
// PID order, locking each players row FOR UPDATE inside the caller's
// transaction.
func (s *Service) PlayersOfUIDTx(ctx context.Context, tx *sql.Tx, uid int64) ([]Player, error) {
	rows, err := tx.QueryContext(ctx, "SELECT pid,name,uid,tid_skin,tid_cape,last_modified FROM "+s.Store.Table("players")+" WHERE uid=? ORDER BY pid FOR UPDATE", uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Player
	for rows.Next() {
		var pl Player
		var last string
		if err = rows.Scan(&pl.PID, &pl.Name, &pl.UID, &pl.TIDSkin, &pl.TIDCape, &last); err != nil {
			return nil, err
		}
		pl.LastModified = last
		out = append(out, pl)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []Player{}
	}
	return out, nil
}

// Binding reads the current binding without locking.
func (s *Service) Binding(ctx context.Context, pid int64) (*Binding, error) {
	return s.bindingTx(ctx, s.Store.DB, pid)
}

func (s *Service) insertBinding(ctx context.Context, q queryer, pid, rowID int64, value string, version int64) (*Binding, error) {
	value, err := normalizeUUID(value)
	if err != nil {
		return nil, err
	}
	_, err = q.ExecContext(ctx, "INSERT INTO "+s.Store.Table("go_uuid_bindings")+" (pid,uuid_row_id,uuid,version) VALUES (?,?,?,?)", pid, rowID, value, version)
	if err != nil {
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
			return nil, ErrUUIDConflict
		}
		return nil, err
	}
	return &Binding{PID: pid, UUIDRowID: rowID, UUID: value, Version: version}, nil
}

// ensureUUIDLocked resolves or allocates the binding of a real player. The
// caller must hold the uuid namespace and a locked players row.
func (s *Service) ensureUUIDLocked(ctx context.Context, tx *sql.Tx, pid int64, name, algorithm string) (*Binding, error) {
	if existing, err := s.bindingTx(ctx, tx, pid); err != nil || existing != nil {
		return existing, err
	}
	if algorithm == "" {
		algorithm = "v3"
	}
	rows, err := s.uuidRows(ctx, tx, name)
	if err != nil {
		return nil, err
	}
	var rowID int64
	var value string
	switch len(rows) {
	case 0:
		if algorithm == "v3" {
			value = UUID3(name)
		} else {
			if value, err = uuid4(); err != nil {
				return nil, err
			}
		}
		result, err := tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("uuid")+" (name,uuid) VALUES (?,?)", name, value)
		if err != nil {
			return nil, err
		}
		rowID, err = result.LastInsertId()
		if err != nil {
			return nil, err
		}
	case 1:
		rowID, value = rows[0].ID, rows[0].Val
	default:
		return nil, ErrUUIDAmbiguous
	}
	return s.insertBinding(ctx, tx, pid, rowID, value, 1)
}

// renameUUIDLocked applies the v4/v3 rename rules. A non-fatal warning is
// returned for a malformed legacy value that is only needed for a missing
// binding; every other UUID error aborts the rename.
func (s *Service) renameUUIDLocked(ctx context.Context, tx *sql.Tx, pid int64, oldName, newName, algorithm string) (binding *Binding, warning error, err error) {
	if oldName == newName {
		binding, err := s.bindingTx(ctx, tx, pid)
		return binding, nil, err
	}
	if algorithm == "" {
		algorithm = "v3"
	}
	binding, err = s.bindingTx(ctx, tx, pid)
	if err != nil {
		return nil, nil, err
	}
	rows, err := s.uuidRows(ctx, tx, oldName)
	if err != nil {
		if errors.Is(err, ErrUUIDUnavailable) {
			if binding != nil {
				return nil, nil, ErrUUIDUnavailable
			}
			return nil, nil, nil
		}
		return nil, nil, err
	}
	if len(rows) > 1 {
		return nil, nil, ErrUUIDAmbiguous
	}
	targets, err := s.uuidRows(ctx, tx, newName)
	if err != nil {
		return nil, nil, err
	}
	if algorithm != "v3" {
		if len(targets) != 0 {
			return nil, nil, ErrUUIDConflict
		}
		if len(rows) == 0 {
			if binding != nil {
				return nil, nil, ErrUUIDConflict
			}
			return nil, nil, nil
		}
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("uuid")+" SET name=? WHERE id=?", newName, rows[0].ID); err != nil {
			return nil, nil, err
		}
		if binding != nil {
			return binding, nil, nil
		}
		if _, err := normalizeUUID(rows[0].Val); err != nil {
			return nil, ErrUUIDMalformed, nil
		}
		created, err := s.insertBinding(ctx, tx, pid, rows[0].ID, rows[0].Val, 1)
		return created, nil, err
	}
	value := UUID3(newName)
	switch len(targets) {
	case 0:
		result, err := tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("uuid")+" (name,uuid) VALUES (?,?)", newName, value)
		if err != nil {
			// The frozen v3 rename never writes the uuid table, so a legacy
			// utf8mb3 column cannot fail the rename when no binding exists.
			if isCharsetError(err) && binding == nil {
				return nil, ErrUUIDUnavailable, nil
			}
			return nil, nil, err
		}
		rowID, err := result.LastInsertId()
		if err != nil {
			return nil, nil, err
		}
		targets = []uuidRow{{ID: rowID, Val: value}}
	case 1:
		canonical, parseErr := normalizeUUID(targets[0].Val)
		if parseErr != nil || canonical != value {
			return nil, nil, ErrUUIDConflict
		}
	default:
		return nil, nil, ErrUUIDAmbiguous
	}
	target := targets[0]
	if binding == nil {
		created, err := s.insertBinding(ctx, tx, pid, target.ID, value, 1)
		return created, nil, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("go_uuid_bindings")+" SET uuid_row_id=?,uuid=?,version=version+1 WHERE pid=?", target.ID, value, pid); err != nil {
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
			return nil, nil, ErrUUIDConflict
		}
		return nil, nil, err
	}
	return &Binding{PID: pid, UUIDRowID: target.ID, UUID: value, Version: binding.Version + 1}, nil, nil
}

// bumpBinding increments the binding version after an ownership change.
func (s *Service) bumpBinding(ctx context.Context, tx *sql.Tx, pid int64) error {
	_, err := tx.ExecContext(ctx, "UPDATE "+s.Store.Table("go_uuid_bindings")+" SET version=version+1 WHERE pid=?", pid)
	return err
}

func (s *Service) deleteBinding(ctx context.Context, q queryer, pid int64) error {
	_, err := q.ExecContext(ctx, "DELETE FROM "+s.Store.Table("go_uuid_bindings")+" WHERE pid=?", pid)
	return err
}

// EnsureUUID is the controlled allocation entry used by protocol adapters for
// real, persisted players. It never runs for inspect/health/auth-reset.
func (s *Service) EnsureUUID(ctx context.Context, pid int64) (*Binding, error) {
	options, err := s.Site.Options(ctx)
	if err != nil {
		return nil, err
	}
	var binding *Binding
	err = s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if err = database.LockNamespaces(ctx, tx, s.Store, "uuid"); err != nil {
			return err
		}
		var name string
		if err = tx.QueryRowContext(ctx, "SELECT name FROM "+s.Store.Table("players")+" WHERE pid=? FOR UPDATE", pid).Scan(&name); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		binding, err = s.ensureUUIDLocked(ctx, tx, pid, name, algorithmOption(options))
		return err
	})
	return binding, err
}

func algorithmOption(options map[string]any) string {
	// Frozen Profile::getUuidFromName uses v3 only when the option equals
	// "v3"; a missing/empty option means the random v4 algorithm.
	if value, _ := options["ygg_uuid_algorithm"].(string); value == "v3" {
		return "v3"
	}
	return "v4"
}

// now is the site-local timestamp used by the frozen models.
func (s *Service) now() time.Time { return s.Now().In(s.Site.Location) }
