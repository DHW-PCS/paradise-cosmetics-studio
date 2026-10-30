// Package outbox stores committed side effects without rerunning business rules.
package outbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
)

type Store struct {
	Database *database.Store
	Now      func() time.Time
}

var ErrHandler = errors.New("outbox: no handler registered for pending task")

func Migrate(ctx context.Context, s *database.Store) error {
	if err := s.ApplyMigration(ctx, "005_outbox", "CREATE TABLE IF NOT EXISTS "+s.Table("go_outbox")+` (id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,operation_key VARCHAR(191) NOT NULL,topic VARCHAR(64) NOT NULL,payload LONGTEXT NOT NULL,available_at BIGINT NOT NULL,lease_until BIGINT NOT NULL DEFAULT 0,claimed_by VARCHAR(64) NULL,attempts INT NOT NULL DEFAULT 0,completed_at BIGINT NULL,UNIQUE operation(operation_key),INDEX pending(completed_at,available_at,lease_until)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`); err != nil {
		return err
	}
	return s.ApplyMigration(ctx, "010_outbox_failures", "ALTER TABLE "+s.Table("go_outbox")+" ADD COLUMN blocked_at BIGINT NULL, ADD COLUMN error_class VARCHAR(64) NULL, ADD INDEX dispatch(blocked_at,completed_at,available_at,lease_until)")
}

// Enqueue belongs to the business owner's transaction. operationKey identifies
// the side effect; a duplicate returns a uniqueness error to the caller.
func (s *Store) Enqueue(ctx context.Context, tx *sql.Tx, operationKey, topic string, payload json.RawMessage) error {
	if !json.Valid(payload) {
		return errors.New("outbox: payload must be JSON")
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO "+s.Database.Table("go_outbox")+" (operation_key,topic,payload,available_at) VALUES (?,?,?,?)", operationKey, topic, []byte(payload), s.Now().Unix())
	return err
}

type Task struct {
	ID                  int64
	OperationKey, Topic string
	Payload             json.RawMessage
}
type Handler func(context.Context, Task) error

// DeliverOne leases in a short transaction, calls the external handler without
// a connection, then acknowledges ownership. External delivery is at least once.
func (s *Store) DeliverOne(ctx context.Context, handlers map[string]Handler, lease time.Duration) (bool, error) {
	if lease <= 0 {
		return false, errors.New("outbox: lease must be positive")
	}
	var task Task
	owner := identity.Token()
	err := s.Database.Transaction(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, "SELECT id,operation_key,topic,payload FROM "+s.Database.Table("go_outbox")+" WHERE blocked_at IS NULL AND completed_at IS NULL AND available_at<=? AND lease_until<=? ORDER BY id LIMIT 1 FOR UPDATE", s.Now().Unix(), s.Now().Unix()).Scan(&task.ID, &task.OperationKey, &task.Topic, &task.Payload)
		if err != nil {
			return err
		}
		if handlers[task.Topic] == nil {
			return ErrHandler
		}
		_, err = tx.ExecContext(ctx, "UPDATE "+s.Database.Table("go_outbox")+" SET claimed_by=?,lease_until=?,attempts=attempts+1 WHERE id=?", owner, s.Now().Add(lease).Unix(), task.ID)
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err = handlers[task.Topic](ctx, task); err != nil {
		var failure *DeliveryFailure
		if !errors.As(err, &failure) {
			return true, err
		}
		var result sql.Result
		if failure.Delay > 0 {
			result, err = s.Database.DB.ExecContext(ctx, "UPDATE "+s.Database.Table("go_outbox")+" SET available_at=?,lease_until=0,claimed_by=NULL,error_class=? WHERE id=? AND claimed_by=? AND lease_until>?", s.Now().Add(failure.Delay).Unix(), failure.Class, task.ID, owner, s.Now().Unix())
		} else {
			result, err = s.Database.DB.ExecContext(ctx, "UPDATE "+s.Database.Table("go_outbox")+" SET blocked_at=?,lease_until=0,claimed_by=NULL,error_class=? WHERE id=? AND claimed_by=? AND lease_until>?", s.Now().Unix(), failure.Class, task.ID, owner, s.Now().Unix())
		}
		return true, ownedResult(result, err)
	}
	result, err := s.Database.DB.ExecContext(ctx, "UPDATE "+s.Database.Table("go_outbox")+" SET completed_at=?,lease_until=0,claimed_by=NULL WHERE id=? AND claimed_by=? AND lease_until>?", s.Now().Unix(), task.ID, owner, s.Now().Unix())
	return true, ownedResult(result, err)
}

// DeliveryFailure classifies external side effects without logging payloads or
// transport replies. Delay>0 retries; Delay=0 retains a blocked task.
type DeliveryFailure struct {
	Class string
	Delay time.Duration
}

func (e *DeliveryFailure) Error() string { return "outbox delivery: " + e.Class }

var ErrLease = errors.New("outbox: delivery lease lost")

var ErrNotBlocked = errors.New("outbox: task is not blocked")

// RetryBlocked requeues only the external side effect after an operator repairs
// its cause. It never repeats the business transaction that created the task.
func (s *Store) RetryBlocked(ctx context.Context, id int64) error {
	result, err := s.Database.DB.ExecContext(ctx, "UPDATE "+s.Database.Table("go_outbox")+" SET blocked_at=NULL,error_class=NULL,available_at=?,lease_until=0,claimed_by=NULL WHERE id=? AND blocked_at IS NOT NULL AND completed_at IS NULL AND lease_until<=?", s.Now().Unix(), id, s.Now().Unix())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotBlocked
	}
	return nil
}

func ownedResult(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrLease
	}
	return nil
}
