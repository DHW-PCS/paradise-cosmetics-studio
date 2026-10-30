package outbox_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"blessing-skin-go/internal/outbox"
	"blessing-skin-go/internal/testsupport"
)

func TestTransactionalSideEffectsAndAcknowledgement(t *testing.T) {
	db, _ := testsupport.Database(t, "tasks_")
	if err := outbox.Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	store := &outbox.Store{Database: db, Now: time.Now}
	cancelled := errors.New("business failed")
	err := db.Transaction(t.Context(), func(tx *sql.Tx) error {
		if err := store.Enqueue(t.Context(), tx, "rolled-back", "mail", json.RawMessage(`{}`)); err != nil {
			return err
		}
		return cancelled
	})
	if err != cancelled {
		t.Fatal(err)
	}
	var n int
	_ = db.DB.QueryRow("SELECT COUNT(*) FROM " + db.Table("go_outbox")).Scan(&n)
	if n != 0 {
		t.Fatal("rolled back task survived")
	}
	err = db.Transaction(t.Context(), func(tx *sql.Tx) error {
		return store.Enqueue(t.Context(), tx, "committed", "mail", json.RawMessage(`{"user":1}`))
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.DeliverOne(t.Context(), nil, time.Minute); !errors.Is(err, outbox.ErrHandler) {
		t.Fatal("unknown task acknowledged")
	}
	calls := 0
	handlers := map[string]outbox.Handler{"mail": func(ctx context.Context, task outbox.Task) error {
		calls++
		if task.OperationKey != "committed" {
			t.Fatal("wrong side effect")
		}
		return nil
	}}
	if worked, err := store.DeliverOne(t.Context(), handlers, time.Minute); err != nil || !worked {
		t.Fatal(err)
	}
	if worked, err := store.DeliverOne(t.Context(), handlers, time.Minute); err != nil || worked || calls != 1 {
		t.Fatal("completed task redelivered")
	}
}

func TestDeliveryRetryBlockedAndLeaseOwnership(t *testing.T) {
	db, _ := testsupport.Database(t, "failures_")
	now := time.Now()
	queue := &outbox.Store{Database: db, Now: func() time.Time { return now }}
	for _, key := range []string{"temporary", "permanent", "good", "lease"} {
		if err := db.Transaction(t.Context(), func(tx *sql.Tx) error { return queue.Enqueue(t.Context(), tx, key, "mail", json.RawMessage(`{}`)) }); err != nil {
			t.Fatal(err)
		}
	}
	handlers := map[string]outbox.Handler{"mail": func(ctx context.Context, task outbox.Task) error {
		switch task.OperationKey {
		case "temporary":
			return &outbox.DeliveryFailure{Class: "smtp_4xx", Delay: time.Minute}
		case "permanent":
			return &outbox.DeliveryFailure{Class: "smtp_5xx"}
		case "lease":
			_, err := db.DB.ExecContext(ctx, "UPDATE "+db.Table("go_outbox")+" SET claimed_by='another-worker' WHERE id=?", task.ID)
			return err
		}
		return nil
	}}
	for range 3 {
		if worked, err := queue.DeliverOne(t.Context(), handlers, time.Minute); !worked || err != nil {
			t.Fatal("classified failure stopped worker", err)
		}
	}
	if _, err := queue.DeliverOne(t.Context(), handlers, time.Minute); !errors.Is(err, outbox.ErrLease) {
		t.Fatal("lease loss falsely acknowledged", err)
	}
	var pending, blocked, completed int
	if err := db.DB.QueryRow("SELECT SUM(completed_at IS NULL AND blocked_at IS NULL),SUM(blocked_at IS NOT NULL),SUM(completed_at IS NOT NULL) FROM "+db.Table("go_outbox")).Scan(&pending, &blocked, &completed); err != nil || pending != 2 || blocked != 1 || completed != 1 {
		t.Fatalf("task state pending=%d blocked=%d completed=%d err=%v", pending, blocked, completed, err)
	}
}

func TestBlockedRetryDoesNotRepeatCompletedTasks(t *testing.T) {
	db, _ := testsupport.Database(t, "retry_")
	queue := &outbox.Store{Database: db, Now: time.Now}
	if _, err := db.DB.Exec("INSERT INTO " + db.Table("go_outbox") + " (operation_key,topic,payload,available_at,blocked_at,error_class) VALUES ('blocked','mail','{}',1,1,'configuration')"); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := db.DB.QueryRow("SELECT id FROM " + db.Table("go_outbox") + " WHERE operation_key='blocked'").Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := queue.RetryBlocked(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	if err := queue.RetryBlocked(t.Context(), id); !errors.Is(err, outbox.ErrNotBlocked) {
		t.Fatal("pending task requeued twice", err)
	}
	if _, err := queue.DeliverOne(t.Context(), map[string]outbox.Handler{"mail": func(context.Context, outbox.Task) error { return nil }}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := queue.RetryBlocked(t.Context(), id); !errors.Is(err, outbox.ErrNotBlocked) {
		t.Fatal("completed task requeued", err)
	}
}
