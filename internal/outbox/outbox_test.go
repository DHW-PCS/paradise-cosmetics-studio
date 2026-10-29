package outbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"blessing-skin-go/internal/testsupport"
)

func TestTransactionalSideEffectsAndAcknowledgement(t *testing.T) {
	db, _ := testsupport.Database(t, "tasks_")
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	store := &Store{Database: db, Now: time.Now}
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
	if _, err = store.DeliverOne(t.Context(), nil, time.Minute); !errors.Is(err, ErrHandler) {
		t.Fatal("unknown task acknowledged")
	}
	calls := 0
	handlers := map[string]Handler{"mail": func(ctx context.Context, task Task) error {
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
