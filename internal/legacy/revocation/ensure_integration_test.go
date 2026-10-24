package revocation_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"blessing-skin-go/internal/legacy/revocation"
	"blessing-skin-go/internal/legacy/testdb"
)

// TestConcurrentEnsureTxCreatesOneBaseline exercises the primitive without the
// account row lock: first-time initialization must not surface a duplicate-key
// error or lose the row to an older snapshot.
func TestConcurrentEnsureTxCreatesOneBaseline(t *testing.T) {
	db := testdb.Open(t)
	if _, err := db.Exec("INSERT INTO users(uid,email,nickname,password) VALUES(1,'init@example.invalid','Nick','x')"); err != nil {
		t.Fatal(err)
	}
	store := revocation.New(db, "")
	secret := []byte("0123456789abcdef0123456789abcdef")

	const callers = 8
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	versions := make(chan int64, callers)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx := context.Background()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				errs <- err
				return
			}
			defer tx.Rollback()
			state, err := store.EnsureTx(ctx, tx, 1, "$2y$04$baseline-hash", secret, time.Now())
			if err == nil {
				err = tx.Commit()
			}
			if err != nil {
				errs <- err
				return
			}
			versions <- state.SessionVersion
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	close(versions)
	for err := range errs {
		t.Fatalf("concurrent EnsureTx failed: %v", err)
	}
	count := 0
	for version := range versions {
		count++
		if version != 1 {
			t.Fatalf("session version = %d, want 1", version)
		}
	}
	if count != callers {
		t.Fatalf("successful callers = %d, want %d", count, callers)
	}
}
