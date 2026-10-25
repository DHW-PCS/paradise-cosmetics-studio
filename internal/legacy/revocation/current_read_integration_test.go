package revocation_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"blessing-skin-go/internal/legacy/revocation"
	"blessing-skin-go/internal/legacy/testdb"
)

const currentReadHash = "$2y$04$baseline-hash-for-current-read"

// seedCurrentReadBaseline inserts one account with a generation-1 state row.
func seedCurrentReadBaseline(t *testing.T) (*sql.DB, *revocation.Store, []byte) {
	t.Helper()
	db := testdb.Open(t)
	if _, err := db.Exec("INSERT INTO users(uid,email,nickname,password) VALUES(1,'generation@example.invalid','Nick',?)", currentReadHash); err != nil {
		t.Fatal(err)
	}
	store := revocation.New(db, "")
	secret := []byte("0123456789abcdef0123456789abcdef")
	state, err := store.Ensure(context.Background(), 1, currentReadHash, secret, time.Now())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if state.SessionVersion != 1 {
		t.Fatalf("baseline version = %d, want 1", state.SessionVersion)
	}
	return db, store, secret
}

// requireAccountLocked proves uid's row is held by another transaction.
func requireAccountLocked(t *testing.T, db *sql.DB, uid int64) {
	t.Helper()
	var got int64
	err := db.QueryRowContext(context.Background(), "SELECT uid FROM users WHERE uid=? FOR UPDATE NOWAIT", uid).Scan(&got)
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) && (mysqlErr.Number == 3572 || mysqlErr.Number == 1205) {
		return
	}
	if err != nil {
		t.Fatalf("lock probe: %v", err)
	}
	t.Fatal("account row is not locked")
}

// TestEnsureTxObservesGenerationCommittedAfterSnapshot covers the read boundary
// that GetCurrentTx exists for: the caller's transaction already established an
// older consistent snapshot (any earlier plain read inside the same transaction
// does that), then another transaction commits a generation advance. EnsureTx
// must report the committed generation; a plain consistent read would keep
// serving the snapshot and hand the caller a stale generation.
func TestEnsureTxObservesGenerationCommittedAfterSnapshot(t *testing.T) {
	db, store, secret := seedCurrentReadBaseline(t)
	ctx := context.Background()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var accounts int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&accounts); err != nil {
		t.Fatalf("establish snapshot: %v", err)
	}
	if accounts != 1 {
		t.Fatalf("accounts = %d, want 1", accounts)
	}

	// A revocation advance commits after the snapshot above.
	advanced, err := store.Bump(ctx, 1, currentReadHash, secret, time.Now())
	if err != nil {
		t.Fatalf("Bump: %v", err)
	}
	if advanced.SessionVersion != 2 {
		t.Fatalf("bumped version = %d, want 2", advanced.SessionVersion)
	}

	state, err := store.EnsureTx(ctx, tx, 1, currentReadHash, secret, time.Now())
	if err != nil {
		t.Fatalf("EnsureTx: %v", err)
	}
	if state.SessionVersion != 2 {
		t.Fatalf("EnsureTx observed generation %d, want 2 (committed after the caller's snapshot)", state.SessionVersion)
	}
}

// TestEnsureTxSeesGenerationCommittedWhileWaitingForAccountLock is the lock-wait
// variant of the same boundary: the writer holds the account row and advances
// the generation, the reader established its snapshot before the writer
// commits, and EnsureTx then waits for the account lock. The returned state must
// be the committed generation.
func TestEnsureTxSeesGenerationCommittedWhileWaitingForAccountLock(t *testing.T) {
	db, store, secret := seedCurrentReadBaseline(t)
	ctx := context.Background()

	// The writer takes the account row lock and advances the generation without
	// committing yet.
	writer, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	var locked int64
	if err := writer.QueryRowContext(ctx, "SELECT uid FROM users WHERE uid=1 FOR UPDATE").Scan(&locked); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	if err := revocation.BumpTx(ctx, writer, "", 1, currentReadHash, secret, time.Now()); err != nil {
		t.Fatalf("BumpTx: %v", err)
	}

	// The reader establishes an older snapshot, then calls EnsureTx in another
	// goroutine so it has to wait for the writer's account lock.
	reader, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback()
	var accounts int
	if err := reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&accounts); err != nil {
		t.Fatalf("reader snapshot: %v", err)
	}

	type result struct {
		state *revocation.State
		err   error
	}
	done := make(chan result, 1)
	go func() {
		state, err := store.EnsureTx(context.Background(), reader, 1, currentReadHash, secret, time.Now())
		done <- result{state, err}
	}()

	// The writer still owns the account row, so the reader above cannot have
	// proceeded past the account lock.
	requireAccountLocked(t, db, 1)
	if err := writer.Commit(); err != nil {
		t.Fatalf("writer commit: %v", err)
	}

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("EnsureTx: %v", got.err)
		}
		if got.state.SessionVersion != 2 {
			t.Fatalf("EnsureTx observed generation %d, want 2 (committed while waiting for the account lock)", got.state.SessionVersion)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("EnsureTx did not return after the writer committed")
	}
}

// TestConcurrentFirstInitializationOfDifferentAccounts is the deadlock
// regression for EnsureTx. When the state row is created lazily, a locking read
// of the missing key (gap lock) followed by INSERT IGNORE (insert intention)
// makes two first-time initializations of adjacent accounts deadlock inside the
// same empty gap. Verified against InnoDB's LATEST DETECTED DEADLOCK report: both
// transactions held an X gap lock on the supremum record and waited for insert
// intention. EnsureTx now writes the baseline first, so concurrent creation of
// different accounts never takes a gap lock.
func TestConcurrentFirstInitializationOfDifferentAccounts(t *testing.T) {
	db := testdb.Open(t)
	ctx := context.Background()
	secret := []byte("0123456789abcdef0123456789abcdef")
	const accounts = 8
	for i := 0; i < accounts; i++ {
		if _, err := db.Exec("INSERT INTO users(uid,email,nickname,password) VALUES(?,?,?,?)",
			i+1, fmt.Sprintf("first-init-%d@example.invalid", i), "Nick", "$2y$04$first-init"); err != nil {
			t.Fatal(err)
		}
	}
	store := revocation.New(db, "")

	// Three rounds so a pre-fix interleaving has several chances to surface; a
	// correct implementation never deadlocks because no gap lock is taken.
	for round := 0; round < 3; round++ {
		var (
			mu   sync.Mutex
			errs []error
			wg   sync.WaitGroup
		)
		fail := func(err error) {
			if err == nil {
				return
			}
			mu.Lock()
			errs = append(errs, err)
			mu.Unlock()
		}
		start := make(chan struct{})
		for i := 0; i < accounts; i++ {
			wg.Add(1)
			go func(uid int64) {
				defer wg.Done()
				<-start
				tx, err := db.BeginTx(ctx, nil)
				if err != nil {
					fail(err)
					return
				}
				defer tx.Rollback()
				if _, err := store.EnsureTx(ctx, tx, uid, "$2y$04$first-init", secret, time.Now()); err != nil {
					fail(err)
					return
				}
				fail(tx.Commit())
			}(int64(i + 1))
		}
		close(start)
		wg.Wait()
		for _, err := range errs {
			t.Fatalf("round %d: concurrent first initialization failed: %v", round, err)
		}
	}
}
