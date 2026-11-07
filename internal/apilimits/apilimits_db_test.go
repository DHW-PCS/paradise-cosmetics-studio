// Store-backed checks for the Yggdrasil core API rate limiter, using the
// synthetic testsupport database; they skip when M2_TEST_DSN is unset.
package apilimits_test

import (
	"crypto/sha1"
	"sync"
	"testing"
	"time"

	"blessing-skin-go/internal/apilimits"
	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/testsupport"
)

func fixedService(t *testing.T) (*apilimits.Service, *database.Store, time.Time) {
	t.Helper()
	store, _ := testsupport.Database(t, "apilimits-")
	svc := apilimits.New(store)
	if err := svc.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	start := time.Unix(1_700_000_000, 0).UTC()
	svc.Now = func() time.Time { return start }
	return svc, store, start
}

func TestTakeSixtiethAndSixtyFirst(t *testing.T) {
	svc, store, start := fixedService(t)
	for i := 1; i <= 60; i++ {
		d, err := svc.Take(t.Context(), 7, "api.example", "203.0.113.1")
		if err != nil {
			t.Fatal(err)
		}
		if !d.Allowed || d.Limit != 60 || d.Remaining != 60-i || d.RetryAfter != 0 {
			t.Fatalf("hit %d = %+v", i, d)
		}
		if d.ResetAt.Unix() != start.Unix()+60 {
			t.Fatalf("hit %d reset = %v", i, d.ResetAt)
		}
	}
	d, err := svc.Take(t.Context(), 7, "api.example", "203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed || d.Remaining != 0 || d.RetryAfter != 60 || d.ResetAt.Unix() != start.Unix()+60 {
		t.Fatalf("61st = %+v", d)
	}
	d2, err := svc.Take(t.Context(), 7, "api.example", "203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	if d2.Allowed || d2.RetryAfter != d.RetryAfter || d2.Remaining != d.Remaining || !d2.ResetAt.Equal(d.ResetAt) {
		t.Fatalf("repeat denied = %+v, first %+v", d2, d)
	}
	key := sha1.Sum([]byte("7"))
	var count, expires int64
	if err := store.DB.QueryRow("SELECT count,expires_at FROM "+store.Table("go_api_limits")+" WHERE digest=?", key[:]).Scan(&count, &expires); err != nil || count != 60 || expires != start.Unix()+60 {
		t.Fatalf("stored row = %d %d err=%v", count, expires, err)
	}
}

func TestTakeWindowRecovery(t *testing.T) {
	svc, _, start := fixedService(t)
	for range 60 {
		if _, err := svc.Take(t.Context(), 0, "api.example", "203.0.113.2"); err != nil {
			t.Fatal(err)
		}
	}
	if d, err := svc.Take(t.Context(), 0, "api.example", "203.0.113.2"); err != nil || d.Allowed {
		t.Fatalf("61st = %+v err=%v", d, err)
	}
	svc.Now = func() time.Time { return start.Add(60 * time.Second) }
	d, err := svc.Take(t.Context(), 0, "api.example", "203.0.113.2")
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed || d.Remaining != 59 || d.ResetAt.Unix() != start.Unix()+120 {
		t.Fatalf("recovery hit = %+v", d)
	}
}

func TestTakeUIDSharedAnonymousIsolated(t *testing.T) {
	svc, _, _ := fixedService(t)
	for i := 0; i < 60; i++ {
		domain, ip := "a.example", "198.51.100.1"
		if i%2 == 1 {
			domain, ip = "b.example", "198.51.100.2"
		}
		if _, err := svc.Take(t.Context(), 9, domain, ip); err != nil {
			t.Fatal(err)
		}
	}
	if d, err := svc.Take(t.Context(), 9, "c.example", "198.51.100.3"); err != nil || d.Allowed {
		t.Fatalf("shared uid 61st = %+v err=%v", d, err)
	}
	if d, err := svc.Take(t.Context(), 0, "a.example", "198.51.100.1"); err != nil || !d.Allowed || d.Remaining != 59 {
		t.Fatalf("anonymous a = %+v err=%v", d, err)
	}
	if d, err := svc.Take(t.Context(), 0, "a.example", "198.51.100.99"); err != nil || !d.Allowed || d.Remaining != 59 {
		t.Fatalf("anonymous other ip = %+v err=%v", d, err)
	}
	if d, err := svc.Take(t.Context(), -1, "a.example", "198.51.100.1"); err != nil || !d.Allowed || d.Remaining != 58 {
		t.Fatalf("anonymous same pair = %+v err=%v", d, err)
	}
}

func TestTakeConcurrentAtomic(t *testing.T) {
	svc, _, _ := fixedService(t)
	const hits = 100
	allowed := make(chan bool, hits)
	var wg sync.WaitGroup
	for range hits {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := svc.Take(t.Context(), 11, "api.example", "203.0.113.4")
			if err != nil {
				t.Error(err)
				return
			}
			allowed <- d.Allowed
		}()
	}
	wg.Wait()
	close(allowed)
	var yes int
	for ok := range allowed {
		if ok {
			yes++
		}
	}
	if yes != 60 {
		t.Fatalf("concurrent allowed = %d, want 60", yes)
	}
}

func TestMigrateIdempotent(t *testing.T) {
	svc, _, _ := fixedService(t)
	if err := svc.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
}
