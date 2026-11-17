// Yggdrasil core API limit lifecycle: CheckSchema requires go_api_limits,
// cleanup removes only expired counters, and reset clears the counters
// while keeping accounts and business data.
package maintenance

import (
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/apilimits"
	"paradise-cosmetics-studio/internal/oauthserver"
	"paradise-cosmetics-studio/internal/testsupport"
)

func TestAPILimitsCleanupOnlyExpired(t *testing.T) {
	store, _ := testsupport.Database(t, "maint-apilimits-")
	if err := oauthserver.Migrate(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err := apilimits.New(store).Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := store.DB.Exec("INSERT INTO "+store.Table("go_api_limits")+" (digest,count,expires_at) VALUES (?,1,?),(?,60,?)", []byte("01234567890123456789"), now.Add(-time.Minute).Unix(), []byte("98765432109876543210"), now.Add(time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	n, err := Cleanup(t.Context(), store, now, 10)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("cleanup removed %d rows, want only the expired counter", n)
	}
	var live int
	if err = store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("go_api_limits")).Scan(&live); err != nil || live != 1 {
		t.Fatalf("live counter = %d err=%v", live, err)
	}
}

func TestAPILimitsResetClearsCountersKeepsAccounts(t *testing.T) {
	store, _ := testsupport.Database(t, "maint-apilimits-reset-")
	if err := oauthserver.Migrate(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err := apilimits.New(store).Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec("INSERT INTO "+store.Table("go_api_limits")+" (digest,count,expires_at) VALUES (?,30,?)", []byte("01234567890123456789"), time.Now().Add(time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	var err error
	if err := ResetAuthentication(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	var counters int
	if err = store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("go_api_limits")).Scan(&counters); err != nil || counters != 0 {
		t.Fatalf("reset left counters=%d err=%v", counters, err)
	}
	var users, versions int
	if err = store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("users")).Scan(&users); err != nil || users != 2 {
		t.Fatalf("reset damaged users: %v", err)
	}
	if err = store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("go_auth_versions")).Scan(&versions); err != nil || versions != 2 {
		t.Fatalf("reset damaged versions: %v", err)
	}
}

func TestAPILimitsMissingTableStrict(t *testing.T) {
	// The shared fixture migrates go_api_limits; this case explicitly
	// drops it so the missing-table behaviour is arranged, not inherited.
	store, _ := testsupport.Database(t, "maint-apilimits-schema-")
	if _, err := store.DB.Exec("DROP TABLE " + store.Table("go_api_limits")); err != nil {
		t.Fatal(err)
	}
	if err := CheckSchema(t.Context(), store); err == nil {
		t.Fatal("CheckSchema accepted a database without go_api_limits")
	}
	if err := ResetAuthentication(t.Context(), store); err == nil {
		t.Fatal("ResetAuthentication silently skipped a missing go_api_limits")
	}
	if _, err := Cleanup(t.Context(), store, time.Now(), 10); err == nil {
		t.Fatal("Cleanup silently skipped a missing go_api_limits")
	}
}
