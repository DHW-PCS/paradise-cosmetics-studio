package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"

	"blessing-skin-go/internal/legacy/passport"
	"blessing-skin-go/internal/legacy/password"
	"blessing-skin-go/internal/legacy/revocation"
	"blessing-skin-go/internal/legacy/testdb"
	"blessing-skin-go/internal/legacy/users"
)

// The lock-cost profile is opt-in: it spawns up to 32 concurrent bcrypt
// verifications and is a measurement, not a correctness gate. Run it with
//
//	M1_LOCKCOST=1 M1_LOCKCOST_OUT=<file.json> M1_TEST_DSN=... \
//	  go test ./internal/legacy/auth/ -run 'TestLockCostProfile' -count=1 -v
//
// The numbers are PoC capacity observations, not a production SLO.
const (
	lockCostSecret   = "0123456789abcdef0123456789abcdef"
	lockCostPassword = "synthetic-password-1"
)

var lockCostConcurrency = []int{1, 8, 32}

type lockCostResult struct {
	Name         string         `json:"name"`
	Concurrency  int            `json:"concurrency"`
	Ops          int            `json:"ops"`
	Errors       int            `json:"errors"`
	ErrorKinds   map[string]int `json:"error_kinds"`
	WallMS       float64        `json:"wall_ms"`
	SumLatencyMS float64        `json:"sum_latency_ms"`
	Throughput   float64        `json:"throughput_per_sec"`
	P50MS        float64        `json:"p50_ms"`
	P95MS        float64        `json:"p95_ms"`
	MaxMS        float64        `json:"max_ms"`
	MinMS        float64        `json:"min_ms"`
}

func summarise(name string, concurrency int, samples []time.Duration, kinds map[string]int, wall time.Duration) lockCostResult {
	ms := make([]float64, len(samples))
	var total time.Duration
	for i, sample := range samples {
		ms[i] = float64(sample) / float64(time.Millisecond)
		total += sample
	}
	sort.Float64s(ms)
	result := lockCostResult{Name: name, Concurrency: concurrency, Ops: len(samples), ErrorKinds: kinds}
	if len(kinds) > 0 {
		for _, count := range kinds {
			result.Errors += count
		}
	}
	if len(ms) == 0 {
		return result
	}
	result.MinMS = ms[0]
	result.MaxMS = ms[len(ms)-1]
	result.P50MS = ms[len(ms)/2]
	if len(ms) >= 20 {
		result.P95MS = ms[(len(ms)*95)/100-1]
	} else {
		result.P95MS = result.MaxMS
	}
	result.SumLatencyMS = float64(total) / float64(time.Millisecond)
	result.WallMS = float64(wall) / float64(time.Millisecond)
	if wall > 0 {
		result.Throughput = float64(len(samples)) / wall.Seconds()
	}
	return result
}

func classifyLockError(err error) string {
	if err == nil {
		return ""
	}
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		switch mysqlErr.Number {
		case 1205:
			return "lock_wait_timeout"
		case 1213:
			return "deadlock"
		case 3572:
			return "nowait_refused"
		}
		return "mysql_" + strconv.Itoa(int(mysqlErr.Number))
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "context_deadline"
	}
	if errors.Is(err, context.Canceled) {
		return "context_canceled"
	}
	return "other"
}

// lockCostRunner performs one measured operation.
type lockCostRunner func(ctx context.Context, lane int) error

func runLockCost(t *testing.T, name string, concurrency, rounds int, runner lockCostRunner) lockCostResult {
	t.Helper()
	ops := concurrency * rounds
	samples := make([]time.Duration, 0, ops)
	kinds := map[string]int{}
	var mu sync.Mutex
	start := make(chan struct{})
	var wg sync.WaitGroup
	for lane := 0; lane < concurrency; lane++ {
		wg.Add(1)
		go func(lane int) {
			defer wg.Done()
			<-start
			for i := 0; i < rounds; i++ {
				begin := time.Now()
				err := runner(context.Background(), lane)
				elapsed := time.Since(begin)
				mu.Lock()
				samples = append(samples, elapsed)
				if kind := classifyLockError(err); kind != "" {
					kinds[kind]++
				}
				mu.Unlock()
			}
		}(lane)
	}
	begin := time.Now()
	close(start)
	wg.Wait()
	return summarise(name, concurrency, samples, kinds, time.Since(begin))
}

// newLockCostServices builds both authentication entry points over one isolated
// database with bcrypt cost 4 synthetic hashes.
func newLockCostServices(t *testing.T, accounts int) (*sql.DB, *Service, *passport.Service, []int64) {
	t.Helper()
	db := testdb.Open(t)
	repo := users.New(db, "")
	hasher, err := password.New(string(password.BCRYPT), "")
	if err != nil {
		t.Fatal(err)
	}
	authSvc := &Service{
		Repo:     repo,
		Rev:      revocation.New(db, ""),
		Hasher:   hasher,
		Secret:   []byte(lockCostSecret),
		LoginKey: "login_web_59ba36addc2b2f9401580f014c7f58ea4e30989d",
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(lockCostPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	uids := make([]int64, 0, accounts)
	for i := 0; i < accounts; i++ {
		result, err := db.Exec(`INSERT INTO users(email,nickname,password,permission,verified)
			VALUES(?,?,?,0,1)`, fmt.Sprintf("lockcost%d@example.invalid", i), fmt.Sprintf("Lock%d", i), string(hash))
		if err != nil {
			t.Fatal(err)
		}
		uid, err := result.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		uids = append(uids, uid)
	}
	// One account keeps a bcrypt cost 10 hash (the deployed default cost) so the
	// unauthenticated lock-hold interval can be compared with the cost 4 lanes.
	productionCostHash, err := bcrypt.GenerateFromPassword([]byte(lockCostPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users(email,nickname,password,permission,verified)
		VALUES('lockcost-cost10@example.invalid','LockCost10',?,0,1)`, string(productionCostHash)); err != nil {
		t.Fatal(err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const clientID = int64(9201)
	if _, err := db.Exec(`INSERT INTO oauth_clients(id,name,secret,provider,redirect,
		personal_access_client,password_client,revoked,created_at,updated_at)
		VALUES(?,?,?,?,?,0,1,0,NOW(),NOW())`, clientID, "LockCost", "lockcost-secret", "users",
		"https://client.invalid/callback"); err != nil {
		t.Fatal(err)
	}
	passportSvc, err := passport.New(passport.Config{
		DB:         db,
		Prefix:     "",
		Users:      repo,
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
		AppKey:     []byte(lockCostSecret),
		AccessTTL:  time.Hour,
		RefreshTTL: time.Hour,
		CodeTTL:    time.Minute,
		Scopes:     passport.RegisteredScopes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return db, authSvc, passportSvc, uids
}

// TestLockCostProfile measures the current "verify under the account lock"
// PoC trade-off for the browser login and the Passport password grant. Same
// account, wrong password and different accounts are separated because only the
// first two serialize on one users row.
func TestLockCostProfile(t *testing.T) {
	if os.Getenv("M1_LOCKCOST") != "1" {
		t.Skip("lock-cost profile is opt-in: set M1_LOCKCOST=1 (and optionally M1_LOCKCOST_OUT)")
	}
	const rounds = 4
	db, authSvc, passportSvc, uids := newLockCostServices(t, 32)
	report := struct {
		Environment map[string]any   `json:"environment"`
		Baseline    lockCostResult   `json:"baseline_single_login"`
		Results     []lockCostResult `json:"results"`
		Notes       []string         `json:"notes"`
	}{
		Environment: map[string]any{
			"bcrypt_cost":               bcrypt.MinCost,
			"max_open_connections":      db.Stats().MaxOpenConnections,
			"isolation":                 "MariaDB 10.11 default REPEATABLE READ, isolated testdb database",
			"scenario_ops_per_worker":   rounds,
			"passport_client":           9201,
			"accounts":                  len(uids),
			"verify_under_account_lock": true,
		},
		Notes: []string{
			"Latency includes client wait, account row acquisition and bcrypt verification.",
			"Same-account scenarios serialize on the users row; different-account scenarios do not.",
			"These are PoC capacity observations, not production SLO or sizing evidence.",
		},
	}

	// Baseline: one login with no contention.
	begin := time.Now()
	if _, err := authSvc.Login(context.Background(), "lockcost0@example.invalid", lockCostPassword, false); err != nil {
		t.Fatalf("baseline login: %v", err)
	}
	report.Baseline = lockCostResult{Name: "baseline_single_login", Concurrency: 1, Ops: 1,
		WallMS: float64(time.Since(begin)) / float64(time.Millisecond),
		P50MS:  float64(time.Since(begin)) / float64(time.Millisecond)}

	email := func(lane int) string { return fmt.Sprintf("lockcost%d@example.invalid", lane) }
	client := strconv.FormatInt(9201, 10)

	for _, concurrency := range lockCostConcurrency {
		// Browser login, one shared account.
		report.Results = append(report.Results, runLockCost(t, "login_same_account_bcrypt_ok", concurrency, rounds,
			func(ctx context.Context, _ int) error {
				_, err := authSvc.Login(ctx, "lockcost0@example.invalid", lockCostPassword, false)
				return err
			}))
		// Browser login, one shared account, wrong password (still verifies under
		// the same lock, so this isolates the failed-verification cost).
		report.Results = append(report.Results, runLockCost(t, "login_same_account_bcrypt_wrong", concurrency, rounds,
			func(ctx context.Context, _ int) error {
				_, err := authSvc.Login(ctx, "lockcost0@example.invalid", "wrong-password-1", false)
				if errors.Is(err, ErrBadPassword) {
					return nil
				}
				return err
			}))
		// Browser login, one account per worker.
		report.Results = append(report.Results, runLockCost(t, "login_different_accounts", concurrency, rounds,
			func(ctx context.Context, lane int) error {
				_, err := authSvc.Login(ctx, email(lane), lockCostPassword, false)
				return err
			}))
		// Passport password grant, one shared account.
		report.Results = append(report.Results, runLockCost(t, "passport_password_same_account", concurrency, rounds,
			func(ctx context.Context, _ int) error {
				_, err := passportSvc.Password(ctx, client, "lockcost-secret", "lockcost0@example.invalid", lockCostPassword, "")
				return err
			}))
		// Passport password grant, one account per worker.
		report.Results = append(report.Results, runLockCost(t, "passport_password_different_accounts", concurrency, rounds,
			func(ctx context.Context, lane int) error {
				_, err := passportSvc.Password(ctx, client, "lockcost-secret", email(lane), lockCostPassword, "")
				return err
			}))
	}

	// Cross-account impact: with the shared account saturated, a different
	// account must still be served instead of queueing behind that row.
	saturated := make(chan struct{})
	crossBegin := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-saturated:
					return
				default:
				}
				_, _ = authSvc.Login(context.Background(), "lockcost0@example.invalid", lockCostPassword, false)
			}
		}()
	}
	crossAcct := make([]time.Duration, 0, 8)
	for i := 0; i < 8; i++ {
		begin := time.Now()
		if _, err := authSvc.Login(context.Background(), email(i+1), lockCostPassword, false); err != nil {
			t.Fatalf("cross-account login: %v", err)
		}
		crossAcct = append(crossAcct, time.Since(begin))
	}
	close(saturated)
	wg.Wait()
	report.Results = append(report.Results, summarise("login_other_account_while_shared_account_saturated", 1, crossAcct, nil, time.Since(crossBegin)))

	// Unauthenticated lock-hold interval: bcrypt cost 10 is the deployed default,
	// so this measures how long a single login holds the account row before a
	// concurrent attempt can be served.
	for _, spec := range []struct {
		name string
		cons int
	}{{"login_cost10_sequential", 1}, {"login_cost10_concurrent_same_account", 8}} {
		samples := make([]time.Duration, 0, 3)
		var mu sync.Mutex
		var wg sync.WaitGroup
		begin := time.Now()
		for lane := 0; lane < spec.cons; lane++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 3; i++ {
					opBegin := time.Now()
					if _, err := authSvc.Login(context.Background(), "lockcost-cost10@example.invalid", lockCostPassword, false); err != nil {
						t.Errorf("cost-10 login: %v", err)
						return
					}
					mu.Lock()
					samples = append(samples, time.Since(opBegin))
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		report.Results = append(report.Results, summarise(spec.name, spec.cons, samples, nil, time.Since(begin)))
	}

	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("\n%s", payload)
	if out := os.Getenv("M1_LOCKCOST_OUT"); out != "" {
		if err := os.WriteFile(out, append(payload, '\n'), 0o600); err != nil {
			t.Fatalf("write %s: %v", out, err)
		}
	}
}

// TestLoginTimeoutReleasesAccountLock covers the bounded-context requirement:
// a login that gives up while waiting for the account row must not keep the
// lock, the connection or a goroutine behind.
func TestLoginTimeoutReleasesAccountLock(t *testing.T) {
	db := testdb.Open(t)
	authSvc, uids := newTimeoutServices(t, db)

	holder, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var locked int64
	if err := holder.QueryRowContext(context.Background(), "SELECT uid FROM users WHERE uid=? FOR UPDATE", uids[0]).Scan(&locked); err != nil {
		_ = holder.Rollback()
		t.Fatalf("holder lock: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	begin := time.Now()
	_, err = authSvc.Login(ctx, "timeout@example.invalid", lockCostPassword, false)
	if err == nil {
		_ = holder.Rollback()
		t.Fatal("login succeeded while another transaction held the account lock")
	}
	if time.Since(begin) > 5*time.Second {
		_ = holder.Rollback()
		t.Fatalf("login did not respect its bounded context (took %s)", time.Since(begin))
	}
	if kind := classifyLockError(err); kind == "" {
		_ = holder.Rollback()
		t.Fatalf("unexpected login error: %v", err)
	}

	if err := holder.Rollback(); err != nil {
		t.Fatalf("release holder: %v", err)
	}

	// The account row must be free again: a NOWAIT probe succeeds once the
	// holder is gone, and a fresh login works, which also proves the abandoned
	// transaction and its connection were reclaimed.
	deadline := time.Now().Add(10 * time.Second)
	for {
		probe, probeErr := db.BeginTx(context.Background(), nil)
		if probeErr != nil {
			t.Fatal(probeErr)
		}
		var got int64
		probeErr = probe.QueryRowContext(context.Background(), "SELECT uid FROM users WHERE uid=? FOR UPDATE NOWAIT", uids[0]).Scan(&got)
		_ = probe.Rollback()
		if probeErr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("account lock was not released: %v", probeErr)
		}
		time.Sleep(50 * time.Millisecond)
	}
	waitForIdlePool(t, db)
	if _, err := authSvc.Login(context.Background(), "timeout@example.invalid", lockCostPassword, false); err != nil {
		t.Fatalf("login after the timeout failed: %v", err)
	}
}

func waitForIdlePool(t *testing.T, db *sql.DB) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		stats := db.Stats()
		if stats.InUse == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("connection pool did not drain: in_use=%d open=%d", stats.InUse, stats.OpenConnections)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func newTimeoutServices(t *testing.T, db *sql.DB) (*Service, []int64) {
	t.Helper()
	repo := users.New(db, "")
	hasher, err := password.New(string(password.BCRYPT), "")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(lockCostPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	result, err := db.Exec(`INSERT INTO users(email,nickname,password,permission,verified)
		VALUES('timeout@example.invalid','Timeout',?,0,1)`, string(hash))
	if err != nil {
		t.Fatal(err)
	}
	uid, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return &Service{
		Repo:     repo,
		Rev:      revocation.New(db, ""),
		Hasher:   hasher,
		Secret:   []byte(lockCostSecret),
		LoginKey: "login_web_59ba36addc2b2f9401580f014c7f58ea4e30989d",
	}, []int64{uid}
}
