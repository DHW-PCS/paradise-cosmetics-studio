package links

// These tests need an isolated MySQL server through M1_TEST_DSN. They exercise
// R06 (one verified link identity for Verify/Observe/Consume) and the D06
// single-consumption contract. Only the exported API is used so the same file
// runs unchanged against the pre-fix baseline for counterexample evidence. The
// signature-encoding test at the end needs no database.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"blessing-skin-go/internal/legacy/testdb"
)

const (
	itKey   = "base64:literal-configured-key"
	itEmail = "r06@example.invalid"
	itHash  = "$2y$04$unused-hash-for-r06"
)

// itNow is the fixed clock shared by the ledger and the signed links.
var itNow = time.Unix(1770000000, 0)

// signURL builds a legacy relative signed URL for target, where target is the
// deployment-independent representation (path plus raw query).
func signURL(key, target string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(target))
	sum := hex.EncodeToString(mac.Sum(nil))
	if strings.Contains(target, "?") {
		return target + "&signature=" + sum
	}
	return target + "?signature=" + sum
}

func newLedger(t *testing.T, db *sql.DB, basePath string) *Ledger {
	t.Helper()
	ledger := &Ledger{DB: db, Key: itKey, BasePath: basePath, Now: func() time.Time { return itNow }}
	if err := ledger.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}
	return ledger
}

func seedUser(t *testing.T, db *sql.DB, email, hash string) int64 {
	t.Helper()
	result, err := db.Exec(`INSERT INTO users(email,nickname,password,permission,verified) VALUES(?,?,?,0,1)`, email, "R06", hash)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return uid
}

func claimRows(t *testing.T, db *sql.DB, prefix string) (fingerprints []string, consumed []bool) {
	t.Helper()
	rows, err := db.Query("SELECT fingerprint,consumed FROM " + prefix + "go_link_claims ORDER BY fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var fingerprint string
		var used bool
		if err := rows.Scan(&fingerprint, &used); err != nil {
			t.Fatal(err)
		}
		fingerprints = append(fingerprints, fingerprint)
		consumed = append(consumed, used)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return fingerprints, consumed
}

func resetTarget(uid int64, expires int64) string {
	return "/auth/reset/" + strconv.FormatInt(uid, 10) + "?expires=" + strconv.FormatInt(expires, 10) + "&next=%2Fhello%3Fx%3D1"
}

// TestR06RepresentationIndependentClaim is the primary R06 counterexample: the
// link observed as a relative URL must be consumable from its absolute form and
// the other way round, and the persisted fingerprint must not be a raw URL hash.
func TestR06RepresentationIndependentClaim(t *testing.T) {
	db := testdb.Open(t)
	ledger := newLedger(t, db, "")
	ctx := context.Background()
	uid := seedUser(t, db, itEmail, itHash)
	identity := Identity(itEmail, itHash)
	expiry := itNow.Unix() + 600
	target := resetTarget(uid, expiry)
	relative := signURL(itKey, target)
	absolute := "https://mail.invalid" + relative

	if err := ledger.Observe(ctx, relative, "reset", identity, uid, expiry); err != nil {
		t.Fatalf("observe relative: %v", err)
	}
	fingerprints, _ := claimRows(t, db, "")
	if len(fingerprints) != 1 {
		t.Fatalf("claim rows = %d, want 1", len(fingerprints))
	}
	if fingerprints[0] == Fingerprint(relative) || fingerprints[0] == Fingerprint(absolute) {
		t.Fatal("claim fingerprint is still a raw URL hash")
	}
	if err := ledger.Consume(ctx, absolute, "reset", identity, uid); err != nil {
		t.Fatalf("consume the absolute form of an observed relative link: %v", err)
	}
	_, consumed := claimRows(t, db, "")
	if len(consumed) != 1 || !consumed[0] {
		t.Fatal("claim not consumed exactly once")
	}
	if err := ledger.Consume(ctx, relative, "reset", identity, uid); !errors.Is(err, ErrDenied) {
		t.Fatalf("replay after absolute consumption = %v, want ErrDenied", err)
	}

	// Reverse direction: observe the absolute form, consume the relative one.
	target = resetTarget(uid, expiry+1)
	relative = signURL(itKey, target)
	absolute = "https://mail.invalid" + relative
	if err := ledger.Observe(ctx, absolute, "reset", identity, uid, expiry+1); err != nil {
		t.Fatalf("observe absolute: %v", err)
	}
	if err := ledger.Consume(ctx, relative, "reset", identity, uid); err != nil {
		t.Fatalf("consume the relative form of an observed absolute link: %v", err)
	}
}

// TestR06SubPathRepresentations keeps the deployment mount prefix out of the
// claim identity while still requiring it in every representation.
func TestR06SubPathRepresentations(t *testing.T) {
	db := testdb.Open(t)
	ledger := newLedger(t, db, "/sub")
	ctx := context.Background()
	uid := seedUser(t, db, itEmail, itHash)
	identity := Identity(itEmail, itHash)
	expiry := itNow.Unix() + 600
	target := resetTarget(uid, expiry)
	signed := signURL(itKey, target)

	if err := ledger.Observe(ctx, "https://a.invalid/sub"+signed, "reset", identity, uid, expiry); err != nil {
		t.Fatalf("observe absolute sub-path: %v", err)
	}
	if err := ledger.Consume(ctx, "https://b.invalid/sub"+signed, "reset", identity, uid); err != nil {
		t.Fatalf("consume another origin under the same sub-path: %v", err)
	}

	// The mount-relative browser path and the absolute form share one claim.
	signed = signURL(itKey, resetTarget(uid, expiry+2))
	if err := ledger.Observe(ctx, "/sub"+signed, "reset", identity, uid, expiry+2); err != nil {
		t.Fatalf("observe mount-relative path: %v", err)
	}
	if err := ledger.Consume(ctx, "https://c.invalid/sub"+signed, "reset", identity, uid); err != nil {
		t.Fatalf("consume absolute form of a mount-relative observation: %v", err)
	}

	// A configured mount prefix is stripped before signing; a different prefix
	// that does not match the URL leaves it in the representation and denies it.
	signed = signURL(itKey, resetTarget(uid, expiry+3))
	if err := ledger.Observe(ctx, signed, "reset", identity, uid, expiry+3); !errors.Is(err, ErrDenied) {
		t.Fatalf("observe without the configured mount prefix = %v, want ErrDenied", err)
	}
	other := &Ledger{DB: db, Key: itKey, BasePath: "/otherx", Now: func() time.Time { return itNow }}
	if err := other.Observe(ctx, "https://c.invalid/other"+signed, "reset", identity, uid, expiry+3); !errors.Is(err, ErrDenied) {
		t.Fatalf("mismatched mount prefix = %v, want ErrDenied", err)
	}
}

// TestR06ClaimChecksKeepClaimUnconsumed covers uid/kind/identity mismatches.
func TestR06ClaimChecksKeepClaimUnconsumed(t *testing.T) {
	db := testdb.Open(t)
	ledger := newLedger(t, db, "")
	ctx := context.Background()
	uid := seedUser(t, db, itEmail, itHash)
	other := seedUser(t, db, "r06-other@example.invalid", itHash)
	identity := Identity(itEmail, itHash)
	expiry := itNow.Unix() + 600
	signed := signURL(itKey, resetTarget(uid, expiry))
	if err := ledger.Observe(ctx, signed, "reset", identity, uid, expiry); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, raw, kind, identity string
		uid                       int64
	}{
		{"wrong-uid", signed, "reset", identity, other},
		{"wrong-kind", signed, "verify", identity, uid},
		{"wrong-identity", signed, "reset", Identity(itEmail, "other-hash"), uid},
		{"unknown-identity", signed, "reset", strings.Repeat("0", 64), uid},
	}
	for _, c := range cases {
		if err := ledger.Consume(ctx, c.raw, c.kind, c.identity, c.uid); err == nil {
			t.Fatalf("%s: consumption accepted", c.name)
		}
	}
	// Every rejected attempt must leave the claim usable.
	if err := ledger.Consume(ctx, "https://mail.invalid"+signed, "reset", identity, uid); err != nil {
		t.Fatalf("claim unusable after rejected attempts: %v", err)
	}
}

// TestR06IssuanceAndExpiryRejections pins the Observe envelope.
func TestR06IssuanceAndExpiryRejections(t *testing.T) {
	db := testdb.Open(t)
	ledger := newLedger(t, db, "")
	ctx := context.Background()
	uid := seedUser(t, db, itEmail, itHash)
	identity := Identity(itEmail, itHash)

	cases := []struct {
		name   string
		url    string
		kind   string
		uid    int64
		expiry int64
		ident  string
	}{
		{"expiry-beyond-envelope", signURL(itKey, resetTarget(uid, itNow.Unix()+7200)), "reset", uid, itNow.Unix() + 7201, identity},
		{"expiry-in-the-past", signURL(itKey, resetTarget(uid, itNow.Unix())), "reset", uid, itNow.Unix() - 1, identity},
		{"expiry-after-url-window", signURL(itKey, resetTarget(uid, itNow.Unix()+60)), "reset", uid, itNow.Unix() + 120, identity},
		{"expired-url", signURL(itKey, resetTarget(uid, itNow.Unix()-10)), "reset", uid, itNow.Unix() + 60, identity},
		{"unknown-kind", signURL(itKey, resetTarget(uid, itNow.Unix()+60)), "signup", uid, itNow.Unix() + 60, identity},
		{"no-uid", signURL(itKey, resetTarget(uid, itNow.Unix()+60)), "reset", 0, itNow.Unix() + 60, identity},
		{"bad-identity-length", signURL(itKey, resetTarget(uid, itNow.Unix()+60)), "reset", uid, itNow.Unix() + 60, "short"},
		{"non-numeric-expiry", signURL(itKey, "/auth/reset/"+strconv.FormatInt(uid, 10)+"?expires=soon"), "reset", uid, itNow.Unix() + 60, identity},
	}
	for _, c := range cases {
		if err := ledger.Observe(ctx, c.url, c.kind, c.ident, c.uid, c.expiry); err == nil {
			t.Fatalf("%s: claim accepted", c.name)
		}
	}
	if rows, _ := claimRows(t, db, ""); len(rows) != 0 {
		t.Fatalf("rejected issuance left %d claim rows", len(rows))
	}
	// A verify link has no native expiry parameter; the claim window is enough.
	if err := ledger.Observe(ctx, signURL(itKey, "/auth/verify/"+strconv.FormatInt(uid, 10)), "verify", identity, uid, itNow.Unix()+300); err != nil {
		t.Fatalf("observe verify link: %v", err)
	}
}

// TestR06ConcurrentConsumeExactlyOnce keeps D06 under two independent callers.
func TestR06ConcurrentConsumeExactlyOnce(t *testing.T) {
	db := testdb.Open(t)
	ledger := newLedger(t, db, "")
	ctx := context.Background()
	uid := seedUser(t, db, itEmail, itHash)
	identity := Identity(itEmail, itHash)
	expiry := itNow.Unix() + 600
	signed := signURL(itKey, resetTarget(uid, expiry))
	if err := ledger.Observe(ctx, signed, "reset", identity, uid, expiry); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = ledger.Consume(ctx, signed, "reset", identity, uid)
		}(i)
	}
	wg.Wait()
	winners := 0
	for _, err := range results {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrDenied), errors.Is(err, ErrChallenge):
		default:
			t.Fatalf("unexpected concurrent consume error: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent consumers succeeded %d times, want 1", winners)
	}
}

// TestR06FailureRollsBackConsumption proves a failed password change leaves the
// claim available and undoes the partial work of the same transaction.
func TestR06FailureRollsBackConsumption(t *testing.T) {
	db := testdb.Open(t)
	ledger := newLedger(t, db, "")
	ctx := context.Background()
	uid := seedUser(t, db, itEmail, itHash)
	identity := Identity(itEmail, itHash)
	expiry := itNow.Unix() + 600
	signed := signURL(itKey, resetTarget(uid, expiry))
	if err := ledger.Observe(ctx, signed, "reset", identity, uid, expiry); err != nil {
		t.Fatal(err)
	}
	lock := func(ctx context.Context, tx *sql.Tx) error {
		var id int
		return tx.QueryRowContext(ctx, "SELECT id FROM go_ygg_lock WHERE id=1 FOR UPDATE").Scan(&id)
	}
	boom := errors.New("m1 injected change failure")
	failing := func(tx *sql.Tx) error {
		if _, err := tx.Exec("UPDATE users SET score=score+7 WHERE uid=?", uid); err != nil {
			return err
		}
		return boom
	}
	if err := ledger.ConsumeReset(ctx, signed, identity, uid, lock, failing); !errors.Is(err, boom) {
		t.Fatalf("ConsumeReset failure = %v, want the injected error", err)
	}
	var score int64
	if err := db.QueryRow("SELECT score FROM users WHERE uid=?", uid).Scan(&score); err != nil {
		t.Fatal(err)
	}
	if score != 0 {
		t.Fatalf("partial transaction work survived the rollback: score=%d", score)
	}
	if _, consumed := claimRows(t, db, ""); len(consumed) != 1 || consumed[0] {
		t.Fatal("claim was consumed although the transaction failed")
	}
	// The same verified representation remains usable.
	changed := false
	change := func(tx *sql.Tx) error {
		if _, err := tx.Exec("UPDATE users SET password=? WHERE uid=?", "$2y$04$new-hash-for-r06", uid); err != nil {
			return err
		}
		changed = true
		return nil
	}
	if err := ledger.ConsumeReset(ctx, "https://mail.invalid"+signed, identity, uid, lock, change); err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}
	if !changed {
		t.Fatal("password change was not applied")
	}
	if _, consumed := claimRows(t, db, ""); len(consumed) != 1 || !consumed[0] {
		t.Fatal("claim not consumed by the successful retry")
	}
	// The stored identity version no longer matches the changed account, so a
	// later replay cannot resurrect the link.
	if err := ledger.Consume(ctx, signed, "reset", identity, uid); !errors.Is(err, ErrDenied) {
		t.Fatalf("replay after password change = %v, want ErrDenied", err)
	}
}

// TestR06ChangedIdentityRequiresNewChallenge keeps the identity binding after an
// email/password change and shows a rebuilt claim still works.
func TestR06ChangedIdentityRequiresNewChallenge(t *testing.T) {
	db := testdb.Open(t)
	ledger := newLedger(t, db, "")
	ctx := context.Background()
	uid := seedUser(t, db, itEmail, itHash)
	identity := Identity(itEmail, itHash)
	expiry := itNow.Unix() + 600
	signed := signURL(itKey, resetTarget(uid, expiry))
	if err := ledger.Observe(ctx, signed, "reset", identity, uid, expiry); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE users SET email=?,password=? WHERE uid=?", "r06-new@example.invalid", "$2y$04$new", uid); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Consume(ctx, signed, "reset", identity, uid); !errors.Is(err, ErrDenied) {
		t.Fatalf("consumption after identity change = %v, want ErrDenied", err)
	}
	if _, consumed := claimRows(t, db, ""); len(consumed) != 1 || consumed[0] {
		t.Fatal("stale-identity attempt consumed the claim")
	}
	// A new controlled issuance for the current identity succeeds.
	if _, err := db.Exec("DELETE FROM go_link_claims"); err != nil {
		t.Fatal(err)
	}
	fresh := Identity("r06-new@example.invalid", "$2y$04$new")
	if err := ledger.Observe(ctx, signed, "reset", fresh, uid, expiry); err != nil {
		t.Fatalf("observe after identity change: %v", err)
	}
	if err := ledger.Consume(ctx, signed, "reset", fresh, uid); err != nil {
		t.Fatalf("consume fresh claim: %v", err)
	}
}

// TestR06ConsumeHoldsCanonicalLockOrder probes the global -> users -> claim lock
// order with NOWAIT readers while the consumption transaction is open.
func TestR06ConsumeHoldsCanonicalLockOrder(t *testing.T) {
	db := testdb.Open(t)
	ledger := newLedger(t, db, "")
	ctx := context.Background()
	uid := seedUser(t, db, itEmail, itHash)
	identity := Identity(itEmail, itHash)
	expiry := itNow.Unix() + 600
	signed := signURL(itKey, resetTarget(uid, expiry))
	if err := ledger.Observe(ctx, signed, "reset", identity, uid, expiry); err != nil {
		t.Fatal(err)
	}
	lock := func(ctx context.Context, tx *sql.Tx) error {
		var id int
		return tx.QueryRowContext(ctx, "SELECT id FROM go_ygg_lock WHERE id=1 FOR UPDATE").Scan(&id)
	}
	fingerprints, _ := claimRows(t, db, "")
	if len(fingerprints) != 1 {
		t.Fatalf("claim rows = %d, want 1", len(fingerprints))
	}
	claim := fingerprints[0]
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	releaseOnce := func() { once.Do(func() { close(release) }) }
	t.Cleanup(releaseOnce)
	change := func(tx *sql.Tx) error {
		close(entered)
		<-release
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- ledger.ConsumeReset(ctx, signed, identity, uid, lock, change) }()
	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("consumption transaction never reached the change hook")
	}

	probes := []struct {
		name, query string
		args        []any
	}{
		{"global-writer-lock", "SELECT id FROM go_ygg_lock WHERE id=1 FOR UPDATE NOWAIT", nil},
		{"users-row-lock", "SELECT uid FROM users WHERE uid=? FOR UPDATE NOWAIT", []any{uid}},
		{"claim-row-lock", "SELECT fingerprint FROM go_link_claims WHERE fingerprint=? FOR UPDATE NOWAIT", []any{claim}},
	}
	for _, probe := range probes {
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var value any
		err = conn.QueryRowContext(ctx, probe.query, probe.args...).Scan(&value)
		if err == nil {
			t.Fatalf("%s: probe acquired a lock held by the consumption transaction", probe.name)
		}
		_ = conn.Close()
	}
	// A concurrent password writer cannot apply while the consumption transaction
	// holds the users row: an interleaved password change is serialized instead of
	// racing the identity check.
	writer, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.ExecContext(ctx, "SET SESSION innodb_lock_wait_timeout=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.ExecContext(ctx, "UPDATE users SET password=? WHERE uid=?", "$2y$04$concurrent", uid); err == nil {
		t.Fatal("interleaved password change applied while the consumption held the row lock")
	}
	_ = writer.Close()
	releaseOnce()
	if err := <-done; err != nil {
		t.Fatalf("consumption transaction failed: %v", err)
	}
	// After the consumption commits, the serialized writer can apply and a replay
	// of the consumed link stays denied.
	if _, err := db.Exec("UPDATE users SET password=? WHERE uid=?", "$2y$04$after", uid); err != nil {
		t.Fatalf("serialized password change after consumption: %v", err)
	}
	if _, consumed := claimRows(t, db, ""); len(consumed) != 1 || !consumed[0] {
		t.Fatal("claim not consumed after the lock probe")
	}
	// With the transaction closed, the pinned locks must be free again.
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var id int
	if err := conn.QueryRowContext(ctx, "SELECT id FROM go_ygg_lock WHERE id=1 FOR UPDATE NOWAIT").Scan(&id); err != nil {
		t.Fatalf("global lock still held after commit: %v", err)
	}
}

// TestR06WrongKeyDoesNotTouchClaim keeps a wrong signature representation from
// creating or consuming anything.
func TestR06WrongKeyDoesNotTouchClaim(t *testing.T) {
	db := testdb.Open(t)
	ledger := newLedger(t, db, "")
	ctx := context.Background()
	uid := seedUser(t, db, itEmail, itHash)
	identity := Identity(itEmail, itHash)
	expiry := itNow.Unix() + 600
	signed := signURL(itKey, resetTarget(uid, expiry))
	if err := ledger.Observe(ctx, signed, "reset", identity, uid, expiry); err != nil {
		t.Fatal(err)
	}
	// Re-signed with the decoded APP_KEY representation: denied, no new row.
	decoded := strings.TrimPrefix(itKey, "base64:")
	forged := signURL(decoded, resetTarget(uid, expiry+5))
	for _, raw := range []string{forged, signed + "&x=1", signed + "#fragment"} {
		if err := ledger.Observe(ctx, raw, "reset", identity, uid, expiry+5); err == nil {
			t.Fatalf("observe accepted %q", raw)
		}
		if err := ledger.Consume(ctx, raw, "reset", identity, uid); err == nil {
			t.Fatalf("consume accepted %q", raw)
		}
	}
	if rows, consumed := claimRows(t, db, ""); len(rows) != 1 || consumed[0] {
		t.Fatal("unverified input changed the claim ledger")
	}
}

// TestSignatureEncodingMatchesNative keeps Go as strict as the frozen Laravel
// signer: hasCorrectSignature compares the lowercase hex string it computes with
// hash_equals, so an uppercase or otherwise non-canonical encoding is denied.
// Decoding the provided value first (the previous behaviour) accepted uppercase
// hex and was therefore broader than native. No database is required.
func TestSignatureEncodingMatchesNative(t *testing.T) {
	target := "/auth/reset/3?expires=" + strconv.FormatInt(itNow.Unix()+600, 10) + "&x=1"
	signed := signURL(itKey, target)
	idx := strings.LastIndex(signed, "signature=") + len("signature=")
	canonical := signed[idx:]
	if canonical == "" || canonical != strings.ToLower(canonical) {
		t.Fatalf("test fixture signature is not canonical lowercase hex: %q", canonical)
	}
	cases := map[string]string{
		"uppercase": strings.ToUpper(canonical),
		"mixed-case": func() string {
			return strings.ToUpper(canonical[:1]) + canonical[1:]
		}(),
		"odd-length":  canonical + "0",
		"non-hex":     "zz" + canonical[2:],
		"truncated":   canonical[:len(canonical)-2],
		"empty-value": "",
	}
	for name, candidate := range cases {
		if err := Verify(signed[:idx]+candidate, itKey, "", itNow); err == nil {
			t.Fatalf("%s signature encoding accepted although native rejects it", name)
		}
	}
	if err := Verify(signed, itKey, "", itNow); err != nil {
		t.Fatalf("canonical lowercase signature rejected: %v", err)
	}
}
