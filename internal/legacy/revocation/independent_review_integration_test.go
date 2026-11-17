package revocation_test

// Independent review addition for the A package: the record's invariant list says
// the BumpTx watermark is guarded by GREATEST, but the shared writer assigns
// VALUES (the caller's clock) directly. This opt-in check documents the gap; it
// is gated so a deliberately failing assertion stays out of the regular suite.

import (
	"context"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/legacy/revocation"
	"paradise-cosmetics-studio/internal/legacy/testdb"
)

// reviewWatermarkHash is a synthetic password hash; only the HMAC fingerprint matters.
const reviewWatermarkHash = "$2y$04$independent-review-watermark"

// TestReviewBumpWatermarkNeverRegresses: a writer whose clock is behind (or a
// retried/parallel writer passing an older timestamp) must not move the
// revocation watermark backwards.
func TestReviewBumpWatermarkNeverRegresses(t *testing.T) {
	db := testdb.Open(t)
	ctx := context.Background()
	if _, err := db.Exec("INSERT INTO users(uid,email,nickname,password) VALUES(1,'review-watermark@example.invalid','Nick',?)", reviewWatermarkHash); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	store := revocation.New(db, "")
	secret := []byte("0123456789abcdef0123456789abcdef")

	ahead := time.Now().Add(time.Hour).Truncate(time.Second)
	behind := ahead.Add(-30 * time.Minute)
	first, err := store.Bump(ctx, 1, reviewWatermarkHash, secret, ahead)
	if err != nil {
		t.Fatalf("first bump: %v", err)
	}
	if first.SessionVersion != 1 {
		t.Fatalf("first bump version = %d, want 1", first.SessionVersion)
	}
	second, err := store.Bump(ctx, 1, reviewWatermarkHash, secret, behind)
	if err != nil {
		t.Fatalf("second bump: %v", err)
	}
	if second.SessionVersion != first.SessionVersion+1 {
		t.Fatalf("second bump version = %d, want %d", second.SessionVersion, first.SessionVersion+1)
	}
	if second.RevokedBefore < first.RevokedBefore {
		t.Errorf("BumpTx regressed revoked_before from %d to %d; the A record's invariant says the watermark uses GREATEST",
			first.RevokedBefore, second.RevokedBefore)
	}
}
