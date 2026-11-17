package yggdrasil_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/players"
	"paradise-cosmetics-studio/internal/yggdrasil"
)

// TestTokenEntriesLockUserBeforeToken is the deterministic lock-cycle
// regression for Refresh/Validate/VerifyBearerToken (integration-design
// section 3: users/version -> token). A barrier transaction holds the
// users row lock, as a signout/authenticate eviction or maintenance
// cleanup transaction does before it touches the token set. The entry
// under test must then block on the users lock without first holding
// the token row lock: the barrier transaction can still lock the token
// row (the users -> token edge) and finish, after which the entry
// proceeds. Under the old token-first order the entry would hold the
// token lock while blocked on users, the probe would block, and the
// two transactions would form a cycle. The bounded waits only give the
// entry goroutine a chance to reach its first lock; they do not claim
// that absence of a deadlock in one run proves the order in general.
func TestTokenEntriesLockUserBeforeToken(t *testing.T) {
	entries := []struct {
		name string
		run  func(h harness, token string) error
	}{
		{"refresh", func(h harness, token string) error {
			_, err := h.svc.Refresh(t.Context(), yggdrasil.RefreshRequest{AccessToken: token})
			return err
		}},
		{"validate", func(h harness, token string) error {
			return h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: token})
		}},
		{"bearer", func(h harness, token string) error {
			_, err := h.svc.VerifyBearerToken(t.Context(), token)
			return err
		}},
	}
	for _, entry := range entries {
		t.Run(entry.name, func(t *testing.T) {
			h := fixture(t)
			token := authToken(t, h)

			txA, err := h.store.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			var uid int64
			if err := txA.QueryRowContext(context.Background(), "SELECT uid FROM "+h.store.Table("users")+" WHERE uid=1 FOR UPDATE").Scan(&uid); err != nil {
				t.Fatal(err)
			}

			done := make(chan error, 1)
			go func() { done <- entry.run(h, token) }()

			time.Sleep(300 * time.Millisecond)
			select {
			case err := <-done:
				_ = txA.Rollback()
				t.Fatalf("entry finished while the users lock was held (err=%v); it must block on users first", err)
			default:
			}

			probeDone := make(chan error, 1)
			go func() {
				var digest []byte
				probeDone <- txA.QueryRowContext(context.Background(), "SELECT digest FROM "+h.store.Table("go_yggdrasil_tokens")+" WHERE user_uid=1 FOR UPDATE").Scan(&digest)
			}()
			select {
			case err := <-probeDone:
				if err != nil {
					_ = txA.Rollback()
					<-done
					t.Fatalf("users holder could not lock the token row: %v", err)
				}
			case <-time.After(5 * time.Second):
				// Release the users lock so the entry can finish and
				// the probe can complete; then report the cycle edge.
				_ = txA.Rollback()
				<-probeDone
				<-done
				t.Fatal("token lock probe blocked: entry took the token lock before the users lock (users <-> token cycle)")
			}

			if err := txA.Rollback(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("entry after users lock release: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("entry did not complete after the users lock was released")
			}
		})
	}
}

// TestHasJoinedLocksTokenBeforeJoin is the lock-cycle regression for
// hasJoined (integration-design section 3: token -> player/binding ->
// join). A barrier transaction holds the token row lock; hasJoined must
// block on the token lock without first holding the join row lock, so
// the barrier transaction can still lock the join row and finish.
// Under the old join-first order the probe would block and the two
// transactions would form a token <-> join cycle.
func TestHasJoinedLocksTokenBeforeJoin(t *testing.T) {
	h := fixture(t)
	token := authToken(t, h)
	setOption(t, h.store, "ygg_private_key", genKey(t, 2048))
	dashed := yggdrasil.MustDashed(players.UUID3("PlayerOne"))
	if err := h.svc.JoinServer(t.Context(), yggdrasil.JoinServerRequest{AccessToken: token, SelectedProfile: dashed, ServerID: "srv-lock", ClientIP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	ip := "127.0.0.1"

	txA, err := h.store.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var digest []byte
	if err := txA.QueryRowContext(context.Background(), "SELECT digest FROM "+h.store.Table("go_yggdrasil_tokens")+" WHERE user_uid=1 FOR UPDATE").Scan(&digest); err != nil {
		t.Fatal(err)
	}

	type result struct {
		ok  bool
		err error
	}
	done := make(chan result, 1)
	go func() {
		_, ok, err := h.svc.HasJoinedServer(t.Context(), yggdrasil.HasJoinedServerRequest{Username: "PlayerOne", ServerID: "srv-lock", IP: &ip})
		done <- result{ok: ok, err: err}
	}()

	time.Sleep(300 * time.Millisecond)
	select {
	case r := <-done:
		_ = txA.Rollback()
		t.Fatalf("hasJoined finished while the token lock was held (ok=%v err=%v); it must block on token first", r.ok, r.err)
	default:
	}

	probeDone := make(chan error, 1)
	go func() {
		var jdigest []byte
		probeDone <- txA.QueryRowContext(context.Background(), "SELECT digest FROM "+h.store.Table("go_yggdrasil_joins")+" WHERE user_uid=1 FOR UPDATE").Scan(&jdigest)
	}()
	select {
	case err := <-probeDone:
		if err != nil {
			_ = txA.Rollback()
			<-done
			t.Fatalf("token holder could not lock the join row: %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = txA.Rollback()
		<-probeDone
		<-done
		t.Fatal("join lock probe blocked: hasJoined took the join lock before the token lock (token <-> join cycle)")
	}

	if err := txA.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.err != nil || !r.ok {
			t.Fatalf("hasJoined after token lock release: ok=%v err=%v, want matched profile", r.ok, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("hasJoined did not complete after the token lock was released")
	}
}

// TestAuthNotExistedCarriesIdentification checks the reconstructed
// auth.not-existed error: 403 ForbiddenOperationException whose message
// interpolates the submitted identification, with no format placeholder.
func TestAuthNotExistedCarriesIdentification(t *testing.T) {
	h := fixture(t)
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"authenticate", func() error {
			_, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "ghost@example.invalid", Password: "whatever-password"})
			return err
		}},
		{"signout", func() error {
			return h.svc.Signout(t.Context(), yggdrasil.SignoutRequest{Username: "ghost@example.invalid", Password: "whatever-password"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil {
				t.Fatal("unknown identification must be refused")
			}
			if yggdrasil.StatusOf(err) != 403 || yggdrasil.NameOf(err) != "ForbiddenOperationException" {
				t.Fatalf("status/name = %d/%s, want 403/ForbiddenOperationException (err=%v)", yggdrasil.StatusOf(err), yggdrasil.NameOf(err), err)
			}
			apiErr, ok := err.(*yggdrasil.APIError)
			if !ok {
				t.Fatalf("error type %T, want *yggdrasil.APIError", err)
			}
			if apiErr.Message != "User ghost@example.invalid is not found." {
				t.Fatalf("message = %q, want interpolated identification", apiErr.Message)
			}
		})
	}
}

// TestTokenRefusalPriorityPreservedAfterLockReorder pins the observable
// error priority that lock reordering must not change: the DB token row
// stays authoritative over the JWT subject, banned precedes the version
// comparison, and in refresh the version comparison precedes the
// clientToken comparison.
func TestTokenRefusalPriorityPreservedAfterLockReorder(t *testing.T) {
	t.Run("db token uid is authoritative over jwt subject", func(t *testing.T) {
		h := fixture(t)
		token := authToken(t, h)
		if _, err := h.store.DB.Exec("UPDATE " + h.store.Table("go_yggdrasil_tokens") + " SET user_uid=2 WHERE user_uid=1"); err != nil {
			t.Fatal(err)
		}
		wrong := "wrong-client-token"
		if err := h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: token, ClientToken: &wrong}); !errors.Is(err, yggdrasil.ErrTokenInvalid) {
			t.Fatalf("validate uid mismatch err = %v, want token-invalid (before clientToken check)", err)
		}
		if _, err := h.svc.Refresh(t.Context(), yggdrasil.RefreshRequest{AccessToken: token}); !errors.Is(err, yggdrasil.ErrTokenInvalid) {
			t.Fatalf("refresh uid mismatch err = %v, want token-invalid", err)
		}
		if _, err := h.svc.VerifyBearerToken(t.Context(), token); !errors.Is(err, yggdrasil.ErrBearer) {
			t.Fatalf("bearer uid mismatch err = %v, want bearer refusal", err)
		}
	})

	t.Run("banned precedes version mismatch", func(t *testing.T) {
		h := fixture(t)
		token := authToken(t, h)
		if err := h.store.Transaction(t.Context(), func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(t.Context(), "UPDATE "+h.store.Table("users")+" SET permission=-1 WHERE uid=1"); err != nil {
				return err
			}
			return h.id.RevokeUID(t.Context(), tx, 1)
		}); err != nil {
			t.Fatal(err)
		}
		if err := h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: token}); !errors.Is(err, yggdrasil.ErrUserBanned) {
			t.Fatalf("validate banned err = %v, want banned", err)
		}
		if _, err := h.svc.Refresh(t.Context(), yggdrasil.RefreshRequest{AccessToken: token}); !errors.Is(err, yggdrasil.ErrUserBanned) {
			t.Fatalf("refresh banned err = %v, want banned", err)
		}
		if _, err := h.svc.VerifyBearerToken(t.Context(), token); !errors.Is(err, yggdrasil.ErrUserBanned) {
			t.Fatalf("bearer banned err = %v, want banned", err)
		}
	})

	t.Run("refresh version precedes clientToken", func(t *testing.T) {
		h := fixture(t)
		token := authToken(t, h)
		if err := h.store.Transaction(t.Context(), func(tx *sql.Tx) error {
			return h.id.RevokeUID(t.Context(), tx, 1)
		}); err != nil {
			t.Fatal(err)
		}
		wrong := "wrong-client-token"
		if _, err := h.svc.Refresh(t.Context(), yggdrasil.RefreshRequest{AccessToken: token, ClientToken: &wrong}); !errors.Is(err, yggdrasil.ErrTokenInvalid) {
			t.Fatalf("refresh stale version err = %v, want token-invalid (before clientToken check)", err)
		}
	})

	t.Run("hasJoined rejects stale binding version at final read", func(t *testing.T) {
		h := fixture(t)
		token := authToken(t, h)
		setOption(t, h.store, "ygg_private_key", genKey(t, 2048))
		dashed := yggdrasil.MustDashed(players.UUID3("PlayerOne"))
		if err := h.svc.JoinServer(t.Context(), yggdrasil.JoinServerRequest{AccessToken: token, SelectedProfile: dashed, ServerID: "srv-stale", ClientIP: "127.0.0.1"}); err != nil {
			t.Fatal(err)
		}
		ip := "127.0.0.1"
		if _, ok, err := h.svc.HasJoinedServer(t.Context(), yggdrasil.HasJoinedServerRequest{Username: "PlayerOne", ServerID: "srv-stale", IP: &ip}); err != nil || !ok {
			t.Fatalf("hasJoined before stale bump: ok=%v err=%v", ok, err)
		}
		if _, err := h.store.DB.Exec("UPDATE " + h.store.Table("go_uuid_bindings") + " SET version=version+1 WHERE pid=1"); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := h.svc.HasJoinedServer(t.Context(), yggdrasil.HasJoinedServerRequest{Username: "PlayerOne", ServerID: "srv-stale", IP: &ip}); err != nil || ok {
			t.Fatalf("hasJoined after binding bump: ok=%v err=%v, want 204 (nil,false,nil)", ok, err)
		}
	})
}
