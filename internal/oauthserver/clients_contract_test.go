package oauthserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/identity"
)

func ownedClientOperations(s *Server, browser *identity.BrowserSession) []struct {
	name string
	run  func(context.Context, int64) error
} {
	return []struct {
		name string
		run  func(context.Context, int64) error
	}{
		{"detail", func(ctx context.Context, id int64) error {
			_, err := s.GetClientDetail(ctx, browser, id)
			return err
		}},
		{"update", func(ctx context.Context, id int64) error {
			_, err := s.UpdateClient(ctx, browser, id, "updated", "https://client.example.invalid/callback", nil, nil)
			return err
		}},
		{"delete", func(ctx context.Context, id int64) error {
			return s.DeleteClient(ctx, browser, id)
		}},
	}
}

func TestOwnedClientManagementOwnerScopeAndSessionRecheck(t *testing.T) {
	s := fixture(t)
	browser, err := s.cfg.Identity.Login(t.Context(), "user@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.cfg.Identity.Login(t.Context(), "admin@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range ownedClientOperations(s, other) {
		t.Run(op.name+"/foreign", func(t *testing.T) {
			if err := op.run(t.Context(), 1); !errors.Is(err, ErrPassportNotFound) {
				t.Fatalf("foreign client: %v", err)
			}
		})
	}
	for _, op := range ownedClientOperations(s, browser) {
		t.Run(op.name+"/missing", func(t *testing.T) {
			if err := op.run(t.Context(), 999); !errors.Is(err, ErrPassportNotFound) {
				t.Fatalf("missing client: %v", err)
			}
		})
		t.Run(op.name+"/owner", func(t *testing.T) {
			if err := op.run(t.Context(), 1); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err = s.cfg.Identity.Logout(t.Context(), browser.Token); err != nil {
		t.Fatal(err)
	}
	for _, op := range ownedClientOperations(s, browser) {
		t.Run(op.name+"/stale-session", func(t *testing.T) {
			if err := op.run(t.Context(), 1); !errors.Is(err, identity.ErrSession) {
				t.Fatalf("logged-out browser: %v", err)
			}
		})
	}
}

// With the owned client held by another transaction, even a stale browser
// must wait for that lock before checking its session. The old users-first
// path returns ErrSession instead of reaching the context deadline.
func TestOwnedClientManagementLocksClientBeforeBrowser(t *testing.T) {
	s := fixture(t)
	browser, err := s.cfg.Identity.Login(t.Context(), "user@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.cfg.Identity.Logout(t.Context(), browser.Token); err != nil {
		t.Fatal(err)
	}
	holder, err := s.cfg.Store.DB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	var id int64
	if err = holder.QueryRowContext(t.Context(), "SELECT id FROM "+s.cfg.Store.Table("oauth_clients")+" WHERE id=1 FOR UPDATE").Scan(&id); err != nil {
		t.Fatal(err)
	}
	for _, op := range ownedClientOperations(s, browser) {
		t.Run(op.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			if err := op.run(ctx, id); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("client lock must precede browser recheck: %v", err)
			}
		})
	}
}
