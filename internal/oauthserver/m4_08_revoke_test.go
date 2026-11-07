package oauthserver

import (
	"errors"
	"net/http"
	"testing"
)

// RevokeToken promises to revoke the whole owned grant, including the newest
// access/refresh pair after rotation retains older inactive rows.
func TestM408RevokeRotatedGrant(t *testing.T) {
	s := fixture(t)
	ctx := t.Context()
	browser, err := s.cfg.Identity.Login(ctx, "user@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	status, current := exchange(s, codeForm(authorize(t, s, true)))
	success(t, status, current)
	for range 2 {
		status, current = exchange(s, refreshForm(current["refresh_token"].(string)))
		success(t, status, current)
	}
	if _, err := s.Validate(ctx, current["access_token"].(string), "User.Read"); err != nil {
		t.Fatalf("latest access token invalid before revocation: %v", err)
	}
	listed, err := s.ListTokens(ctx, browser)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 {
		t.Fatalf("active grant count=%d, want 1", len(listed))
	}
	id := listed[0].ID
	for _, table := range []string{"go_oauth_access", "go_oauth_refresh"} {
		var total, active int
		if err := s.cfg.Store.DB.QueryRowContext(ctx, "SELECT COUNT(*),SUM(active) FROM "+s.cfg.Store.Table(table)+" WHERE request_id=?", id).Scan(&total, &active); err != nil {
			t.Fatal(err)
		}
		if total != 3 || active != 1 {
			t.Fatalf("%s rotation precondition: total=%d active=%d, want 3/1", table, total, active)
		}
	}
	// Put one consumed access row first in the fixture's InnoDB indexes.
	// Only its stored digest changes; the newest token remains untouched.
	if _, err := s.cfg.Store.DB.ExecContext(ctx, "UPDATE "+s.cfg.Store.Table("go_oauth_access")+" SET signature=? WHERE request_id=? AND active=0 ORDER BY signature LIMIT 1", make([]byte, 32), id); err != nil {
		t.Fatal(err)
	}
	var firstActive bool
	if err := s.cfg.Store.DB.QueryRowContext(ctx, "SELECT active FROM "+s.cfg.Store.Table("go_oauth_access")+" WHERE request_id=? AND user_uid=?", id, browser.User.UID).Scan(&firstActive); err != nil {
		t.Fatal(err)
	}
	if firstActive {
		t.Fatal("fixture must expose a consumed inactive row before the newest active row")
	}

	// Another grant for the same user and client must remain usable.
	status, unrelated := exchange(s, codeForm(authorize(t, s, true)))
	success(t, status, unrelated)
	other, err := s.cfg.Identity.Login(ctx, "admin@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeToken(ctx, other, id); !errors.Is(err, ErrPassportNotFound) {
		t.Fatalf("foreign revocation: %v", err)
	}
	if _, err := s.Validate(ctx, current["access_token"].(string)); err != nil {
		t.Fatalf("foreign revocation affected latest access: %v", err)
	}

	if err := s.RevokeToken(ctx, browser, id); err != nil {
		t.Fatal(err)
	}
	// Check persistence before attempting refresh: replay handling can itself
	// revoke a grant and must not conceal a no-op management revocation.
	for _, table := range []string{"go_oauth_access", "go_oauth_refresh"} {
		var active int
		if err := s.cfg.Store.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.cfg.Store.Table(table)+" WHERE request_id=? AND active=1", id).Scan(&active); err != nil {
			t.Fatal(err)
		}
		if active != 0 {
			t.Fatalf("%s active rows after revocation=%d, want 0", table, active)
		}
	}
	if _, err := s.Validate(ctx, current["access_token"].(string)); !errors.Is(err, ErrToken) {
		t.Fatalf("latest access token after revocation: %v", err)
	}
	status, rejected := exchange(s, refreshForm(current["refresh_token"].(string)))
	if status != http.StatusBadRequest || rejected["error"] != "invalid_grant" {
		t.Fatalf("latest refresh after revocation: status=%d error=%v", status, rejected["error"])
	}
	if err := s.RevokeToken(ctx, browser, id); err != nil {
		t.Fatalf("repeat revocation: %v", err)
	}
	if _, err := s.Validate(ctx, unrelated["access_token"].(string), "User.Read"); err != nil {
		t.Fatalf("unrelated access token revoked: %v", err)
	}
	status, next := exchange(s, refreshForm(unrelated["refresh_token"].(string)))
	success(t, status, next)
}
