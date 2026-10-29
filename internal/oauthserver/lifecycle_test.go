package oauthserver

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"authelia.com/provider/oauth2"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/maintenance"
)

type introspectionFailure struct {
	oauth2.Provider
	err error
}

func (p introspectionFailure) IntrospectToken(context.Context, string, oauth2.TokenUse, oauth2.Session, ...string) (oauth2.TokenUse, oauth2.AccessRequester, error) {
	return "", nil, p.err
}

func TestValidateProtocolErrorClassification(t *testing.T) {
	s := fixture(t)
	cause := errors.New("synthetic provider failure")
	for _, tc := range []struct {
		name      string
		err, want error
	}{
		{"server", oauth2.ErrServerError.WithWrap(cause), ErrUnavailable},
		{"temporary", oauth2.ErrTemporarilyUnavailable.WithWrap(cause), ErrUnavailable},
		{"invalid", oauth2.ErrRequestUnauthorized, ErrToken},
		{"context", context.Canceled, context.Canceled},
		{"other", cause, cause},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s.provider = introspectionFailure{err: fmt.Errorf("provider: %w", tc.err)}
			principal, err := s.Validate(t.Context(), "synthetic")
			if principal != nil || !errors.Is(err, tc.want) {
				t.Fatalf("classification: %v", err)
			}
			if tc.want == ErrUnavailable && !errors.Is(err, cause) {
				t.Fatal("provider cause lost")
			}
		})
	}
}

func TestRefreshReplayRetentionAndCleanup(t *testing.T) {
	s := fixture(t)
	status, data := exchange(s, codeForm(authorize(t, s, true)))
	success(t, status, data)
	old := data["refresh_token"].(string)
	signature := identity.Digest(s.storage.strategy.RefreshTokenSignature(t.Context(), old))
	var expiry int64
	if err := s.cfg.Store.DB.QueryRow("SELECT expires_at FROM "+s.cfg.Store.Table("go_oauth_refresh")+" WHERE signature=?", signature).Scan(&expiry); err != nil {
		t.Fatal(err)
	}
	status, rotated := exchange(s, refreshForm(old))
	success(t, status, rotated)
	for range 2 {
		status, _ = exchange(s, refreshForm(old))
		if status == 200 {
			t.Fatal("replay accepted")
		}
		var active bool
		var retainedExpiry int64
		if err := s.cfg.Store.DB.QueryRow("SELECT active,expires_at FROM "+s.cfg.Store.Table("go_oauth_refresh")+" WHERE signature=?", signature).Scan(&active, &retainedExpiry); err != nil || active || retainedExpiry != expiry {
			t.Fatalf("consumed record not retained: %v", err)
		}
	}
	if _, err := s.Validate(t.Context(), rotated["access_token"].(string)); !errors.Is(err, ErrToken) {
		t.Fatalf("grant not revoked: %v", err)
	}
	for _, tc := range []struct {
		now  int64
		want int
	}{{expiry - 1, 1}, {expiry, 0}} {
		if _, err := maintenance.Cleanup(t.Context(), s.cfg.Store, time.Unix(tc.now, 0), 500); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := s.cfg.Store.DB.QueryRow("SELECT COUNT(*) FROM "+s.cfg.Store.Table("go_oauth_refresh")+" WHERE signature=?", signature).Scan(&count); err != nil || count != tc.want {
			t.Fatalf("cleanup count=%d err=%v", count, err)
		}
	}
}

func TestRefreshReplayStorageFailureRollsBack(t *testing.T) {
	s := fixture(t)
	status, data := exchange(s, codeForm(authorize(t, s, true)))
	success(t, status, data)
	old := data["refresh_token"].(string)
	status, rotated := exchange(s, refreshForm(old))
	success(t, status, rotated)
	if _, err := s.cfg.Store.DB.Exec("CREATE TRIGGER fail_revoke BEFORE UPDATE ON " + s.cfg.Store.Table("go_oauth_access") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic revoke failure'"); err != nil {
		t.Fatal(err)
	}
	status, result := exchange(s, refreshForm(old))
	if status != 500 || result["error"] != "server_error" {
		t.Fatalf("replay fault: %d %v", status, result["error"])
	}
	if _, err := s.cfg.Store.DB.Exec("DROP TRIGGER fail_revoke"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Validate(t.Context(), rotated["access_token"].(string)); err != nil {
		t.Fatalf("partial revocation committed: %v", err)
	}
	status, data = exchange(s, refreshForm(rotated["refresh_token"].(string)))
	success(t, status, data)
}
