package yggdrasil_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"paradise-cosmetics-studio/internal/players"
	"paradise-cosmetics-studio/internal/yggdrasil"
)

// TestModuleLockRefusesBusiness checks the batch4 TX-internal gate: when
// the wired module lock refuses, business transactions abort with
// ErrModuleNotServed before issuing anything.
func TestModuleLockRefusesBusiness(t *testing.T) {
	h := fixture(t)
	setOption(t, h.store, "ygg_token_expire_1", "3600")
	setOption(t, h.store, "ygg_token_expire_2", "86400")
	h.svc.ModuleLock = func(ctx context.Context, tx *sql.Tx) error {
		return yggdrasil.ErrModuleNotServed
	}
	if _, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password"}); !errors.Is(err, yggdrasil.ErrModuleNotServed) {
		t.Fatalf("authenticate err = %v", err)
	}
	// An existing profile reaches the business transaction and hits
	// the lock; a discovery miss returns the 204 shape beforehand.
	if _, _, err := h.svc.GetProfileByUUID(t.Context(), players.UUID3("PlayerOne"), false); !errors.Is(err, yggdrasil.ErrModuleNotServed) {
		t.Fatalf("profile err = %v", err)
	}
	// Clearing the hook restores service behavior.
	h.svc.ModuleLock = nil
	if _, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password"}); err != nil {
		t.Fatalf("authenticate after clearing lock = %v", err)
	}
}

// TestListLogsPageOrderAndSanitize checks time-descending pagination and
// the render-time parameter desensitization.
func TestListLogsPageOrderAndSanitize(t *testing.T) {
	h := fixture(t)
	for i, params := range []string{
		`{"selectedProfile":"a","accessToken":"secret"}`,
		`{"profileId":3,"password":"secret"}`,
		`not-json`,
	} {
		if _, err := h.store.DB.Exec("INSERT INTO "+h.store.Table("ygg_log")+" (action,user_id,player_id,parameters,ip,time) VALUES (?,?,?,?,?,?)", "join", 1, 1, params, "127.0.0.1", "2026-11-04 10:00:0"+string(rune('0'+i))); err != nil {
			t.Fatal(err)
		}
	}
	page1, err := h.svc.ListLogsPage(t.Context(), 2, 0)
	if err != nil || len(page1) != 2 || page1[0].Parameters != `not-json` {
		t.Fatalf("page1 = %+v %v", page1, err)
	}
	page2, err := h.svc.ListLogsPage(t.Context(), 2, 2)
	if err != nil || len(page2) != 1 {
		t.Fatalf("page2 = %+v %v", page2, err)
	}
	if got := yggdrasil.SanitizeStoredParameters(`{"selectedProfile":"a","accessToken":"secret"}`); got != `{"selectedProfile":"a"}` {
		t.Fatalf("sanitize = %s", got)
	}
	if got := yggdrasil.SanitizeStoredParameters("not-json"); got != "{}" {
		t.Fatalf("sanitize invalid = %s", got)
	}
}
