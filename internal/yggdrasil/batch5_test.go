package yggdrasil_test

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"blessing-skin-go/internal/maintenance"
	"blessing-skin-go/internal/oauthserver"
	"blessing-skin-go/internal/players"
	"blessing-skin-go/internal/yggdrasil"
)

// TestConcurrentRefreshExactlyOneWins exercises the atomic rotation
// contract: parallel refreshes of one access token must produce
// exactly one winner; the losers must see the protocol token-invalid
// refusal, and exactly one token row must remain.
func TestConcurrentRefreshExactlyOneWins(t *testing.T) {
	h := fixture(t)
	token := authToken(t, h)
	const workers = 6
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]error, workers)
	tokens := make([]string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			res, err := h.svc.Refresh(t.Context(), yggdrasil.RefreshRequest{AccessToken: token})
			if err == nil {
				tokens[idx] = res.AccessToken
			}
			results[idx] = err
		}(i)
	}
	close(start)
	wg.Wait()
	wins := 0
	var winner string
	for i, err := range results {
		if err == nil {
			wins++
			winner = tokens[i]
			continue
		}
		if !errors.Is(err, yggdrasil.ErrTokenInvalid) {
			t.Fatalf("losing refresh %d err = %v, want token-invalid", i, err)
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent refresh winners = %d, want exactly 1", wins)
	}
	if winner == "" || winner == token {
		t.Fatal("winner must carry a rotated token")
	}
	if n := tokenCount(t, h.store, 1); n != 1 {
		t.Fatalf("token rows after concurrent refresh = %d, want 1", n)
	}
	if err := h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: winner}); err != nil {
		t.Fatalf("winning token must validate: %v", err)
	}
	if err := h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: token}); err == nil {
		t.Fatal("original token must be gone after concurrent refresh")
	}
}

// TestIssuanceOrderEvictsOldestAtLimit checks the per-UID issuance
// queue: at limit 2 the third issuance evicts the oldest token by
// issuance_order, leaving the two newest valid.
func TestIssuanceOrderEvictsOldestAtLimit(t *testing.T) {
	h := fixture(t)
	setOption(t, h.store, "ygg_token_expire_1", "3600")
	setOption(t, h.store, "ygg_token_expire_2", "86400")
	setOption(t, h.store, "ygg_tokens_limit", "2")
	var issued []string
	for i := 0; i < 3; i++ {
		res, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password"})
		if err != nil {
			t.Fatal(err)
		}
		issued = append(issued, res.AccessToken)
	}
	if n := tokenCount(t, h.store, 1); n != 2 {
		t.Fatalf("token rows at limit 2 = %d, want 2", n)
	}
	if err := h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: issued[0]}); err == nil {
		t.Fatal("oldest issuance must have been evicted")
	}
	for _, tok := range issued[1:] {
		if err := h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: tok}); err != nil {
			t.Fatalf("newer issuance must validate: %v", err)
		}
	}
	// issuance_order values of the survivors are strictly increasing.
	rows, err := h.store.DB.Query("SELECT issuance_order FROM " + h.store.Table("go_yggdrasil_tokens") + " WHERE user_uid=1 ORDER BY issuance_order")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var orders []int64
	for rows.Next() {
		var order int64
		if err := rows.Scan(&order); err != nil {
			t.Fatal(err)
		}
		orders = append(orders, order)
	}
	if len(orders) != 2 || orders[0] >= orders[1] {
		t.Fatalf("issuance orders = %v, want two increasing values", orders)
	}
}

// TestAuthVersionBumpInvalidatesYggTokenEverywhere mirrors the
// password-change identity event: the account layer bumps the UID
// auth version (internal/account calls RevokeUID on password change),
// and every Yggdrasil credential check must then reject the old token
// while a fresh authenticate issues a working one.
func TestAuthVersionBumpInvalidatesYggTokenEverywhere(t *testing.T) {
	h := fixture(t)
	token := authToken(t, h)
	dashed := yggdrasil.MustDashed(players.UUID3("PlayerOne"))
	if err := h.svc.JoinServer(t.Context(), yggdrasil.JoinServerRequest{AccessToken: token, SelectedProfile: dashed, ServerID: "srv-before", ClientIP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	err := h.store.Transaction(t.Context(), func(tx *sql.Tx) error {
		return h.id.RevokeUID(t.Context(), tx, 1)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: token}); err == nil {
		t.Fatal("validate must reject a token from before the version bump")
	}
	if _, err := h.svc.Refresh(t.Context(), yggdrasil.RefreshRequest{AccessToken: token}); err == nil {
		t.Fatal("refresh must reject a token from before the version bump")
	}
	if err := h.svc.JoinServer(t.Context(), yggdrasil.JoinServerRequest{AccessToken: token, SelectedProfile: dashed, ServerID: "srv-after", ClientIP: "127.0.0.1"}); err == nil {
		t.Fatal("join must reject a token from before the version bump")
	}
	if _, err := h.svc.VerifyBearerToken(t.Context(), token); err == nil {
		t.Fatal("Bearer verification must reject a token from before the version bump")
	}
	fresh, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: fresh.AccessToken}); err != nil {
		t.Fatalf("fresh token after the bump must validate: %v", err)
	}
}

// TestRefreshSelectedProfileSemantics covers the refresh-time
// selectedProfile object contract: an unknown name is a 400 refusal, a
// foreign player's profile is a 403 owner refusal, a wrong id for an
// own name is a 400 not-matched refusal, and none of these consume the
// old token. Passing the bound selection succeeds and retains it.
func TestRefreshSelectedProfileSemantics(t *testing.T) {
	h := fixture(t)
	token := authToken(t, h)
	own := yggdrasil.MustDashed(players.UUID3("PlayerOne"))
	// An unbound token (uid 2 has no roles, so nothing is auto-selected)
	// asking for another user's profile reaches the ownership check: 403.
	unbound, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "admin@example.invalid", Password: "original-password"})
	if err != nil {
		t.Fatal(err)
	}
	foreignSel := yggdrasil.SelectedProfileInput{ID: own, Name: "PlayerOne"}
	if _, err := h.svc.Refresh(t.Context(), yggdrasil.RefreshRequest{AccessToken: unbound.AccessToken, SelectedProfile: &foreignSel}); !errors.Is(err, yggdrasil.ErrPlayerOwner) {
		t.Fatalf("unbound foreign refresh err = %v, want owner refusal", err)
	}
	if err := h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: unbound.AccessToken}); err != nil {
		t.Fatalf("failed owner refresh must not consume the token: %v", err)
	}
	// A second player owned by uid 2, with its own UUID binding.
	foreignHex := players.UUID3("ForeignRole")
	if _, err := h.store.DB.Exec("INSERT INTO " + h.store.Table("players") + " (uid,name) VALUES (2,'ForeignRole')"); err != nil {
		t.Fatal(err)
	}
	var foreignPID int64
	if err := h.store.DB.QueryRow("SELECT pid FROM " + h.store.Table("players") + " WHERE name='ForeignRole'").Scan(&foreignPID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.DB.Exec("INSERT INTO "+h.store.Table("uuid")+" (name,uuid) VALUES (?,?)", "ForeignRole", foreignHex); err != nil {
		t.Fatal(err)
	}
	var foreignRowID int64
	if err := h.store.DB.QueryRow("SELECT id FROM " + h.store.Table("uuid") + " WHERE name='ForeignRole' ORDER BY id LIMIT 1").Scan(&foreignRowID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.DB.Exec("INSERT INTO "+h.store.Table("go_uuid_bindings")+" (pid,uuid_row_id,uuid,version) VALUES (?,?,?,1)", foreignPID, foreignRowID, foreignHex); err != nil {
		t.Fatal(err)
	}
	foreign := yggdrasil.MustDashed(foreignHex)
	cases := []struct {
		name string
		in   yggdrasil.SelectedProfileInput
		want error
	}{
		{"unknown name", yggdrasil.SelectedProfileInput{ID: own, Name: "GhostRole"}, yggdrasil.ErrPlayerNotExisted},
		// Legacy refresh checks the bound profileId before ownership: a
		// bound token asking for a different id is a 400 not-matched, not 403.
		{"foreign id on bound token", yggdrasil.SelectedProfileInput{ID: foreign, Name: "ForeignRole"}, yggdrasil.ErrPlayerNotMatched},
		{"own name wrong id", yggdrasil.SelectedProfileInput{ID: "00000000-0000-0000-0000-000000000000", Name: "PlayerOne"}, yggdrasil.ErrPlayerNotMatched},
	}
	for _, tc := range cases {
		in := tc.in
		if _, err := h.svc.Refresh(t.Context(), yggdrasil.RefreshRequest{AccessToken: token, SelectedProfile: &in}); !errors.Is(err, tc.want) {
			t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
		if err := h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: token}); err != nil {
			t.Fatalf("%s: failed refresh must not consume the old token: %v", tc.name, err)
		}
	}
	sel := yggdrasil.SelectedProfileInput{ID: own, Name: "PlayerOne"}
	refreshed, err := h.svc.Refresh(t.Context(), yggdrasil.RefreshRequest{AccessToken: token, SelectedProfile: &sel})
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.SelectedProfile == nil || refreshed.SelectedProfile.ID != players.UUID3("PlayerOne") || refreshed.SelectedProfile.Name != "PlayerOne" {
		t.Fatalf("bound selection must be retained: %+v", refreshed.SelectedProfile)
	}
	if err := h.svc.JoinServer(t.Context(), yggdrasil.JoinServerRequest{AccessToken: refreshed.AccessToken, SelectedProfile: own, ServerID: "srv-refresh", ClientIP: "127.0.0.1"}); err != nil {
		t.Fatalf("join with the refreshed token must succeed: %v", err)
	}
}

// TestVerboseLogWriteGate checks the verbose switch at the storage
// layer: with verbose off an authenticate writes no ygg_log row; with
// verbose on it writes one allowlisted row that carries neither the
// access token nor the password.
func TestVerboseLogWriteGate(t *testing.T) {
	h := fixture(t)
	setOption(t, h.store, "ygg_token_expire_1", "3600")
	setOption(t, h.store, "ygg_token_expire_2", "86400")
	logCount := func() int {
		var n int
		if err := h.store.DB.QueryRow("SELECT COUNT(*) FROM " + h.store.Table("ygg_log")).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if _, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password"}); err != nil {
		t.Fatal(err)
	}
	if n := logCount(); n != 0 {
		t.Fatalf("verbose off wrote %d ygg_log rows, want 0", n)
	}
	verboseSvc := yggdrasil.New(h.store, h.id, nil, testKey, true, func() time.Time { return h.now })
	res, err := verboseSvc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password"})
	if err != nil {
		t.Fatal(err)
	}
	if n := logCount(); n != 1 {
		t.Fatalf("verbose on wrote %d ygg_log rows, want 1", n)
	}
	var parameters string
	if err := h.store.DB.QueryRow("SELECT parameters FROM " + h.store.Table("ygg_log") + " WHERE action='authenticate'").Scan(&parameters); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(parameters, "clientTokenPresent") {
		t.Fatalf("verbose log parameters missing allowlisted key: %s", parameters)
	}
	if strings.Contains(parameters, res.AccessToken) || strings.Contains(parameters, "original-password") {
		t.Fatalf("verbose log leaked a secret: %s", parameters)
	}
}

// TestMigrateIdempotentPreservesTokensAndSchema checks that rerunning
// the offline migration neither fails nor drops live token state, and
// that the maintenance schema gate then passes.
func TestMigrateIdempotentPreservesTokensAndSchema(t *testing.T) {
	h := fixture(t)
	token := authToken(t, h)
	for i := 0; i < 2; i++ {
		if err := yggdrasil.Migrate(t.Context(), h.store); err != nil {
			t.Fatalf("migrate rerun %d: %v", i, err)
		}
	}
	if n := tokenCount(t, h.store, 1); n != 1 {
		t.Fatalf("rerun migrate dropped tokens: %d rows", n)
	}
	if err := h.svc.Validate(t.Context(), yggdrasil.ValidateRequest{AccessToken: token}); err != nil {
		t.Fatalf("token must still validate after migrate rerun: %v", err)
	}
	if err := oauthserver.Migrate(t.Context(), h.store); err != nil {
		t.Fatal(err)
	}
	if err := oauthserver.MigrateConsents(t.Context(), h.store); err != nil {
		t.Fatal(err)
	}
	if err := oauthserver.MigrateAPIDigest(t.Context(), h.store); err != nil {
		t.Fatal(err)
	}
	if err := maintenance.CheckSchema(t.Context(), h.store); err != nil {
		t.Fatalf("CheckSchema after migrate rerun: %v", err)
	}
}

// TestHasJoinedRepeatReadAndTimestampMillis checks that repeated
// hasJoined reads stay successful with identical signed property
// values, and that the textures payload timestamp is in milliseconds.
func TestHasJoinedRepeatReadAndTimestampMillis(t *testing.T) {
	h := fixture(t)
	token := authToken(t, h)
	setOption(t, h.store, "ygg_private_key", genKey(t, 2048))
	setOption(t, h.store, "site_url", "https://skin.example.invalid")
	dashed := yggdrasil.MustDashed(players.UUID3("PlayerOne"))
	if err := h.svc.JoinServer(t.Context(), yggdrasil.JoinServerRequest{AccessToken: token, SelectedProfile: dashed, ServerID: "srv-repeat", ClientIP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	ip := "127.0.0.1"
	first, ok, err := h.svc.HasJoinedServer(t.Context(), yggdrasil.HasJoinedServerRequest{Username: "PlayerOne", ServerID: "srv-repeat", IP: &ip})
	if err != nil || !ok || first == nil {
		t.Fatalf("first hasJoined = %v %v %v", first, ok, err)
	}
	second, ok, err := h.svc.HasJoinedServer(t.Context(), yggdrasil.HasJoinedServerRequest{Username: "PlayerOne", ServerID: "srv-repeat", IP: &ip})
	if err != nil || !ok || second == nil {
		t.Fatalf("repeat hasJoined = %v %v %v", second, ok, err)
	}
	if len(first.Properties) != 2 || len(second.Properties) != 2 || first.Properties[0].Value != second.Properties[0].Value {
		t.Fatal("repeat hasJoined must return identical property values")
	}
	raw, err := base64.StdEncoding.DecodeString(first.Properties[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Timestamp float64 `json:"timestamp"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	wantMs := float64(h.now.UnixMilli())
	if payload.Timestamp < wantMs-60000 || payload.Timestamp > wantMs+60000 {
		t.Fatalf("textures timestamp %v is not milliseconds around %v", payload.Timestamp, wantMs)
	}
}
