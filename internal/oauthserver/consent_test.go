// Slice-B focused checks: OAuth Actor two-phase recheck, pending consent
// single-slot/single-consumption, and the API digest migration. Uses the
// real database and the existing authorize/exchange helpers.
package oauthserver

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"paradise-cosmetics-studio/internal/identity"
)

func sliceFixture(t *testing.T) *Server {
	t.Helper()
	s := fixture(t)
	if err := MigrateConsents(t.Context(), s.cfg.Store); err != nil {
		t.Fatal(err)
	}
	if err := MigrateAPIDigest(t.Context(), s.cfg.Store); err != nil {
		t.Fatal(err)
	}
	return s
}

func consentAuthorizeURL(t *testing.T, scope string) *http.Request {
	t.Helper()
	q := url.Values{"response_type": {"code"}, "client_id": {"1"}, "redirect_uri": {"https://client.example.invalid/callback"}, "state": {"synthetic-state"}, "scope": {scope}}
	sum := sha256.Sum256([]byte(verifier))
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	q.Set("code_challenge_method", "S256")
	return httptest.NewRequest("GET", "https://skin.example.invalid/oauth/authorize?"+q.Encode(), nil)
}

func TestScopeRequirementSemantics(t *testing.T) {
	if !ScopeCovers([]string{"*"}, "Anything.Read") {
		t.Fatal("wildcard did not cover an arbitrary scope")
	}
	if !ScopeCovers([]string{"Closet.ReadWrtie"}, "Closet.ReadWrite") {
		t.Fatal("Closet.ReadWrtie did not cover Closet.ReadWrite")
	}
	if !ScopeCovers([]string{"Closet.ReadWrite"}, "Closet.ReadWrtie") {
		t.Fatal("Closet.ReadWrite did not cover Closet.ReadWrtie")
	}
	if ScopeCovers([]string{"Closet.Read"}, "Closet.ReadWrite") {
		t.Fatal("unrelated Closet scope was generalized")
	}
	if ScopeCovers([]string{"closet.readwrite"}, "Closet.ReadWrite") {
		t.Fatal("scope matching became case-insensitive")
	}
	granted := []string{"User.Read", "Player.Read"}
	cases := []struct {
		name     string
		required identity.ScopeRequirement
		want     bool
	}{
		{"empty", identity.ScopeRequirement{}, true},
		{"all-of satisfied", identity.ScopeRequirement{AllOf: []string{"User.Read", "Player.Read"}}, true},
		{"all-of missing one", identity.ScopeRequirement{AllOf: []string{"User.Read", "Player.ReadWrite"}}, false},
		{"any-of one satisfied", identity.ScopeRequirement{AnyOf: []string{"Player.ReadWrite", "User.Read"}}, true},
		{"any-of none satisfied", identity.ScopeRequirement{AnyOf: []string{"Player.ReadWrite", "Closet.ReadWrite"}}, false},
		{"all-of and any-of satisfied", identity.ScopeRequirement{AllOf: []string{"User.Read"}, AnyOf: []string{"Player.ReadWrite", "Player.Read"}}, true},
		{"all-of satisfied any-of none", identity.ScopeRequirement{AllOf: []string{"User.Read"}, AnyOf: []string{"Player.ReadWrite"}}, false},
		{"all-of missing any-of satisfied", identity.ScopeRequirement{AllOf: []string{"User.Read", "Player.ReadWrite"}, AnyOf: []string{"Player.Read"}}, false},
	}
	for _, tc := range cases {
		if got := scopeRequirementSatisfied(granted, tc.required); got != tc.want {
			t.Fatalf("%s: scopeRequirementSatisfied = %v, want %v", tc.name, got, tc.want)
		}
	}
	if !scopeRequirementSatisfied([]string{"*"}, identity.ScopeRequirement{AllOf: []string{"User.Read"}, AnyOf: []string{"Player.ReadWrite"}}) {
		t.Fatal("wildcard did not satisfy a combined requirement")
	}
	if !scopeRequirementSatisfied([]string{"Closet.ReadWrtie"}, identity.ScopeRequirement{AnyOf: []string{"Closet.ReadWrite"}}) {
		t.Fatal("alias did not satisfy an any-of requirement")
	}
}

func TestActorRecheckScopeRequirementAnyAll(t *testing.T) {
	s := sliceFixture(t)
	status, data := exchange(s, url.Values{"grant_type": {"password"}, "client_id": {"3"}, "client_secret": {"password-secret"}, "username": {"user@example.invalid"}, "password": {"original-password"}})
	if status != 200 {
		t.Fatalf("password grant status=%d error=%v", status, data["error"])
	}
	actor, err := s.AuthenticateActor(t.Context(), data["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	recheck := func(required identity.ScopeRequirement) (*identity.User, error) {
		var user *identity.User
		err := s.cfg.Store.Transaction(t.Context(), func(tx *sql.Tx) error {
			if err := actor.PrepareTx(t.Context(), tx); err != nil {
				return err
			}
			if err := s.cfg.Identity.LockUsersTx(t.Context(), tx, []int64{1}); err != nil {
				return err
			}
			u, err := actor.RecheckTx(t.Context(), tx, required)
			if err != nil {
				return err
			}
			user = u
			return nil
		})
		return user, err
	}
	if u, err := recheck(identity.ScopeRequirement{AnyOf: []string{"Player.Read", "User.Read"}}); err != nil || u.UID != 1 {
		t.Fatalf("any-of with one granted scope: user=%v err=%v", u, err)
	}
	if _, err := recheck(identity.ScopeRequirement{AnyOf: []string{"Player.Read", "Player.ReadWrite"}}); !errors.Is(err, ErrScope) {
		t.Fatalf("any-of with no granted scope classified as: %v", err)
	}
	if _, err := recheck(identity.ScopeRequirement{AllOf: []string{"User.Read", "Player.Read"}}); !errors.Is(err, ErrScope) {
		t.Fatalf("all-of with a missing scope classified as: %v", err)
	}
	if _, err := recheck(identity.ScopeRequirement{AllOf: []string{"User.Read"}, AnyOf: []string{"Player.Read", "Player.ReadWrite"}}); !errors.Is(err, ErrScope) {
		t.Fatalf("all-of satisfied but any-of empty classified as: %v", err)
	}
	if u, err := recheck(identity.ScopeRequirement{AllOf: []string{"User.Read"}, AnyOf: []string{"Player.ReadWrite", "User.Read"}}); err != nil || u.UID != 1 {
		t.Fatalf("combined requirement: user=%v err=%v", u, err)
	}
	if u, err := recheck(identity.ScopeRequirement{}); err != nil || u.UID != 1 {
		t.Fatalf("empty requirement: user=%v err=%v", u, err)
	}
}

func TestActorRecheckReturnsCurrentUserAfterSeparateTxDemotion(t *testing.T) {
	s := sliceFixture(t)
	// The fixture admin (uid 2) starts at permission 2. The business
	// transaction pins a pre-demotion plain-SELECT snapshot, a
	// separate transaction then demotes the account and commits, and
	// recheck in the same business transaction must still return the
	// current row via its FOR UPDATE reads, not the pinned snapshot.
	status, data := exchange(s, url.Values{"grant_type": {"password"}, "client_id": {"3"}, "client_secret": {"password-secret"}, "username": {"admin@example.invalid"}, "password": {"original-password"}})
	if status != 200 {
		t.Fatalf("password grant status=%d error=%v", status, data["error"])
	}
	actor, err := s.AuthenticateActor(t.Context(), data["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if actor.UID() != 2 {
		t.Fatalf("actor uid=%d, want 2", actor.UID())
	}
	// Open the business transaction first and take a plain (snapshot)
	// read of the current row: under REPEATABLE READ this pins the
	// pre-demotion permission/verified for plain SELECTs in this
	// transaction. Only a current read (FOR UPDATE) sees the demotion
	// committed by the separate transaction below.
	mainTx, err := s.cfg.Store.DB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer mainTx.Rollback()
	var snapshotPermission int
	var snapshotVerified bool
	if err = mainTx.QueryRowContext(t.Context(), "SELECT permission,verified FROM "+s.cfg.Store.Table("users")+" WHERE uid=2").Scan(&snapshotPermission, &snapshotVerified); err != nil {
		t.Fatal(err)
	}
	if snapshotPermission != 2 || !snapshotVerified {
		t.Fatalf("snapshot before demotion = permission %d verified %v, want 2/true", snapshotPermission, snapshotVerified)
	}
	err = s.cfg.Store.Transaction(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), "UPDATE "+s.cfg.Store.Table("users")+" SET permission=0, verified=0 WHERE uid=2")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = actor.PrepareTx(t.Context(), mainTx); err != nil {
		t.Fatal(err)
	}
	if err = s.cfg.Identity.LockUsersTx(t.Context(), mainTx, []int64{2}); err != nil {
		t.Fatal(err)
	}
	got, err := actor.RecheckTx(t.Context(), mainTx, identity.ScopeRequirement{AllOf: []string{"User.Read"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = mainTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got.UID != 2 || got.Permission != 0 || got.Verified {
		t.Fatalf("recheck returned stale user after demotion: %+v", got)
	}
}

func TestActorRecheckUsesBorrowedTxAndRejectsRevoked(t *testing.T) {
	s := sliceFixture(t)
	// Password grant gives a real access token (grant_type=password).
	status, data := exchange(s, url.Values{"grant_type": {"password"}, "client_id": {"3"}, "client_secret": {"password-secret"}, "username": {"user@example.invalid"}, "password": {"original-password"}})
	// fixtureConfig default scopes may exclude details; success helper:
	if status != 200 {
		t.Fatalf("password grant status=%d error=%v", status, data["error"])
	}
	token := data["access_token"].(string)

	actor, err := s.AuthenticateActor(t.Context(), token)
	if err != nil {
		t.Fatal(err)
	}
	if actor.UID() != 1 || actor.Domain() != identity.DomainOAuth {
		t.Fatalf("actor identity = %d/%q", actor.UID(), actor.Domain())
	}
	// Happy path: PrepareTx -> sorted users pre-lock -> RecheckTx.
	err = s.cfg.Store.Transaction(t.Context(), func(tx *sql.Tx) error {
		if err = actor.PrepareTx(t.Context(), tx); err != nil {
			return err
		}
		if err = s.cfg.Identity.LockUsersTx(t.Context(), tx, []int64{2, 1}); err != nil {
			return err
		}
		u, err := actor.RecheckTx(t.Context(), tx, identity.ScopeRequirement{AllOf: []string{"User.Read"}})
		if err != nil {
			return err
		}
		if u.UID != 1 || u.Permission != 0 {
			t.Fatalf("rechecked user = %+v", u)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Scope failure is distinct from credential failure.
	err = s.cfg.Store.Transaction(t.Context(), func(tx *sql.Tx) error {
		if err = actor.PrepareTx(t.Context(), tx); err != nil {
			return err
		}
		_, err = actor.RecheckTx(t.Context(), tx, identity.ScopeRequirement{AllOf: []string{"Player.ReadWrite"}})
		return err
	})
	if !errors.Is(err, ErrScope) {
		t.Fatalf("missing scope classified as: %v", err)
	}
	// Revoke the token family through its own client (client 3 issued the
	// password grant): entry passes once, recheck must fail after refresh.
	refreshTok, _ := data["refresh_token"].(string)
	refreshForm3 := url.Values{"grant_type": {"refresh_token"}, "client_id": {"3"}, "client_secret": {"password-secret"}, "refresh_token": {refreshTok}}
	rotStatus, rotData := exchange(s, refreshForm3)
	success(t, rotStatus, rotData)
	err = s.cfg.Store.Transaction(t.Context(), func(tx *sql.Tx) error {
		if err = actor.PrepareTx(t.Context(), tx); err != nil {
			return err
		}
		_, err = actor.RecheckTx(t.Context(), tx, identity.ScopeRequirement{})
		return err
	})
	if !errors.Is(err, ErrToken) {
		t.Fatalf("revoked actor rechecked: %v", err)
	}
}

func TestActorRecheckSQLFaultReturnsUnavailableAndRollsBack(t *testing.T) {
	s := sliceFixture(t)
	status, data := exchange(s, url.Values{"grant_type": {"password"}, "client_id": {"3"}, "client_secret": {"password-secret"}, "username": {"user@example.invalid"}, "password": {"original-password"}})
	if status != 200 {
		t.Fatalf("password grant status=%d error=%v", status, data["error"])
	}
	actor, err := s.AuthenticateActor(t.Context(), data["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var originalNickname string
	if err = s.cfg.Store.DB.QueryRowContext(t.Context(), "SELECT nickname FROM "+s.cfg.Store.Table("users")+" WHERE uid=?", actor.UID()).Scan(&originalNickname); err != nil {
		t.Fatal(err)
	}
	// DDL is outside the business transaction so its implicit commit
	// cannot commit the business write. This database is fixture-owned.
	if _, err = s.cfg.Store.DB.ExecContext(t.Context(), "DROP TABLE "+s.cfg.Store.Table("go_oauth_access")); err != nil {
		t.Fatal(err)
	}
	var user *identity.User
	err = s.cfg.Store.Transaction(t.Context(), func(tx *sql.Tx) error {
		if err := actor.PrepareTx(t.Context(), tx); err != nil {
			return err
		}
		if err := identity.LockUsersTx(t.Context(), tx, s.cfg.Store, []int64{actor.UID()}); err != nil {
			return err
		}
		if _, err := tx.ExecContext(t.Context(), "UPDATE "+s.cfg.Store.Table("users")+" SET nickname=? WHERE uid=?", "Uncommitted Actor change", actor.UID()); err != nil {
			return err
		}
		var err error
		user, err = actor.RecheckTx(t.Context(), tx, identity.ScopeRequirement{})
		return err
	})
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrToken) {
		t.Fatalf("storage fault must be unavailable, not invalid token: %v", err)
	}
	if user != nil {
		t.Fatal("storage fault returned an authorized user")
	}
	var nickname string
	if err = s.cfg.Store.DB.QueryRowContext(t.Context(), "SELECT nickname FROM "+s.cfg.Store.Table("users")+" WHERE uid=?", actor.UID()).Scan(&nickname); err != nil {
		t.Fatal(err)
	}
	if nickname != originalNickname {
		t.Fatal("business write survived rollback after recheck storage fault")
	}
}

func TestActorRejectsRefreshAndClientCredentials(t *testing.T) {
	s := sliceFixture(t)
	status, data := exchange(s, codeForm(authorize(t, s, true)))
	success(t, status, data)
	// A refresh bearer is a real credential but the wrong use for actors.
	if _, err := s.AuthenticateActor(t.Context(), data["refresh_token"].(string)); !errors.Is(err, ErrToken) {
		t.Fatalf("refresh bearer became actor: %v", err)
	}
	// Client credentials (UID 0) are valid OAuth tokens, never user actors.
	creds := url.Values{"grant_type": {"client_credentials"}, "client_id": {"3"}, "client_secret": {"password-secret"}}
	status, credData := exchange(s, creds)
	success(t, status, credData)
	if _, err := s.AuthenticateActor(t.Context(), credData["access_token"].(string)); !errors.Is(err, ErrToken) {
		t.Fatalf("client-credentials became user actor: %v", err)
	}
	// A mere malformed bearer is a credential error, not a service error.
	if _, err := s.AuthenticateActor(t.Context(), "not-a-token"); !errors.Is(err, ErrToken) {
		t.Fatalf("malformed bearer classified as: %v", err)
	}
}

func TestActorRecheckDetectsDowngradeAndClientChange(t *testing.T) {
	s := sliceFixture(t)
	status, data := exchange(s, codeForm(authorize(t, s, true)))
	success(t, status, data)
	actor, err := s.AuthenticateActor(t.Context(), data["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	// Permission downgrade to banned after entry validation.
	if _, err = s.cfg.Store.DB.Exec("UPDATE " + s.cfg.Store.Table("users") + " SET permission=-1 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	err = s.cfg.Store.Transaction(t.Context(), func(tx *sql.Tx) error {
		if err = actor.PrepareTx(t.Context(), tx); err != nil {
			return err
		}
		_, err = actor.RecheckTx(t.Context(), tx, identity.ScopeRequirement{})
		return err
	})
	if !errors.Is(err, ErrToken) {
		t.Fatalf("downgraded actor rechecked: %v", err)
	}
	if _, err = s.cfg.Store.DB.Exec("UPDATE " + s.cfg.Store.Table("users") + " SET permission=0 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	// Client revoked: PrepareTx refuses before users are locked.
	if _, err = s.cfg.Store.DB.Exec("UPDATE " + s.cfg.Store.Table("oauth_clients") + " SET revoked=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	err = s.cfg.Store.Transaction(t.Context(), func(tx *sql.Tx) error {
		return actor.PrepareTx(t.Context(), tx)
	})
	if !errors.Is(err, ErrToken) {
		t.Fatalf("revoked client prepared: %v", err)
	}
}

func TestPendingConsentSingleSlotSingleConsumption(t *testing.T) {
	s := sliceFixture(t)
	browser, err := s.cfg.Identity.Login(t.Context(), "user@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	// First GET stages; second GET from the same session replaces it.
	first, err := s.ConsentShow(t.Context(), consentAuthorizeURL(t, "Player.Read"), browser)
	if err != nil {
		t.Fatal(err)
	}
	if first.AuthToken == "" {
		t.Fatal("expected a pending consent page")
	}
	second, err := s.ConsentShow(t.Context(), consentAuthorizeURL(t, "Player.Read"), browser)
	if err != nil {
		t.Fatal(err)
	}
	if second.AuthToken == first.AuthToken || second.AuthToken == "" {
		t.Fatal("second GET did not rotate the pending slot")
	}
	if _, err = s.ConsentApprove(t.Context(), browser, first.AuthToken); !errors.Is(err, ErrConsent) {
		t.Fatalf("replaced pending approved: %v", err)
	}
	redirect, err := s.ConsentApprove(t.Context(), browser, second.AuthToken)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(redirect, "code=") || !strings.Contains(redirect, "state=synthetic-state") {
		t.Fatalf("approve redirect = %q", redirect)
	}
	if _, err = s.ConsentApprove(t.Context(), browser, second.AuthToken); !errors.Is(err, ErrConsent) {
		t.Fatalf("pending approved twice: %v", err)
	}
	// Deny consumes as well and preserves state.
	third, err := s.ConsentShow(t.Context(), consentAuthorizeURL(t, "Player.Read"), browser)
	if err != nil {
		t.Fatal(err)
	}
	denyRedirect, err := s.ConsentDeny(t.Context(), browser, third.AuthToken)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(denyRedirect, "error=access_denied") || !strings.Contains(denyRedirect, "state=synthetic-state") {
		t.Fatalf("deny redirect = %q", denyRedirect)
	}
	if _, err = s.ConsentApprove(t.Context(), browser, third.AuthToken); !errors.Is(err, ErrConsent) {
		t.Fatalf("denied pending approved: %v", err)
	}
}

func TestPendingConsentCrossSessionAndDisplayDrift(t *testing.T) {
	s := sliceFixture(t)
	browser, err := s.cfg.Identity.Login(t.Context(), "user@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.cfg.Identity.Login(t.Context(), "user@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	view, err := s.ConsentShow(t.Context(), consentAuthorizeURL(t, "Player.Read"), browser)
	if err != nil {
		t.Fatal(err)
	}
	// Another session cannot approve this pending request.
	if _, err = s.ConsentApprove(t.Context(), other, view.AuthToken); !errors.Is(err, ErrConsent) {
		t.Fatalf("cross-session approve: %v", err)
	}
	// Changing the displayed description after GET forces a fresh page.
	if _, err = s.cfg.Store.DB.Exec("INSERT INTO " + s.cfg.Store.Table("scopes") + " (name,description) VALUES ('Player.Read','changed display')"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ConsentApprove(t.Context(), browser, view.AuthToken); !errors.Is(err, ErrConsentStale) {
		t.Fatalf("drifted display approved: %v", err)
	}
	if _, err = s.cfg.Store.DB.Exec("DELETE FROM " + s.cfg.Store.Table("scopes") + " WHERE name='Player.Read'"); err != nil {
		t.Fatal(err)
	}
	// Fresh GET captures the current display again and approves.
	fresh, err := s.ConsentShow(t.Context(), consentAuthorizeURL(t, "Player.Read"), browser)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ConsentApprove(t.Context(), browser, fresh.AuthToken); err != nil {
		t.Fatal(err)
	}
}
