// M4-03 slice B: access-only borrowed-transaction Actor adapter and the
// first-party API digest migration. Protocol library types stay in this
// package; identity only sees identity.Actor.
package oauthserver

import (
	"context"
	"database/sql"
	"errors"
	"strconv"

	"authelia.com/provider/oauth2"
	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
)

// MigrateAPIDigest adds the first-party API cookie digest to the browser
// session row (nullable, unique). The secret itself is random and never
// stored; validity follows the session row's expiry and the UID version.
// Wired by the composition root; slice-B tests call it directly.
func MigrateAPIDigest(ctx context.Context, store *database.Store) error {
	ddl := "ALTER TABLE " + store.Table("go_web_sessions") + " ADD COLUMN api_digest BINARY(32) NULL, ADD UNIQUE INDEX api_digest_unique(api_digest)"
	return store.ApplyMigration(ctx, "006_go_web_sessions_api_digest", ddl)
}

// ScopeCovers reports whether one granted scope satisfies one required
// scope. The wildcard "*" covers any requirement; Closet.ReadWrtie and
// Closet.ReadWrite are equivalent (the frozen Passport alias pair). Any
// other name is matched case-sensitively and never rewritten.
func ScopeCovers(granted []string, required string) bool {
	for _, scope := range granted {
		if scope == "*" {
			return true
		}
		if scope == required {
			return true
		}
		if (scope == "Closet.ReadWrtie" && required == "Closet.ReadWrite") || (scope == "Closet.ReadWrite" && required == "Closet.ReadWrtie") {
			return true
		}
	}
	return false
}

// scopeRequirementSatisfied reports whether granted scopes satisfy a
// requirement: every AllOf scope must be covered, and a non-empty
// AnyOf requires at least one covered scope. The empty requirement
// is satisfied without any scope check.
func scopeRequirementSatisfied(granted []string, required identity.ScopeRequirement) bool {
	for _, scope := range required.AllOf {
		if !ScopeCovers(granted, scope) {
			return false
		}
	}
	if len(required.AnyOf) == 0 {
		return true
	}
	for _, scope := range required.AnyOf {
		if ScopeCovers(granted, scope) {
			return true
		}
	}
	return false
}

// oauthActor carries the access-token proof for one business operation.
// The snapshot pins the scope facts seen during entry validation, so the
// recheck never rebuilds them from mutable state.
type oauthActor struct {
	server   *Server
	token    string
	clientID string
	uid      int64
	version  int64
	scopes   []string
	snapshot Snapshot
}

func (a *oauthActor) UID() int64       { return a.uid }
func (a *oauthActor) Domain() string   { return identity.DomainOAuth }
func (a *oauthActor) ClientID() string { return a.clientID }
func (a *oauthActor) Scopes() []string { return append([]string(nil), a.scopes...) }
func (a *oauthActor) Version() int64   { return a.version }

// PrepareTx locks the current OAuth client before any users are locked.
// The caller pre-locks the sorted user set next, then calls RecheckTx.
func (a *oauthActor) PrepareTx(ctx context.Context, tx *sql.Tx) error {
	var revoked bool
	err := tx.QueryRowContext(ctx, "SELECT revoked FROM "+a.server.cfg.Store.Table("oauth_clients")+" WHERE id=? FOR UPDATE", a.clientID).Scan(&revoked)
	if errors.Is(err, sql.ErrNoRows) || revoked {
		return ErrToken
	}
	return err
}

// RecheckTx revalidates the bound access token in the caller's transaction.
// It never begins or commits, and never calls the owned Validate path: it
// borrows the transaction, re-runs access introspection (which locks the
// version row and the current access row), and then checks that the
// revalidated proof still binds the actor's client, UID, version, and the
// required scopes. A revoked, downgraded, or client-changed token fails
// here even though entry validation passed earlier.
func (a *oauthActor) RecheckTx(ctx context.Context, tx *sql.Tx, required identity.ScopeRequirement) (*identity.User, error) {
	root := &transaction{tx: tx}
	flow := context.WithValue(ctx, transactionKey{}, root)
	flow = withSnapshot(flow, a.snapshot)
	use, request, err := a.server.provider.IntrospectToken(flow, a.token, oauth2.AccessToken, newSession(0, 0))
	if root.failed {
		return nil, errors.Join(ErrUnavailable, err)
	}
	if err != nil {
		return nil, classifyActorError(err)
	}
	if use != oauth2.AccessToken {
		return nil, ErrToken
	}
	uid, _ := strconv.ParseInt(request.GetSession().GetSubject(), 10, 64)
	if uid != a.uid || request.GetClient().GetID() != a.clientID {
		return nil, ErrToken
	}
	if uid == 0 {
		return nil, ErrToken
	}
	state, ok := request.GetSession().(*session)
	if !ok || state.Version != a.version {
		return nil, ErrToken
	}
	granted := request.GetGrantedScopes()
	if !scopeRequirementSatisfied(granted, required) {
		return nil, ErrScope
	}
	// Current user row (already locked by the caller) supplies the
	// authoritative permission and identity fields.
	var user identity.User
	err = tx.QueryRowContext(ctx, "SELECT uid,email,nickname,permission,verified,COALESCE(locale,''),is_dark_mode FROM "+a.server.cfg.Store.Table("users")+" WHERE uid=? FOR UPDATE", a.uid).Scan(&user.UID, &user.Email, &user.Nickname, &user.Permission, &user.Verified, &user.Locale, &user.DarkMode)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrToken
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// classifyActorError maps protocol failures: 5xx and SQL faults stay
// service errors (never "invalid token"), credential failures become
// ErrToken for the OAuth actor boundary.
func classifyActorError(err error) error {
	var protocol *oauth2.RFC6749Error
	if errors.As(err, &protocol) {
		if protocol.CodeField >= 500 {
			return errors.Join(ErrUnavailable, err)
		}
		return ErrToken
	}
	// Other failures (SQL faults, context errors) keep their identity so
	// callers never mistake them for an invalid credential.
	return err
}

// AuthenticateActor performs the full entry validation for one bearer
// credential in its own short transaction, confirms the token use is
// exactly access, then hands back an actor that can only be rechecked in
// another owner's transaction. Client-credentials tokens (UID 0) are
// valid OAuth client tokens but never user actors and are rejected here.
func (s *Server) AuthenticateActor(ctx context.Context, token string) (identity.Actor, error) {
	var actor *oauthActor
	lease, err := s.policy.AcquireRead(ctx)
	if err != nil {
		return nil, err
	}
	err = s.storage.runLeased(ctx, s.cfg.Store.DB, lease, func(ctx context.Context) error {
		use, request, err := s.provider.IntrospectToken(ctx, token, oauth2.AccessToken, newSession(0, 0))
		if err != nil {
			return err
		}
		if use != oauth2.AccessToken {
			return ErrToken
		}
		uid, _ := strconv.ParseInt(request.GetSession().GetSubject(), 10, 64)
		if uid == 0 {
			return ErrToken
		}
		state, ok := request.GetSession().(*session)
		if !ok {
			return ErrToken
		}
		actor = &oauthActor{
			server:   s,
			token:    token,
			clientID: request.GetClient().GetID(),
			uid:      uid,
			version:  state.Version,
			scopes:   append([]string(nil), request.GetGrantedScopes()...),
			snapshot: lease.Snapshot(),
		}
		return nil
	})
	if err != nil {
		return nil, classifyActorError(err)
	}
	if actor == nil {
		return nil, ErrToken
	}
	return actor, nil
}

// ActorAccessor lets callers that bind an actor to a concrete client or
// scope set without importing protocol types.
func (s *Server) ActorClientID(actor identity.Actor) (string, bool) {
	if a, ok := actor.(*oauthActor); ok {
		return a.clientID, true
	}
	return "", false
}
