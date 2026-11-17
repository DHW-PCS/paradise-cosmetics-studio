// Package identity actor boundary for M4-03 core APIs (slice B).
//
// An Actor is an internal application identity, never a forged
// BrowserSession. The OAuth library types stay private to the oauthserver
// package: the actor proof here is an opaque Actor interface, and only the
// oauthserver package implements the OAuth flavor.
package identity

import (
	"context"
	"database/sql"
	"sort"

	"paradise-cosmetics-studio/internal/database"
)

// Auth domains identify how the actor was authenticated. Callers must not
// treat the domain as a permission grant; RecheckTx always returns the
// current user row from the business transaction.
const (
	DomainBrowser   = "browser"
	DomainOAuth     = "oauth"
	DomainAPICookie = "api-cookie"
)

// ScopeRequirement is the opaque scope requirement handed to
// RecheckTx. It is interpreted only by the OAuth adapter: every
// AllOf scope must be covered, and a non-empty AnyOf requires at
// least one covered scope. The empty requirement checks no scope.
type ScopeRequirement struct {
	AllOf []string
	AnyOf []string
}

// Actor is the internal, non-HTTP credential for one business operation.
// UID is only a lock plan: it never proves the current permission.
type Actor interface {
	// UID is the claimed user. Callers sort and pre-lock all
	// participant users before RecheckTx; the UID alone is not a
	// current authorization.
	UID() int64
	// Domain returns DomainBrowser, DomainOAuth, or DomainAPICookie.
	Domain() string
	// PrepareTx locks the authentication infrastructure row (for
	// OAuth the current client) before any users are locked. It
	// borrows the owner's transaction and never commits.
	PrepareTx(ctx context.Context, tx *sql.Tx) error
	// RecheckTx locks the current credential state (version and the
	// current access row for OAuth) using the same transaction and
	// returns the current user. required is opaque to this package;
	// the OAuth adapter interprets it (exact-scope matching with the
	// Closet.ReadWrtie alias). Browser and API-cookie actors ignore it.
	RecheckTx(ctx context.Context, tx *sql.Tx, required ScopeRequirement) (*User, error)
}

// ActorPreparer is the prepare half of Actor, for callers that only need
// to order locks.
type ActorPreparer interface {
	PrepareTx(ctx context.Context, tx *sql.Tx) error
}

// ActorRechecker is the recheck half of Actor.
type ActorRechecker interface {
	RecheckTx(ctx context.Context, tx *sql.Tx, required ScopeRequirement) (*User, error)
}

// browserActor wraps one verified BrowserSession. The existing public
// browser entry points keep their signatures; core commands may take the
// actor instead so browser and OAuth share one business transaction.
type browserActor struct {
	svc     *Service
	session *BrowserSession
}

func (a *browserActor) UID() int64     { return a.session.User.UID }
func (a *browserActor) Domain() string { return DomainBrowser }

// PrepareTx adds no client lock for browser actors (integration-design §2).
func (a *browserActor) PrepareTx(context.Context, *sql.Tx) error { return nil }

// RecheckTx reuses CheckBrowserTx, which locks users, UID version, and
// the browser session row in the owner's transaction.
func (a *browserActor) RecheckTx(ctx context.Context, tx *sql.Tx, _ ScopeRequirement) (*User, error) {
	return a.svc.CheckBrowserTx(ctx, tx, a.session)
}

// NewBrowserActor returns the actor for an authenticated browser session.
// The session must already carry a user; anonymous sessions are not actors.
func (s *Service) NewBrowserActor(b *BrowserSession) (Actor, error) {
	if b == nil || b.User == nil {
		return nil, ErrSession
	}
	return &browserActor{svc: s, session: b}, nil
}

type apiCookieActor struct {
	svc   *Service
	proof apiCookieProof
}

func (a *apiCookieActor) UID() int64     { return a.proof.uid }
func (a *apiCookieActor) Domain() string { return DomainAPICookie }

func (a *apiCookieActor) PrepareTx(context.Context, *sql.Tx) error { return nil }

func (a *apiCookieActor) RecheckTx(ctx context.Context, tx *sql.Tx, _ ScopeRequirement) (*User, error) {
	current, err := a.svc.checkAPICookieTx(ctx, tx, &a.proof)
	if err != nil {
		return nil, err
	}
	return current.User, nil
}

// NewAPICookieActor takes only a result from ValidateAPI. Its private
// API-cookie proof is distinct from the raw web token used by BrowserActor.
func (s *Service) NewAPICookieActor(validatedSession *BrowserSession) (Actor, error) {
	if validatedSession == nil || validatedSession.apiProof == nil {
		return nil, ErrSession
	}
	return &apiCookieActor{svc: s, proof: *validatedSession.apiProof}, nil
}

// LockUsersTx pre-locks every participant users row in ascending UID
// order. Callers form the full participant set first (actor/owner/target
// UIDs), then call this once: a smaller UID discovered later must roll
// back instead of being locked out of order. Each row is locked with
// SELECT ... FOR UPDATE (a current read). A missing row reports ErrStale.
func (s *Service) LockUsersTx(ctx context.Context, tx *sql.Tx, uids []int64) error {
	return LockUsersTx(ctx, tx, s.Store, uids)
}

// LockUsersTx pre-locks participant users using the same ascending,
// deduplicated current-read and ErrStale rules as Service.LockUsersTx.
func LockUsersTx(ctx context.Context, tx *sql.Tx, store *database.Store, uids []int64) error {
	seen := make(map[int64]bool, len(uids))
	ordered := make([]int64, 0, len(uids))
	for _, uid := range uids {
		if uid == 0 || seen[uid] {
			continue
		}
		seen[uid] = true
		ordered = append(ordered, uid)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	for _, uid := range ordered {
		var locked int64
		err := tx.QueryRowContext(ctx, "SELECT uid FROM "+store.Table("users")+" WHERE uid=? FOR UPDATE", uid).Scan(&locked)
		if err == sql.ErrNoRows {
			return ErrStale
		}
		if err != nil {
			return err
		}
		if locked != uid {
			return ErrStale
		}
	}
	return nil
}
