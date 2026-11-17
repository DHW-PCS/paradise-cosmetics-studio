package oauthserver

import (
	"context"
	"errors"
	"time"

	"authelia.com/provider/oauth2"
	"paradise-cosmetics-studio/internal/identity"
)

// PersonalToken is the issuance result. ID is the engine request id
// (request.GetID()), the same request_id the list/revoke paths use; it is
// deliberately not the access-token signature.
type PersonalToken struct {
	ID          string    `json:"id"`
	AccessToken string    `json:"accessToken"`
	Name        string    `json:"name"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

// IssuePersonalToken is a protected application service, not a public grant.
// It uses the engine's public RS256 strategy and authoritative access storage.
func (s *Server) IssuePersonalToken(ctx context.Context, b *identity.BrowserSession, name string, scopes []string) (*PersonalToken, error) {
	if name == "" {
		return nil, errors.New("personal token name is required")
	}
	// The issuance pins one snapshot before the transaction and consults
	// only the names it published: a scope added online is usable without a
	// restart, while the commit-ambiguity poison refuses issuance.
	lease, err := s.policy.AcquireRead(ctx)
	if err != nil {
		return nil, err
	}
	snapshot := lease.Snapshot()
	for _, scope := range scopes {
		found := scope == "*"
		for _, registered := range snapshot.Names {
			found = found || registered == scope
		}
		if !found {
			lease.Release()
			return nil, ErrScope
		}
	}
	var issued *PersonalToken
	err = s.storage.runLeased(ctx, s.cfg.Store.DB, lease, func(ctx context.Context) error {
		var id string
		if err := root(ctx).tx.QueryRowContext(ctx, "SELECT CAST(id AS CHAR) FROM "+s.cfg.Store.Table("oauth_clients")+" WHERE personal_access_client=1 AND revoked=0 ORDER BY id LIMIT 1").Scan(&id); err != nil {
			return err
		}
		client, err := s.storage.GetClient(ctx, id)
		if err != nil {
			return err
		}
		u, err := s.cfg.Identity.CheckBrowserTx(ctx, root(ctx).tx, b)
		if err != nil {
			return err
		}
		state := newSession(u.UID, b.Version)
		state.Label = name
		expiry := time.Now().Add(s.cfg.AccessLifetime)
		state.SetExpiresAt(oauth2.AccessToken, expiry)
		request := oauth2.NewAccessRequest(state)
		request.Client = client
		for _, scope := range scopes {
			request.AppendRequestedScope(scope)
			request.GrantScope(scope)
		}
		requestID := request.GetID()
		token, signature, err := s.storage.strategy.GenerateAccessToken(ctx, request)
		if err != nil {
			return err
		}
		if err = s.storage.CreateAccessTokenSession(ctx, signature, request); err != nil {
			return err
		}
		issued = &PersonalToken{ID: requestID, AccessToken: token, Name: name, ExpiresAt: expiry}
		return nil
	})
	return issued, err
}
