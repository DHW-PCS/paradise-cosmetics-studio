package oauthserver

import (
	"context"
	"errors"
	"time"

	"authelia.com/provider/oauth2"
	"blessing-skin-go/internal/identity"
)

type PersonalToken struct {
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
	for _, scope := range scopes {
		found := scope == "*"
		for _, registered := range s.cfg.Scopes {
			found = found || registered == scope
		}
		if !found {
			return nil, ErrScope
		}
	}
	var issued *PersonalToken
	err := s.storage.run(ctx, func(ctx context.Context) error {
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
		token, signature, err := s.storage.strategy.GenerateAccessToken(ctx, request)
		if err != nil {
			return err
		}
		if err = s.storage.CreateAccessTokenSession(ctx, signature, request); err != nil {
			return err
		}
		issued = &PersonalToken{AccessToken: token, Name: name, ExpiresAt: expiry}
		return nil
	})
	return issued, err
}
