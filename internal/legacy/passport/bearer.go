package passport

import (
	"context"
	"errors"
	"strconv"
)

// ErrInvalidToken covers every reason the resource server rejects a bearer
// token; the HTTP layer maps it to 401.
var ErrInvalidToken = errors.New("passport: invalid access token")

// Identity is the validated bearer context.
type Identity struct {
	UID      int64
	ClientID string
	Scopes   []string
	TokenID  string
}

// ValidateAccess mirrors BearerTokenValidator plus Passport's TokenGuard:
// signature and time constraints, database revocation, an active client and an
// existing user.
func (s *Service) ValidateAccess(ctx context.Context, token string) (*Identity, error) {
	claims, err := ParseAndVerifyRS256(s.cfg.PublicKey, token, s.cfg.now())
	if err != nil {
		return nil, ErrInvalidToken
	}
	revoked, err := s.repo.AccessTokenRevoked(ctx, claims.JTI)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, ErrInvalidToken
	}
	uid, err := strconv.ParseInt(claims.Sub, 10, 64)
	if err != nil || uid <= 0 {
		return nil, ErrInvalidToken
	}
	if len(claims.Aud) == 0 {
		return nil, ErrInvalidToken
	}
	clientID, ok := ClientID(claims.Aud[0])
	if !ok {
		return nil, ErrInvalidToken
	}
	client, err := s.repo.FindClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client == nil || client.Revoked || (client.Provider != "" && client.Provider != "users") {
		return nil, ErrInvalidToken
	}
	user, found, err := s.cfg.Users.ByUID(ctx, uid)
	if err != nil {
		return nil, err
	}
	if !found || user.UID != uid {
		return nil, ErrInvalidToken
	}
	return &Identity{UID: uid, ClientID: claims.Aud[0], Scopes: claims.Scopes, TokenID: claims.JTI}, nil
}

// RefreshID decrypts a refresh token and returns its row id. The token is not
// checked for expiry; revocation by an operator should still work.
func (s *Service) RefreshID(token string) (string, error) {
	var payload refreshPayload
	if err := s.decryptPayload(token, &payload); err != nil {
		return "", err
	}
	if payload.RefreshTokenID == "" {
		return "", errors.New("passport: refresh token has no id")
	}
	return payload.RefreshTokenID, nil
}

// AccessID verifies an access token and returns its JWT id.
func (s *Service) AccessID(token string) (string, error) {
	claims, err := ParseAndVerifyRS256(s.cfg.PublicKey, token, s.cfg.now())
	if err != nil {
		return "", err
	}
	return claims.JTI, nil
}
