package passport

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"blessing-skin-go/internal/legacy/revocation"
)

// IssueCode is the native equivalent of completing an authorized
// authorization-code request. It persists the code row and returns the opaque
// Defuse ciphertext.
func (s *Service) IssueCode(ctx context.Context, clientID, uid int64, redirectURI string, scopes []string, challenge, method string) (string, string, time.Time, error) {
	var (
		code    string
		id      string
		expires time.Time
	)
	err := s.withTx(ctx, func(tx *Service, sqlTx *sql.Tx) error {
		client, err := tx.repo.FindClient(ctx, clientID)
		if err != nil {
			return err
		}
		if client == nil || client.Revoked {
			return errInvalidClient("unknown client")
		}
		if !client.AllowsRedirect(redirectURI) {
			return errInvalidRequest("invalid redirect URI")
		}
		if len(scopes) == 0 {
			scopes = append([]string(nil), DefaultScopes...)
		}
		if unknown, ok := ValidateScopes(scopes); !ok {
			return errInvalidScope(unknown)
		}
		// Issue under the same account boundary as redemption so a concurrent
		// password change cannot revoke the previous generation between the
		// approval check and this row.
		user, err := tx.lockUser(ctx, sqlTx, uid)
		if err != nil {
			return err
		}
		if user == nil {
			return errInvalidGrant("The user credentials were incorrect.")
		}
		approvedRev, err := tx.approvedVersion(ctx, sqlTx, uid)
		if err != nil {
			return err
		}
		id, err = randomID(40)
		if err != nil {
			return err
		}
		expires = s.cfg.now().Add(s.cfg.CodeTTL).Truncate(time.Second)
		if err := tx.repo.CreateAuthCode(ctx, AuthCodeRow{
			ID: id, UserID: uid, ClientID: client.Identifier(), Scopes: scopes, ExpiresAt: expires,
		}); err != nil {
			return err
		}
		code, err = tx.encryptPayload(codePayload{
			ClientID:            client.Identifier(),
			RedirectURI:         redirectURI,
			AuthCodeID:          id,
			Scopes:              scopes,
			UserID:              uid,
			ExpireTime:          expires.Unix(),
			CodeChallenge:       challenge,
			CodeChallengeMethod: method,
			ApprovedRev:         approvedRev,
		})
		return err
	})
	if err != nil {
		return "", "", time.Time{}, err
	}
	return code, id, expires, nil
}

// approvedVersion reads the account's current session generation inside tx. No
// state row means no revocation has been recorded yet, which is generation 0.
func (s *Service) approvedVersion(ctx context.Context, tx *sql.Tx, uid int64) (int64, error) {
	state, err := revocation.New(s.cfg.DB, s.cfg.Prefix).GetTx(ctx, tx, uid)
	if errors.Is(err, revocation.ErrNoState) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return state.SessionVersion, nil
}

// ExchangeCode implements the authorization_code grant.
func (s *Service) ExchangeCode(ctx context.Context, code, clientID, secret, redirectURI, verifier string) (*TokenResponse, error) {
	return s.tokenTransaction(ctx, func(tx *Service, sqlTx *sql.Tx) (*TokenResponse, error) {
		return tx.exchangeCode(ctx, sqlTx, code, clientID, secret, redirectURI, verifier)
	})
}

func (s *Service) exchangeCode(ctx context.Context, sqlTx *sql.Tx, code, clientID, secret, redirectURI, verifier string) (*TokenResponse, error) {
	client, tokenErr := s.clientForToken(ctx, clientID, secret)
	if tokenErr != nil {
		return nil, tokenErr
	}
	// ClientRepository::validateClient admits authorization_code only for
	// non-first-party clients.
	if client.FirstParty() {
		return nil, errInvalidClient("client cannot use the authorization_code grant")
	}
	var payload codePayload
	if err := s.decryptPayload(code, &payload); err != nil {
		return nil, errInvalidRequest("Cannot decrypt the authorization code")
	}
	uid, ok := toInt64(payload.UserID)
	if !ok || payload.AuthCodeID == "" {
		return nil, errInvalidRequest("Authorization code malformed")
	}
	// Lock the account before consuming the code so a concurrent password
	// change cannot revoke the old generation and then lose to this issuance.
	if _, err := s.lockUser(ctx, sqlTx, uid); err != nil {
		return nil, err
	}
	if payload.ApprovedRev > 0 {
		current, err := s.approvedVersion(ctx, sqlTx, uid)
		if err != nil {
			return nil, err
		}
		if current != payload.ApprovedRev {
			return nil, errInvalidGrant("Authorization code has been revoked")
		}
	}
	if s.cfg.now().Unix() > payload.ExpireTime {
		return nil, errInvalidRequest("Authorization code has expired")
	}
	revoked, err := s.repo.AuthCodeRevoked(ctx, payload.AuthCodeID)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, errInvalidRequest("Authorization code has been revoked")
	}
	if payload.ClientID != client.Identifier() {
		return nil, errInvalidRequest("Authorization code was not issued to this client")
	}
	if payload.RedirectURI != "" && redirectURI == "" {
		return nil, errInvalidRequest("redirect_uri is required")
	}
	if payload.RedirectURI != redirectURI {
		return nil, errInvalidRequest("Invalid redirect URI")
	}
	if payload.CodeChallenge != "" && !verifyPKCE(payload.CodeChallenge, payload.CodeChallengeMethod, verifier) {
		if verifier == "" {
			return nil, errInvalidRequest("code_verifier is required")
		}
		return nil, errInvalidGrant("Failed to verify `code_verifier`.")
	}
	if unknown, ok := ValidateScopes(payload.Scopes); !ok {
		return nil, errInvalidScope(unknown)
	}
	// Single winner: only one caller may consume the code.
	consumed, err := s.repo.RevokeAuthCodeIfActive(ctx, payload.AuthCodeID)
	if err != nil {
		return nil, err
	}
	if !consumed {
		return nil, errInvalidGrant("Authorization code has been revoked")
	}

	accessToken, accessID, expires, err := s.issueAccessToken(ctx, client, uid, payload.Scopes)
	if err != nil {
		return nil, err
	}
	refreshToken, _, _, err := s.issueRefreshToken(ctx, client, uid, payload.Scopes, accessID)
	if err != nil {
		return nil, err
	}
	return &TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    expires.Unix() - s.cfg.now().Unix(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// Refresh implements the refresh_token grant, including single-winner
// rotation.
func (s *Service) Refresh(ctx context.Context, refreshToken, clientID, secret, scopeParam string) (*TokenResponse, error) {
	return s.tokenTransaction(ctx, func(tx *Service, sqlTx *sql.Tx) (*TokenResponse, error) {
		return tx.refresh(ctx, sqlTx, refreshToken, clientID, secret, scopeParam)
	})
}

func (s *Service) refresh(ctx context.Context, sqlTx *sql.Tx, refreshToken, clientID, secret, scopeParam string) (*TokenResponse, error) {
	client, tokenErr := s.clientForToken(ctx, clientID, secret)
	if tokenErr != nil {
		return nil, tokenErr
	}
	var payload refreshPayload
	if err := s.decryptPayload(refreshToken, &payload); err != nil {
		return nil, errInvalidGrant("Cannot decrypt the refresh token")
	}
	uid, ok := toInt64(payload.UserID)
	if !ok || payload.RefreshTokenID == "" {
		return nil, errInvalidGrant("Refresh token malformed")
	}
	// Same identity boundary as the other grants: rotation cannot outrun a
	// password change or global revocation for this account.
	if _, err := s.lockUser(ctx, sqlTx, uid); err != nil {
		return nil, err
	}
	if payload.ClientID != client.Identifier() {
		return nil, errInvalidGrant("Token is not linked to client")
	}
	if payload.ExpireTime < s.cfg.now().Unix() {
		return nil, errInvalidGrant("Token has expired")
	}
	revoked, err := s.repo.RefreshTokenRevoked(ctx, payload.RefreshTokenID)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, errInvalidGrant("Token has been revoked")
	}

	scopes := payload.Scopes
	if requested := ParseScopes(scopeParam); len(requested) > 0 {
		allowed := scopeSet(scopes)
		for _, scope := range requested {
			if !allowed[scope] {
				return nil, errInvalidScope(scope)
			}
		}
		scopes = IntersectScopes(requested)
	}
	if unknown, ok := ValidateScopes(scopes); !ok {
		return nil, errInvalidScope(unknown)
	}

	rotated, err := s.repo.RevokeRefreshTokenIfActive(ctx, payload.RefreshTokenID)
	if err != nil {
		return nil, err
	}
	if !rotated {
		return nil, errInvalidGrant("Token has been revoked")
	}
	if err := s.repo.RevokeAccessToken(ctx, payload.AccessTokenID); err != nil {
		return nil, err
	}

	accessToken, accessID, expires, err := s.issueAccessToken(ctx, client, uid, scopes)
	if err != nil {
		return nil, err
	}
	newRefresh, _, _, err := s.issueRefreshToken(ctx, client, uid, scopes, accessID)
	if err != nil {
		return nil, err
	}
	return &TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    expires.Unix() - s.cfg.now().Unix(),
		AccessToken:  accessToken,
		RefreshToken: newRefresh,
	}, nil
}

// Password implements the password grant using the frozen email lookup and
// Laravel's password_verify semantics.
func (s *Service) Password(ctx context.Context, clientID, secret, username, password, scopeParam string) (*TokenResponse, error) {
	return s.tokenTransaction(ctx, func(tx *Service, sqlTx *sql.Tx) (*TokenResponse, error) {
		return tx.password(ctx, sqlTx, clientID, secret, username, password, scopeParam)
	})
}

func (s *Service) password(ctx context.Context, sqlTx *sql.Tx, clientID, secret, username, password, scopeParam string) (*TokenResponse, error) {
	client, tokenErr := s.clientForToken(ctx, clientID, secret)
	if tokenErr != nil {
		return nil, tokenErr
	}
	if !client.Password {
		return nil, errInvalidClient("client cannot use the password grant")
	}
	// The frozen app has no auth.guards.api fallback; only users is configured.
	if client.Provider != "users" {
		return nil, errors.New("passport: unable to determine authentication model from configuration")
	}
	// The lock is taken by the email that identifies the credential, so the
	// verification and the issuance below cannot straddle a password change.
	user, found, err := s.cfg.Users.ByEmailForUpdate(ctx, sqlTx, username)
	if err != nil {
		return nil, err
	}
	if !found || !verifyLaravelPassword(password, user.Password) {
		return nil, errInvalidGrant("The user credentials were incorrect.")
	}
	if s.afterVerify != nil {
		s.afterVerify()
	}
	scopes := ParseScopes(scopeParam)
	if len(scopes) == 0 {
		scopes = append([]string(nil), DefaultScopes...)
	}
	if unknown, ok := ValidateScopes(scopes); !ok {
		return nil, errInvalidScope(unknown)
	}
	accessToken, accessID, expires, err := s.issueAccessToken(ctx, client, user.UID, scopes)
	if err != nil {
		return nil, err
	}
	refreshToken, _, _, err := s.issueRefreshToken(ctx, client, user.UID, scopes, accessID)
	if err != nil {
		return nil, err
	}
	return &TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    expires.Unix() - s.cfg.now().Unix(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// RevokeAccess revokes the access-token row by JWT id.
func (s *Service) RevokeAccess(ctx context.Context, tokenID string) error {
	return s.repo.RevokeAccessToken(ctx, tokenID)
}

// RevokeRefresh revokes the refresh-token row by id.
func (s *Service) RevokeRefresh(ctx context.Context, tokenID string) error {
	return s.repo.RevokeRefreshToken(ctx, tokenID)
}

// RevokeCode revokes the authorization-code row by id.
func (s *Service) RevokeCode(ctx context.Context, tokenID string) error {
	return s.repo.RevokeAuthCode(ctx, tokenID)
}

// ClientCreate inserts a synthetic client.
func (s *Service) ClientCreate(ctx context.Context, client Client) error {
	return s.repo.CreateClient(ctx, client)
}

// Reset removes synthetic clients and their token rows.
func (s *Service) Reset(ctx context.Context, uid int64, clients []int64) error {
	return s.repo.Reset(ctx, uid, clients)
}

// ClientID parses a client id and reports whether it is numeric.
func ClientID(value string) (int64, bool) {
	id, err := strconv.ParseInt(value, 10, 64)
	return id, err == nil
}
