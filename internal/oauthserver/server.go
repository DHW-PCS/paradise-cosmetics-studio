// Package oauthserver adapts the selected OAuth engine to Go-owned state.
// Protocol library types remain private to this package.
package oauthserver

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	engine "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
	"blessing-skin-go/internal/admission"
	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
)

type Config struct {
	Store                                         *database.Store
	Identity                                      *identity.Service
	PrivateKey                                    *rsa.PrivateKey
	Secret                                        []byte
	Issuer                                        string
	Scopes                                        []string
	AccessLifetime, RefreshLifetime, CodeLifetime time.Duration
}

type Server struct {
	cfg      Config
	provider oauth2.Provider
	storage  *storage
}

type session struct {
	engine.JWTSession
	Version int64
	Label   string
}

func (s *session) Clone() oauth2.Session {
	clone := *s
	clone.JWTSession = *s.JWTSession.Clone().(*engine.JWTSession)
	return &clone
}
func newSession(uid, version int64) *session {
	sub := ""
	if uid != 0 {
		sub = strconv.FormatInt(uid, 10)
	}
	return &session{JWTSession: engine.JWTSession{Subject: sub, JWTClaims: &jwt.JWTClaims{Subject: sub}, JWTHeader: jwt.NewHeaders()}, Version: version}
}

func New(c Config) (*Server, error) {
	if c.Store == nil || c.Identity == nil || c.PrivateKey == nil || len(c.Secret) < 32 || c.Issuer == "" || len(c.Scopes) == 0 || c.AccessLifetime <= 0 || c.RefreshLifetime <= 0 || c.CodeLifetime <= 0 {
		return nil, errors.New("oauth server: incomplete configuration")
	}
	cfg := &oauth2.Config{GlobalSecret: c.Secret, AccessTokenIssuer: c.Issuer, AccessTokenLifespan: c.AccessLifetime, RefreshTokenLifespan: c.RefreshLifetime, AuthorizeCodeLifespan: c.CodeLifetime, RefreshTokenScopes: []string{}, ScopeStrategy: oauth2.ExactScopeStrategy, EnforceJWTProfileAccessTokens: true, EnablePKCEPlainChallengeMethod: true, EnforcePKCEForPublicClients: true}
	issuer, err := jwt.NewDefaultIssuerRS256(c.PrivateKey)
	if err != nil {
		return nil, err
	}
	strategy := compose.NewOAuth2JWTStrategy(&jwt.DefaultStrategy{Config: cfg, Issuer: issuer}, compose.NewOAuth2HMACStrategy(cfg), cfg)
	st := &storage{store: c.Store, identity: c.Identity, scopes: append(append([]string(nil), c.Scopes...), "*"), strategy: strategy}
	p := compose.Compose(cfg, st, strategy, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2RefreshTokenGrantFactory, compose.OAuth2ResourceOwnerPasswordCredentialsFactory, compose.OAuth2ClientCredentialsGrantFactory, compose.OAuth2PKCEFactory, compose.OAuth2TokenIntrospectionFactory, compose.OAuth2TokenRevocationFactory)
	return &Server{c, p, st}, nil
}

// Authorize is called only after the application obtains authenticated consent.
// The credential is rechecked in the same transaction that issues the code.
func (s *Server) Authorize(ctx context.Context, r *http.Request, browser *identity.BrowserSession) (string, error) {
	if err := r.ParseForm(); err != nil {
		return "", oauth2.ErrInvalidRequest
	}
	if r.Form.Get("scope") == "" {
		r.Form.Set("scope", "User.Read")
	}
	var code string
	err := s.storage.run(ctx, func(ctx context.Context) error {
		request, err := s.provider.NewAuthorizeRequest(ctx, r)
		if err != nil {
			return err
		}
		user, err := s.cfg.Identity.CheckBrowserTx(ctx, root(ctx).tx, browser)
		if err != nil {
			return err
		}
		for _, scope := range request.GetRequestedScopes() {
			if scope != "*" {
				request.GrantScope(scope)
			}
		}
		response, err := s.provider.NewAuthorizeResponse(ctx, request, newSession(user.UID, browser.Version))
		if err != nil {
			return err
		}
		code = response.GetCode()
		return nil
	})
	return code, err
}

// Token implements the protocol endpoint. Password calculation precedes the
// SQL transaction, while the same admission slot covers verification and issuance.
func (s *Server) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.provider.WriteAccessError(r.Context(), w, nil, oauth2.ErrInvalidRequest)
		return
	}
	grant := r.PostForm.Get("grant_type")
	if (grant == "password" || grant == "client_credentials") && r.PostForm.Get("scope") == "" {
		r.PostForm.Set("scope", "User.Read")
	}
	var request oauth2.AccessRequester
	var response oauth2.AccessResponder
	process := func(proof *identity.PasswordProof) error {
		db := s.cfg.Store.DB
		if proof != nil {
			db = s.cfg.Identity.LoginStore.DB
		}
		return s.storage.runOn(r.Context(), db, func(ctx context.Context) error {
			root := ctx.Value(transactionKey{}).(*transaction)
			root.proof = proof
			root.code = r.PostForm.Get("code")
			root.refresh = r.PostForm.Get("refresh_token")
			var err error
			request, err = s.provider.NewAccessRequest(ctx, r, newSession(0, 0))
			if err != nil {
				return err
			}
			if grant == "password" || grant == "client_credentials" {
				for _, scope := range request.GetRequestedScopes() {
					request.GrantScope(scope)
				}
			}
			if proof != nil {
				if _, err = s.cfg.Identity.RecheckPassword(ctx, root.tx, proof); err != nil {
					return err
				}
			}
			response, err = s.provider.NewAccessResponse(ctx, request)
			return err
		})
	}
	var err error
	if r.PostForm.Get("grant_type") == "password" {
		err = s.cfg.Identity.WithPassword(r.Context(), r.PostForm.Get("username"), r.PostForm.Get("password"), identity.EmailOnly, process)
		if errors.Is(err, identity.ErrCredentials) || errors.Is(err, identity.ErrStale) {
			err = oauth2.ErrInvalidGrant
		}
	} else {
		err = process(nil)
	}
	if err != nil {
		if errors.Is(err, admission.ErrBusy) {
			err = oauth2.ErrTemporarilyUnavailable
		}
		var protocolError *oauth2.RFC6749Error
		if !errors.As(err, &protocolError) {
			err = oauth2.ErrServerError.WithWrap(err)
		}
		s.provider.WriteAccessError(r.Context(), w, request, err)
		return
	}
	s.provider.WriteAccessResponse(r.Context(), w, request, response)
}

type Principal struct {
	UID      int64
	ClientID string
	Scopes   []string
}

func (s *Server) Validate(ctx context.Context, token string, scopes ...string) (*Principal, error) {
	var p *Principal
	err := s.storage.run(ctx, func(ctx context.Context) error {
		_, request, err := s.provider.IntrospectToken(ctx, token, oauth2.AccessToken, newSession(0, 0))
		if err != nil {
			return err
		}
		for _, scope := range scopes {
			if !request.GetGrantedScopes().Has(scope) && !request.GetGrantedScopes().Has("*") {
				return ErrScope
			}
		}
		uid, _ := strconv.ParseInt(request.GetSession().GetSubject(), 10, 64)
		p = &Principal{uid, request.GetClient().GetID(), append([]string(nil), request.GetGrantedScopes()...)}
		return nil
	})
	if err != nil {
		var protocol *oauth2.RFC6749Error
		if errors.As(err, &protocol) {
			if protocol.CodeField >= 500 {
				return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
			}
			return nil, ErrToken
		}
	}
	return p, err
}

var ErrToken = errors.New("oauth: invalid or revoked token")
var ErrScope = errors.New("oauth: insufficient scope")
var ErrUnavailable = errors.New("oauth: authoritative storage unavailable")

// Migrate installs the Go OAuth state only; it never alters Passport tables.
func (s *Server) Migrate(ctx context.Context) error {
	return Migrate(ctx, s.cfg.Store)
}

func Migrate(ctx context.Context, store *database.Store) error {
	for _, name := range []string{"go_oauth_codes", "go_oauth_access", "go_oauth_refresh", "go_oauth_pkce"} {
		ddl := "CREATE TABLE IF NOT EXISTS " + store.Table(name) + ` (signature BINARY(32) PRIMARY KEY,request_id VARCHAR(64) NOT NULL,client_id VARCHAR(100) NOT NULL,user_uid BIGINT NULL,version BIGINT NULL,active BOOLEAN NOT NULL,expires_at BIGINT NOT NULL,access_signature BINARY(32) NULL,payload LONGTEXT NOT NULL,INDEX grant_id(request_id),INDEX expiry(expires_at),INDEX account(user_uid)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
		if err := store.ApplyMigration(ctx, "004_"+name, ddl); err != nil {
			return err
		}
	}
	return nil
}
