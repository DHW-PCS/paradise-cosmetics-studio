package oauthserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	engine "authelia.com/provider/oauth2/handler/oauth2"
	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
)

type storage struct {
	store    *database.Store
	identity *identity.Service
	scopes   []string
	strategy engine.CoreStrategy
}
type transactionKey struct{}
type transaction struct {
	tx            *sql.Tx
	done          bool
	revocation    bool
	failed        bool
	clientID      string
	proof         *identity.PasswordProof
	code, refresh string
}

// run starts before protocol validation so PKCE deletion and code consumption
// share the same transaction. An engine Commit is real, including replay revocation.
func (s *storage) run(ctx context.Context, f func(context.Context) error) error {
	return s.runOn(ctx, s.store.DB, f)
}
func (s *storage) runOn(ctx context.Context, db *sql.DB, f func(context.Context) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	root := &transaction{tx: tx}
	ctx = context.WithValue(ctx, transactionKey{}, root)
	err = f(ctx)
	if root.failed {
		return ErrUnavailable
	}
	if root.done {
		return err
	}
	if err == nil || root.revocation && !root.failed {
		if commitErr := tx.Commit(); commitErr != nil {
			return commitErr
		}
	}
	return err
}

func root(ctx context.Context) *transaction { return ctx.Value(transactionKey{}).(*transaction) }
func (s *storage) BeginTX(ctx context.Context) (context.Context, error) {
	_ = root(ctx)
	return ctx, nil
}
func (s *storage) Commit(ctx context.Context) error {
	r := root(ctx)
	if r.failed {
		return ErrUnavailable
	}
	r.done = true
	return r.tx.Commit()
}
func (s *storage) Rollback(ctx context.Context) error {
	r := root(ctx)
	if r.done {
		return nil
	}
	r.done = true
	return r.tx.Rollback()
}
func (s *storage) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	r := root(ctx)
	result, err := r.tx.ExecContext(ctx, q, args...)
	if err != nil {
		r.failed = true
	}
	return result, err
}

func (s *storage) GetClient(ctx context.Context, id string) (oauth2.Client, error) {
	r := root(ctx)
	var secret sql.NullString
	var redirect string
	var revoked, personal, password bool
	err := r.tx.QueryRowContext(ctx, "SELECT secret,redirect,revoked,personal_access_client,password_client FROM "+s.store.Table("oauth_clients")+" WHERE id=? FOR UPDATE", id).Scan(&secret, &redirect, &revoked, &personal, &password)
	if errors.Is(err, sql.ErrNoRows) || revoked {
		return nil, oauth2.ErrNotFound
	}
	if err != nil {
		r.failed = true
		return nil, err
	}
	if r.clientID == "" {
		r.clientID = id
	}
	grants := []string{"client_credentials"}
	if password {
		grants = append(grants, "password", "refresh_token")
	} else if !personal {
		grants = append(grants, "authorization_code", "refresh_token")
	}
	return &oauth2.DefaultClient{ID: id, ClientSecret: oauth2.NewPlainTextClientSecret(secret.String), RedirectURIs: strings.Split(redirect, ","), GrantTypes: grants, ResponseTypes: []string{"code"}, Scopes: s.scopes, Public: !secret.Valid || secret.String == ""}, nil
}

var errUnsupported = errors.New("oauth server: unsupported client operation")

func (s *storage) CreateClient(context.Context, oauth2.Client) error         { return errUnsupported }
func (s *storage) UpdateClient(context.Context, string, oauth2.Client) error { return errUnsupported }
func (s *storage) DeleteClient(context.Context, string) error                { return errUnsupported }
func (s *storage) ClientAssertionJWTValid(context.Context, string) error     { return errUnsupported }
func (s *storage) SetClientAssertionJWT(context.Context, string, time.Time) error {
	return errUnsupported
}

type record struct {
	ID                                 string
	Requested                          time.Time
	RequestedScopes, GrantedScopes     []string
	RequestedAudience, GrantedAudience []string
	Form                               url.Values
	Session                            *session
}

func (s *storage) save(ctx context.Context, table, signature, access string, request oauth2.Requester, typ oauth2.TokenType) error {
	state := request.GetSession().(*session)
	if err := s.checkUser(ctx, state); err != nil {
		return err
	}
	form := url.Values{}
	for _, key := range []string{"redirect_uri", "code_challenge", "code_challenge_method"} {
		if v, ok := request.GetRequestForm()[key]; ok {
			form[key] = v
		}
	}
	body, err := json.Marshal(record{request.GetID(), request.GetRequestedAt(), request.GetRequestedScopes(), request.GetGrantedScopes(), request.GetRequestedAudience(), request.GetGrantedAudience(), form, state})
	if err != nil {
		return err
	}
	var uid, version any
	if state.Subject != "" {
		uid = state.Subject
		version = state.Version
	}
	var accessDigest []byte
	if access != "" {
		accessDigest = identity.Digest(access)
	}
	_, err = s.exec(ctx, "INSERT INTO "+s.store.Table(table)+" (signature,request_id,client_id,user_uid,version,active,expires_at,access_signature,payload) VALUES (?,?,?,?,?,1,?,?,?)", identity.Digest(signature), request.GetID(), request.GetClient().GetID(), uid, version, request.GetSession().GetExpiresAt(typ).Unix(), accessDigest, body)
	return err
}

func (s *storage) checkUser(ctx context.Context, state *session) error {
	if state.Subject == "" {
		return nil
	}
	r := root(ctx)
	uid, err := strconv.ParseInt(state.Subject, 10, 64)
	if err != nil {
		return oauth2.ErrNotFound
	}
	if r.proof != nil {
		if r.proof.UID() != uid {
			return oauth2.ErrNotFound
		}
		if _, err = s.identity.RecheckPassword(ctx, r.tx, r.proof); err != nil {
			return err
		}
	}
	var permission int
	if err = r.tx.QueryRowContext(ctx, "SELECT permission FROM "+s.store.Table("users")+" WHERE uid=? FOR UPDATE", uid).Scan(&permission); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return oauth2.ErrNotFound
		}
		r.failed = true
		return err
	}
	var current int64
	if err = r.tx.QueryRowContext(ctx, "SELECT version FROM "+s.store.Table("go_auth_versions")+" WHERE user_uid=? FOR UPDATE", uid).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return oauth2.ErrNotFound
		}
		r.failed = true
		return err
	}
	if current != state.Version || permission < 0 {
		return oauth2.ErrNotFound
	}
	return nil
}

func (s *storage) get(ctx context.Context, table, signature string) (oauth2.Requester, bool, error) {
	r := root(ctx)
	var body []byte
	var client string
	var active bool
	err := r.tx.QueryRowContext(ctx, "SELECT client_id,payload FROM "+s.store.Table(table)+" WHERE signature=?", identity.Digest(signature)).Scan(&client, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, oauth2.ErrNotFound
	}
	if err != nil {
		r.failed = true
		return nil, false, err
	}
	if r.clientID != "" && r.clientID != client {
		return nil, false, oauth2.ErrNotFound
	}
	var data record
	if err = json.Unmarshal(body, &data); err != nil {
		r.failed = true
		return nil, false, err
	}
	c, err := s.GetClient(ctx, client)
	if err != nil {
		return nil, false, err
	}
	if err = s.checkUser(ctx, data.Session); err != nil {
		return nil, false, err
	}
	err = r.tx.QueryRowContext(ctx, "SELECT active,payload FROM "+s.store.Table(table)+" WHERE signature=? FOR UPDATE", identity.Digest(signature)).Scan(&active, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, oauth2.ErrNotFound
	}
	if err != nil {
		r.failed = true
		return nil, false, err
	}
	if err = json.Unmarshal(body, &data); err != nil {
		r.failed = true
		return nil, false, err
	}
	request := oauth2.NewRequest()
	request.ID = data.ID
	request.RequestedAt = data.Requested
	request.Client = c
	request.RequestedScope = data.RequestedScopes
	request.GrantedScope = data.GrantedScopes
	request.RequestedAudience = data.RequestedAudience
	request.GrantedAudience = data.GrantedAudience
	request.Form = data.Form
	request.Session = data.Session
	return request, active, nil
}

func (s *storage) CreateAuthorizeCodeSession(ctx context.Context, sig string, r oauth2.Requester) error {
	return s.save(ctx, "go_oauth_codes", sig, "", r, oauth2.AuthorizeCode)
}
func (s *storage) GetAuthorizeCodeSession(ctx context.Context, sig string, _ oauth2.Session) (oauth2.Requester, error) {
	r, active, err := s.get(ctx, "go_oauth_codes", sig)
	if err != nil {
		return nil, err
	}
	if !active {
		if err = s.strategy.ValidateAuthorizeCode(ctx, r, root(ctx).code); err != nil {
			return nil, oauth2.ErrInvalidGrant.WithWrap(err)
		}
		return r, oauth2.ErrInvalidatedAuthorizeCode
	}
	return r, nil
}
func (s *storage) InvalidateAuthorizeCodeSession(ctx context.Context, sig string) error {
	result, err := s.exec(ctx, "UPDATE "+s.store.Table("go_oauth_codes")+" SET active=0 WHERE signature=? AND active=1", identity.Digest(sig))
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return oauth2.ErrInvalidatedAuthorizeCode
	}
	return nil
}
func (s *storage) CreateAccessTokenSession(ctx context.Context, sig string, r oauth2.Requester) error {
	return s.save(ctx, "go_oauth_access", sig, "", r, oauth2.AccessToken)
}
func (s *storage) GetAccessTokenSession(ctx context.Context, sig string, _ oauth2.Session) (oauth2.Requester, error) {
	r, active, err := s.get(ctx, "go_oauth_access", sig)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, oauth2.ErrNotFound
	}
	return r, nil
}
func (s *storage) DeleteAccessTokenSession(ctx context.Context, sig string) error {
	_, err := s.exec(ctx, "DELETE FROM "+s.store.Table("go_oauth_access")+" WHERE signature=?", identity.Digest(sig))
	return err
}
func (s *storage) CreateRefreshTokenSession(ctx context.Context, sig, access string, r oauth2.Requester) error {
	return s.save(ctx, "go_oauth_refresh", sig, access, r, oauth2.RefreshToken)
}
func (s *storage) GetRefreshTokenSession(ctx context.Context, sig string, _ oauth2.Session) (oauth2.Requester, error) {
	r, active, err := s.get(ctx, "go_oauth_refresh", sig)
	if err != nil {
		return nil, err
	}
	if !active {
		if err = s.strategy.ValidateRefreshToken(ctx, r, root(ctx).refresh); err != nil {
			return nil, oauth2.ErrInvalidGrant.WithWrap(err)
		}
		return r, oauth2.ErrInactiveToken
	}
	return r, nil
}
func (s *storage) DeleteRefreshTokenSession(ctx context.Context, sig string) error {
	_, err := s.exec(ctx, "UPDATE "+s.store.Table("go_oauth_refresh")+" SET active=0 WHERE signature=?", identity.Digest(sig))
	return err
}
func (s *storage) RotateRefreshToken(ctx context.Context, id, sig string) error {
	result, err := s.exec(ctx, "UPDATE "+s.store.Table("go_oauth_refresh")+" SET active=0 WHERE request_id=? AND signature=? AND active=1", id, identity.Digest(sig))
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return oauth2.ErrInactiveToken
	}
	_, err = s.exec(ctx, "UPDATE "+s.store.Table("go_oauth_access")+" SET active=0 WHERE request_id=?", id)
	return err
}
func (s *storage) RevokeAccessToken(ctx context.Context, id string) error {
	return s.revoke(ctx, "go_oauth_access", id)
}
func (s *storage) RevokeRefreshToken(ctx context.Context, id string) error {
	return s.revoke(ctx, "go_oauth_refresh", id)
}
func (s *storage) revoke(ctx context.Context, table, id string) error {
	_, err := s.exec(ctx, "UPDATE "+s.store.Table(table)+" SET active=0 WHERE request_id=?", id)
	if err == nil {
		root(ctx).revocation = true
	}
	return err
}
func (s *storage) CreatePKCERequestSession(ctx context.Context, sig string, r oauth2.Requester) error {
	return s.save(ctx, "go_oauth_pkce", sig, "", r, oauth2.AuthorizeCode)
}
func (s *storage) GetPKCERequestSession(ctx context.Context, sig string, _ oauth2.Session) (oauth2.Requester, error) {
	r, _, err := s.get(ctx, "go_oauth_pkce", sig)
	return r, err
}
func (s *storage) DeletePKCERequestSession(ctx context.Context, sig string) error {
	_, err := s.exec(ctx, "DELETE FROM "+s.store.Table("go_oauth_pkce")+" WHERE signature=?", identity.Digest(sig))
	return err
}
func (s *storage) Authenticate(ctx context.Context, name, raw string) (string, error) {
	r := root(ctx)
	if r.proof == nil {
		return "", oauth2.ErrInvalidGrant
	}
	request := ctx.Value(oauth2.AccessRequestContextKey).(oauth2.AccessRequester)
	state := request.GetSession().(*session)
	state.Subject = strconv.FormatInt(r.proof.UID(), 10)
	state.Version = r.proof.Version()
	state.JWTClaims.Subject = state.Subject
	return state.Subject, nil
}
