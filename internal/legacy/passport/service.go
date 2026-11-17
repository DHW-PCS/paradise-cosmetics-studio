package passport

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"paradise-cosmetics-studio/internal/legacy/users"
)

// Error mirrors the OAuth error body produced by OAuthServerException.
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	Status      int    `json:"-"`
	Message     string `json:"message,omitempty"`
}

func (e *Error) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

func errInvalidRequest(description string) *Error {
	return &Error{Code: "invalid_request", Description: description, Status: 400}
}

func errInvalidClient(description string) *Error {
	return &Error{Code: "invalid_client", Description: description, Status: 401}
}

func errInvalidGrant(description string) *Error {
	return &Error{Code: "invalid_grant", Description: description, Status: 400}
}

func errInvalidScope(scope string) *Error {
	return &Error{Code: "invalid_scope", Description: "The requested scope is invalid, unknown, or malformed: " + scope, Status: 400}
}

// Service owns the frozen Passport repositories and codec.
type Service struct {
	cfg  Config
	repo *Repo

	// afterVerify is a test-only observation point invoked inside the token
	// transaction once the password has matched. Nil in production.
	afterVerify func()
}

func New(cfg Config) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Service{cfg: cfg, repo: NewRepo(cfg.DB, cfg.Prefix, cfg.location())}, nil
}

func (s *Service) Repo() *Repo { return s.repo }

type TokenResponse struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type codePayload struct {
	ClientID            string   `json:"client_id"`
	RedirectURI         string   `json:"redirect_uri"`
	AuthCodeID          string   `json:"auth_code_id"`
	Scopes              []string `json:"scopes"`
	UserID              any      `json:"user_id"`
	ExpireTime          int64    `json:"expire_time"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	// ApprovedRev is the account session version observed under the lock when
	// the approval issued this code. New Go codes always write it, including a
	// zero generation, so redemption can tell "approved at generation 0" from
	// "native code that never recorded an approval generation". A nil pointer
	// means the native PHP writer produced the payload; that compatibility path
	// keeps the frozen row-revocation, expiry and client checks.
	ApprovedRev *int64 `json:"approved_rev"`
}

type refreshPayload struct {
	ClientID       string   `json:"client_id"`
	RefreshTokenID string   `json:"refresh_token_id"`
	AccessTokenID  string   `json:"access_token_id"`
	Scopes         []string `json:"scopes"`
	UserID         any      `json:"user_id"`
	ExpireTime     int64    `json:"expire_time"`
}

func (s *Service) issueAccessToken(ctx context.Context, client *Client, uid int64, scopes []string) (string, string, time.Time, error) {
	id, err := randomID(40)
	if err != nil {
		return "", "", time.Time{}, err
	}
	now := s.cfg.now()
	expires := now.Add(s.cfg.AccessTTL).Truncate(time.Second)
	if err := s.repo.CreateAccessToken(ctx, AccessTokenRow{
		ID: id, UserID: uid, ClientID: client.Identifier(), Scopes: scopes, ExpiresAt: expires,
	}); err != nil {
		return "", "", time.Time{}, err
	}
	token, err := SignRS256(s.cfg.PrivateKey, Claims{
		Aud:    []string{client.Identifier()},
		JTI:    id,
		IAT:    now.Unix(),
		NBF:    now.Unix(),
		EXP:    expires.Unix(),
		Sub:    strconv.FormatInt(uid, 10),
		Scopes: scopes,
	})
	if err != nil {
		return "", "", time.Time{}, err
	}
	return token, id, expires, nil
}

func (s *Service) issueRefreshToken(ctx context.Context, client *Client, uid int64, scopes []string, accessTokenID string) (string, string, time.Time, error) {
	id, err := randomID(40)
	if err != nil {
		return "", "", time.Time{}, err
	}
	expires := s.cfg.now().Add(s.cfg.RefreshTTL).Truncate(time.Second)
	if err := s.repo.CreateRefreshToken(ctx, RefreshTokenRow{
		ID: id, AccessTokenID: accessTokenID, ExpiresAt: expires,
	}); err != nil {
		return "", "", time.Time{}, err
	}
	token, err := s.encryptPayload(refreshPayload{
		ClientID:       client.Identifier(),
		RefreshTokenID: id,
		AccessTokenID:  accessTokenID,
		Scopes:         scopes,
		UserID:         uid,
		ExpireTime:     expires.Unix(),
	})
	if err != nil {
		return "", "", time.Time{}, err
	}
	return token, id, expires, nil
}

func (s *Service) encryptPayload(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return EncryptWithPassword(string(data), s.cfg.AppKey)
}

func (s *Service) decryptPayload(ciphertext string, target any) error {
	plaintext, err := DecryptWithPassword(ciphertext, s.cfg.AppKey)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(plaintext), target)
}

func randomID(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func toInt64(value any) (int64, bool) {
	switch v := value.(type) {
	case float64:
		return int64(v), true
	case int64:
		return v, true
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		return n, err == nil
	default:
		return 0, false
	}
}

func verifySecret(client *Client, provided string) bool {
	if !client.Confidential() {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(client.Secret), []byte(provided)) == 1
}

func verifyLaravelPassword(raw, hash string) bool {
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(raw)) == nil
	}
	// Laravel's BcryptHasher uses password_verify, which also accepts argon2
	// hashes. Those are not part of the M1-02 fixtures; treated as a gap.
	return false
}

var verifierPattern = regexp.MustCompile(`^[A-Za-z0-9\-._~]{43,128}$`)

func verifyPKCE(challenge, method, verifier string) bool {
	if challenge == "" {
		return true
	}
	if verifier == "" || !verifierPattern.MatchString(verifier) {
		return false
	}
	switch method {
	case "", "plain":
		return subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) == 1
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
	default:
		return false
	}
}

func (s *Service) clientForToken(ctx context.Context, clientID string, secret string) (*Client, *Error) {
	id, err := strconv.ParseInt(clientID, 10, 64)
	if err != nil {
		return nil, errInvalidClient("unknown client")
	}
	client, err := s.repo.FindClient(ctx, id)
	if err != nil {
		return nil, &Error{Code: "server_error", Description: err.Error(), Status: 500}
	}
	if client == nil || client.Revoked {
		return nil, errInvalidClient("unknown client")
	}
	if !verifySecret(client, secret) {
		return nil, errInvalidClient("invalid client secret")
	}
	return client, nil
}

// tokenTransaction commits identity checks, consumption, revocation and new
// token rows together. A storage failure must not consume a credential, leave a
// partial token pair, or issue credentials from an account state that a
// concurrent password change already replaced.
func (s *Service) tokenTransaction(ctx context.Context, issue func(*Service, *sql.Tx) (*TokenResponse, error)) (*TokenResponse, error) {
	var response *TokenResponse
	err := s.withTx(ctx, func(scoped *Service, tx *sql.Tx) error {
		var err error
		response, err = issue(scoped, tx)
		return err
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

// withTx runs fn against a service and repository bound to one transaction.
func (s *Service) withTx(ctx context.Context, fn func(*Service, *sql.Tx) error) error {
	tx, err := s.cfg.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	scoped := *s
	repo := *s.repo
	repo.db = tx
	scoped.repo = &repo
	if err := fn(&scoped, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// lockUser serializes credential verification and issuance with password
// changes and global revocation for the same account. A missing account returns
// a nil user: the frozen grants do not re-check the user when rotating, so only
// an existing row needs to be locked.
func (s *Service) lockUser(ctx context.Context, tx *sql.Tx, uid int64) (*users.User, error) {
	user, found, err := s.cfg.Users.ByUIDForUpdate(ctx, tx, uid)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return user, nil
}
