package yggdrasil

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
)

// Service owns the Yggdrasil authentication lifecycle over database state.
//
// Flow per method (design lock order):
//
//	throttle (authenticate/signout only) -> identity password Gate outside
//	SQL -> module-state shared read (caller/HTTP layer holds it) ->
//	users row lock -> auth version -> token set -> identification /
//	players / binding current reads -> verification -> token write.
//
// The module-state shared read is owned by the caller (HTTP layer or
// offline driver); service methods assume that layer is held and never
// acquire the registration layer themselves.
type Service struct {
	Store    *database.Store
	Identity *identity.Service
	AppKey   []byte
	Verbose  bool
	Now      func() time.Time
	// ModuleLock, when set, installs the module-state shared current read
	// inside each business transaction and refuses with ErrModuleNotServed
	// when the module is unregistered or disabled. It is wired by the HTTP
	// composition root to modules.Manager.LockStateTx; a nil hook disables
	// the gate (direct service tests).
	ModuleLock func(ctx context.Context, tx *sql.Tx) error

	opts options
	jwt  jwtKey
}

// lockModuleState runs the wired module-state shared lock inside the
// caller's transaction, before any user/token lock, so the exclusive
// enable/disable writer (options rows first, then users) cannot interleave
// with a running business transaction.
func (s *Service) lockModuleState(ctx context.Context, tx *sql.Tx) error {
	if s.ModuleLock == nil {
		return nil
	}
	return s.ModuleLock(ctx, tx)
}

// New wires the Yggdrasil service. appKey is the HS256 secret
// (config.AppKey); verbose is config.YggVerboseLog.
// New wires the Yggdrasil service. snapshot is the declared options
// snapshot (nil reads the live options table); appKey is the HS256 secret
// (config.AppKey); verbose is config.YggVerboseLog.
func New(store *database.Store, id *identity.Service, snapshot map[string]string, appKey []byte, verbose bool, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	s := &Service{Store: store, Identity: id, AppKey: append([]byte(nil), appKey...), Verbose: verbose, Now: now}
	s.opts = newOptions(store, snapshot)
	s.jwt = newJWTKey(appKey)
	return s
}

func (s *Service) now() time.Time { return s.Now() }

// --- request / result shapes (batch4 maps these to protocol JSON) --------

type AuthenticateRequest struct {
	Username    string
	Password    string
	ClientToken *string // nil = missing field, generate; non-nil value kept verbatim
	RequestUser bool
	ClientIP    string
}

type AuthenticateResult struct {
	AccessToken       string
	ClientToken       string
	AvailableProfiles []Profile
	SelectedProfile   *Profile
	User              *User
}

type RefreshRequest struct {
	AccessToken     string
	ClientToken     *string
	SelectedProfile *SelectedProfileInput
	ClientIP        string
}

type RefreshResult struct {
	AccessToken       string
	ClientToken       string
	AvailableProfiles []Profile
	SelectedProfile   *Profile
	User              *User
}

type ValidateRequest struct {
	AccessToken string
	ClientToken *string
	ClientIP    string
}

type InvalidateRequest struct {
	AccessToken string
	ClientIP    string
}

type SignoutRequest struct {
	Username string
	Password string
	ClientIP string
}

// tokenRow is one go_yggdrasil_tokens row.
type tokenRow struct {
	Digest         []byte
	IssuanceOrder  int64
	UserUID        int64
	Version        int64
	ClientToken    string
	HasClientTok   bool
	SelectedPID    int64
	HasSelected    bool
	SelectedUUID   string
	BindingVersion int64
	HasBindingVer  bool
	Yggt           string
	CreatedAt      int64
	AccessUntil    int64
	RefreshUntil   int64
}

func scanToken(row interface{ Scan(...any) error }) (*tokenRow, error) {
	t := &tokenRow{}
	var ct sql.NullString
	var sp sql.NullInt64
	var su sql.NullString
	var bv sql.NullInt64
	err := row.Scan(&t.Digest, &t.IssuanceOrder, &t.UserUID, &t.Version, &ct, &sp, &su, &bv, &t.Yggt, &t.CreatedAt, &t.AccessUntil, &t.RefreshUntil)
	if err != nil {
		return nil, err
	}
	if ct.Valid {
		t.ClientToken = ct.String
		t.HasClientTok = true
	}
	if sp.Valid {
		t.SelectedPID = sp.Int64
		t.HasSelected = true
	}
	if su.Valid {
		t.SelectedUUID = su.String
	}
	if bv.Valid {
		t.BindingVersion = bv.Int64
		t.HasBindingVer = true
	}
	return t, nil
}

const tokenColumns = "digest,issuance_order,user_uid,version,client_token,selected_pid,selected_uuid,binding_version,yggt,created_at,access_until,refresh_until"

// currentUser is a freshly read account row inside the business transaction.
type currentUser struct {
	UID        int64
	Email      string
	Password   string
	Permission int
	Verified   bool
}

func (s *Service) lockUser(ctx context.Context, tx *sql.Tx, uid int64) (*currentUser, error) {
	u := &currentUser{}
	err := tx.QueryRowContext(ctx, "SELECT u.uid,u.email,u.password,u.permission,u.verified FROM "+s.Store.Table("users")+" u WHERE u.uid=? FOR UPDATE", uid).Scan(&u.UID, &u.Email, &u.Password, &u.Permission, &u.Verified)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// lockUserAndVersion acquires the users row and then the auth version row
// for uid in the frozen integration-design lock order
// (users -> auth versions -> credential/token). It is the only entry
// points Refresh, Validate and verifyTokenTx use to locate the account
// for a verified JWT: the subject UID from the already verified JWT
// selects the user to lock, and the DB token row remains authoritative
// for the UID/version comparison performed by the caller afterwards.
// Missing user/version rows are reported through the flags instead of an
// immediate return so callers can preserve their exact legacy error
// priority (token checks that preceded the user/version checks in the
// original code still run first). SQL faults are returned immediately.
func (s *Service) lockUserAndVersion(ctx context.Context, tx *sql.Tx, uid int64) (user *currentUser, version int64, userMissing, versionMissing bool, err error) {
	user, err = s.lockUser(ctx, tx, uid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, true, true, nil
		}
		return nil, 0, false, false, err
	}
	if err := tx.QueryRowContext(ctx, "SELECT version FROM "+s.Store.Table("go_auth_versions")+" WHERE user_uid=? FOR UPDATE", user.UID).Scan(&version); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user, 0, false, true, nil
		}
		return nil, 0, false, false, err
	}
	return user, version, false, false, nil
}

// requireVerified applies the require_verification option check.
func (s *Service) requireVerified(opts map[string]any, u *currentUser) error {
	raw, present := optionPresent(opts, "require_verification")
	if optionTruthy(raw, present) && !u.Verified {
		return ErrUserNotVerified
	}
	return nil
}

// --- profile discovery ----------------------------------------------------

type roleInfo struct {
	PID            int64
	Name           string
	UUIDDashed     string
	UUIDHex        string
	BindingVersion int64
}

// loadRoles locks the user's current player rows and their bindings, and
// returns the available profiles in PID order. A missing binding is a
// service fault: the protocol cannot name the role without it.
func (s *Service) loadRoles(ctx context.Context, tx *sql.Tx, uid int64) ([]roleInfo, []Profile, error) {
	rows, err := tx.QueryContext(ctx, "SELECT pid,name FROM "+s.Store.Table("players")+" WHERE uid=? ORDER BY pid FOR UPDATE", uid)
	if err != nil {
		return nil, nil, err
	}
	type pidName struct {
		pid  int64
		name string
	}
	var list []pidName
	for rows.Next() {
		var pn pidName
		if err = rows.Scan(&pn.pid, &pn.name); err != nil {
			rows.Close()
			return nil, nil, err
		}
		list = append(list, pn)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, nil, err
	}
	rows.Close()
	var roles []roleInfo
	var profiles []Profile
	for _, pn := range list {
		var uuidHex string
		var version int64
		err := tx.QueryRowContext(ctx, "SELECT uuid,version FROM "+s.Store.Table("go_uuid_bindings")+" WHERE pid=? FOR UPDATE", pn.pid).Scan(&uuidHex, &version)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, errors.New("yggdrasil: player binding missing; run player binding migration")
		}
		if err != nil {
			return nil, nil, err
		}
		dashed, ok := hexToDashed(uuidHex)
		if !ok {
			return nil, nil, errors.New("yggdrasil: stored player binding is malformed")
		}
		roles = append(roles, roleInfo{PID: pn.pid, Name: pn.name, UUIDDashed: dashed, UUIDHex: uuidHex, BindingVersion: version})
		profiles = append(profiles, Profile{ID: uuidHex, Name: pn.name})
	}
	if profiles == nil {
		profiles = []Profile{}
	}
	return roles, profiles, nil
}

// --- token persistence ------------------------------------------------------

func (s *Service) insertToken(ctx context.Context, tx *sql.Tx, digest []byte, uid, version int64, clientToken string, sel *roleInfo, yggt string, now time.Time, accessSec, refreshSec int64) error {
	var selPID any
	var selUUID any
	var bindVer any
	if sel != nil {
		selPID = sel.PID
		selUUID = sel.UUIDDashed
		bindVer = sel.BindingVersion
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("go_yggdrasil_tokens")+" (digest,user_uid,version,client_token,selected_pid,selected_uuid,binding_version,yggt,created_at,access_until,refresh_until) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
		digest, uid, version, clientToken, selPID, selUUID, bindVer, yggt, now.Unix(), now.Unix()+accessSec, now.Unix()+refreshSec)
	return err
}

func (s *Service) loadTokenForUpdate(ctx context.Context, tx *sql.Tx, digest []byte) (*tokenRow, error) {
	row := tx.QueryRowContext(ctx, "SELECT "+tokenColumns+" FROM "+s.Store.Table("go_yggdrasil_tokens")+" WHERE digest=? FOR UPDATE", digest)
	t, err := scanToken(row)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// tokenTTL reads both expiry windows without defaults: missing means 0.
func (s *Service) tokenTTL(opts map[string]any) (accessSec, refreshSec int64) {
	raw1, p1 := optionPresent(opts, "ygg_token_expire_1")
	raw2, p2 := optionPresent(opts, "ygg_token_expire_2")
	return optionInt(raw1, p1), optionInt(raw2, p2)
}

func (s *Service) tokenLimit(opts map[string]any) int64 {
	raw, present := optionPresent(opts, "ygg_tokens_limit")
	if !present {
		return 10
	}
	return optionInt(raw, present)
}

// concatDigest is the deterministic join key basis (batch3 uses it).
func concatDigest(parts ...string) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

// --- authenticate -----------------------------------------------------------

// Authenticate issues one access token after a shared password proof. The
// username throttle runs first; sign-in admission is the shared identity
// gate inside the password proof. A failed proof never writes token state.
func (s *Service) Authenticate(ctx context.Context, req AuthenticateRequest) (*AuthenticateResult, error) {
	if req.Username == "" || req.Password == "" {
		return nil, ErrAuthEmpty
	}
	if err := s.EnforceRateLimit(ctx, req.Username); err != nil {
		return nil, err
	}
	opts, err := s.opts.load(ctx)
	if err != nil {
		return nil, err
	}
	var result *AuthenticateResult
	err = s.Identity.WithYggdrasilPassword(ctx, req.Username, req.Password, identity.PasswordIntentAuthenticate, func(proof *identity.PasswordProof) error {
		return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
			if err := s.lockModuleState(ctx, tx); err != nil {
				return err
			}
			u, err := s.lockUser(ctx, tx, proof.UID())
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return AuthNotExistedError(req.Username)
				}
				return err
			}
			if u.Permission < 0 {
				return ErrUserBanned
			}
			if err := s.requireVerified(opts, u); err != nil {
				return err
			}
			uid, err := s.Identity.RecheckGamePasswordTx(ctx, tx, proof)
			if err != nil {
				if errors.Is(err, identity.ErrStale) {
					return ErrAuthNotMatched
				}
				if errors.Is(err, identity.ErrNoVersion) {
					// Fresh issuance may initialize the missing version.
					// lockUser already holds the row lock, so the
					// VersionTx init is safe here.
					if _, err := s.Identity.VersionTx(ctx, tx, u.UID); err != nil {
						return err
					}
					uid = &identity.User{UID: u.UID, Email: u.Email, Nickname: "", Permission: u.Permission, Verified: u.Verified}
				} else {
					return err
				}
			}
			if uid == nil {
				return ErrAuthNotMatched
			}
			// Identification is already rechecked inside
			// RecheckGamePasswordTx; load the current role set now.
			roles, profiles, err := s.loadRoles(ctx, tx, u.UID)
			if err != nil {
				return err
			}
			version := proof.Version()
			if version == 0 {
				version = 1
			}
			if !proof.VersionExists() {
				version = 1
			}
			clientToken := ""
			if req.ClientToken == nil {
				clientToken = newClientToken()
			} else {
				clientToken = *req.ClientToken
			}
			accessSec, refreshSec := s.tokenTTL(opts)
			now := s.now()
			var selected *roleInfo
			if len(roles) == 1 {
				r := roles[0]
				selected = &r
			}
			selStr := ""
			if selected != nil {
				selStr = selected.UUIDDashed
			}
			accessToken, yggt, err := s.jwt.sign(u.UID, selStr, now, accessSec)
			if err != nil {
				return err
			}
			digest := tokenDigest(accessToken)
			if err := s.insertToken(ctx, tx, digest, u.UID, version, clientToken, selected, yggt, now, accessSec, refreshSec); err != nil {
				return err
			}
			result = &AuthenticateResult{AccessToken: accessToken, ClientToken: clientToken, AvailableProfiles: profiles}
			if selected != nil {
				sel := Profile{ID: selected.UUIDHex, Name: selected.Name}
				result.SelectedProfile = &sel
			}
			if req.RequestUser {
				result.User = &User{ID: userUUIDv5(u.Email), Properties: []any{}}
			}
			if err := s.evictOldest(ctx, tx, u.UID, s.tokenLimit(opts), digest); err != nil {
				return err
			}
			return s.insertLogTx(ctx, tx, yggLogEntry{Action: "authenticate", UserID: u.UID, IP: req.ClientIP, Time: now, Parameters: map[string]any{"clientTokenPresent": req.ClientToken != nil, "requestUser": req.RequestUser}})
		})
	})
	if err != nil {
		if errors.Is(err, identity.ErrBanned) {
			return nil, ErrUserBanned
		}
		// ErrNoAccount wraps ErrCredentials (identity), so it must be
		// checked first or the auth.not-existed refusal is unreachable.
		if errors.Is(err, identity.ErrNoAccount) {
			return nil, AuthNotExistedError(req.Username)
		}
		if errors.Is(err, identity.ErrCredentials) {
			return nil, ErrAuthNotMatched
		}
		return nil, err
	}
	return result, nil
}

// evictOldest drops at most one oldest pre-existing token when the UID
// was at or over the limit before the new issuance, mirroring the legacy
// queue shift: the freshly inserted token is never a candidate. With
// limit <= 0 every prior token is dropped, leaving exactly one.
func (s *Service) evictOldest(ctx context.Context, tx *sql.Tx, uid int64, limit int64, newDigest []byte) error {
	rows, err := tx.QueryContext(ctx, "SELECT digest FROM "+s.Store.Table("go_yggdrasil_tokens")+" WHERE user_uid=? ORDER BY issuance_order", uid)
	if err != nil {
		return err
	}
	var digests [][]byte
	for rows.Next() {
		var d []byte
		if err = rows.Scan(&d); err != nil {
			rows.Close()
			return err
		}
		digests = append(digests, d)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	var prior [][]byte
	for _, d := range digests {
		if string(d) != string(newDigest) {
			prior = append(prior, d)
		}
	}
	if int64(len(prior)) >= limit && len(prior) > 0 {
		_, err = tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("go_yggdrasil_tokens")+" WHERE digest=?", prior[0])
		return err
	}
	return nil
}

// --- refresh ----------------------------------------------------------------

// Refresh rotates one token without rechecking the password. The access
// expiry does not block a refresh inside the independent refresh window.
// A clientToken mismatch reports 403 without consuming the stored token.
func (s *Service) Refresh(ctx context.Context, req RefreshRequest) (*RefreshResult, error) {
	if req.AccessToken == "" {
		return nil, ErrTokenInvalid
	}
	cl, err := s.jwt.parse(req.AccessToken)
	if err != nil {
		return nil, ErrTokenInvalid
	}
	uidFromJWT, err := parseUID(cl.Subject)
	if err != nil {
		return nil, ErrTokenInvalid
	}
	opts, err := s.opts.load(ctx)
	if err != nil {
		return nil, err
	}
	var result *RefreshResult
	err = s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if err := s.lockModuleState(ctx, tx); err != nil {
			return err
		}
		// Frozen lock order: users -> version -> token. The verified JWT
		// subject selects the user/version to lock first; the token row
		// is then locked and must still name that UID and version. The
		// deferred missing flags preserve the original error priority:
		// token absence/expiry/UID mismatch precede user/version refusals,
		// and banned precedes the version comparison.
		u, version, userMissing, versionMissing, err := s.lockUserAndVersion(ctx, tx, uidFromJWT)
		if err != nil {
			return err
		}
		tok, err := s.loadTokenForUpdate(ctx, tx, tokenDigest(req.AccessToken))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrTokenInvalid
			}
			return err
		}
		now := s.now()
		if now.Unix() > tok.RefreshUntil {
			return ErrTokenInvalid
		}
		if tok.UserUID != uidFromJWT {
			return ErrTokenInvalid
		}
		if userMissing {
			return ErrTokenInvalid
		}
		if u.Permission < 0 {
			return ErrUserBanned
		}
		if versionMissing || version != tok.Version {
			return ErrTokenInvalid
		}
		storedClient := tok.ClientToken
		if req.ClientToken != nil && phpTruthy(*req.ClientToken) && *req.ClientToken != storedClient {
			return ErrTokenNotMatched
		}
		roles, profiles, err := s.loadRoles(ctx, tx, u.UID)
		if err != nil {
			return err
		}
		var selected *roleInfo
		if req.SelectedProfile != nil {
			selRole, selErr := s.resolveSelected(ctx, tx, u.UID, roles, tok, req.SelectedProfile)
			if selErr != nil {
				return selErr
			}
			selected = selRole
		} else if tok.HasSelected {
			// Retain only a still-current bound selection.
			for i := range roles {
				if roles[i].PID == tok.SelectedPID && roles[i].UUIDDashed == tok.SelectedUUID && roles[i].BindingVersion == tok.BindingVersion {
					selected = &roles[i]
					break
				}
			}
		}
		accessSec, refreshSec := s.tokenTTL(opts)
		selStr := ""
		if selected != nil {
			selStr = selected.UUIDDashed
		}
		accessToken, yggt, err := s.jwt.sign(u.UID, selStr, now, accessSec)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("go_yggdrasil_tokens")+" WHERE digest=?", tokenDigest(req.AccessToken)); err != nil {
			return err
		}
		if err := s.insertToken(ctx, tx, tokenDigest(accessToken), u.UID, version, storedClient, selected, yggt, now, accessSec, refreshSec); err != nil {
			return err
		}
		result = &RefreshResult{AccessToken: accessToken, ClientToken: storedClient, AvailableProfiles: profiles}
		if selected != nil {
			sel := Profile{ID: selected.UUIDHex, Name: selected.Name}
			result.SelectedProfile = &sel
		}
		result.User = &User{ID: userUUIDv5(u.Email), Properties: []any{}}
		return s.insertLogTx(ctx, tx, yggLogEntry{Action: "refresh", UserID: u.UID, IP: req.ClientIP, Time: now, Parameters: map[string]any{"clientTokenPresent": req.ClientToken != nil}})
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// resolveSelected validates a client-supplied selected profile against the
// current role set and the token's bound selection.
func (s *Service) resolveSelected(ctx context.Context, tx *sql.Tx, uid int64, roles []roleInfo, tok *tokenRow, in *SelectedProfileInput) (*roleInfo, error) {
	// Existence: any player with that name anywhere.
	var foundPID int64
	var foundUID int64
	err := tx.QueryRowContext(ctx, "SELECT pid,uid FROM "+s.Store.Table("players")+" WHERE name=? LIMIT 1", in.Name).Scan(&foundPID, &foundUID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPlayerNotExisted
	}
	if err != nil {
		return nil, err
	}
	if tok.HasSelected && in.ID != tok.SelectedUUID {
		return nil, ErrPlayerNotMatched
	}
	// Must belong to the current role set with matching id.
	var match *roleInfo
	for i := range roles {
		if roles[i].Name == in.Name && roles[i].UUIDDashed == MustDashed(in.ID) {
			match = &roles[i]
			break
		}
	}
	if match == nil {
		// Distinguish: owned player with wrong id vs foreign player.
		for _, r := range roles {
			if r.Name == in.Name {
				return nil, ErrPlayerNotMatched
			}
		}
		return nil, ErrPlayerOwner
	}
	return match, nil
}

func parseUID(sub string) (int64, error) {
	var n int64
	_, err := scanInt(sub, &n)
	return n, err
}

func scanInt(s string, out *int64) (int, error) {
	if s == "" {
		return 0, errInvalidToken
	}
	n, err := parseDecimal(s)
	if err != nil {
		return 0, errInvalidToken
	}
	*out = n
	return len(s), nil
}

// --- validate / invalidate ---------------------------------------------------

// Validate checks signature, issuer, subject, access window, refresh
// window, current user/version and the ban state. A clientToken mismatch
// is a separate 403 and never invalidates the token.
func (s *Service) Validate(ctx context.Context, req ValidateRequest) error {
	if req.AccessToken == "" {
		return ErrTokenInvalid
	}
	cl, err := s.jwt.parse(req.AccessToken)
	if err != nil {
		return ErrTokenInvalid
	}
	uid, err := parseUID(cl.Subject)
	if err != nil {
		return ErrTokenInvalid
	}
	now := s.now()
	if now.Unix() > cl.ExpiresAt {
		return ErrTokenInvalid
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if err := s.lockModuleState(ctx, tx); err != nil {
			return err
		}
		// Frozen lock order: users -> version -> token (see Refresh).
		// Deferred missing flags preserve the original priority: token
		// absence/expiry/UID mismatch and the clientToken check precede
		// user/version refusals; banned precedes the version comparison.
		u, version, userMissing, versionMissing, err := s.lockUserAndVersion(ctx, tx, uid)
		if err != nil {
			return err
		}
		tok, err := s.loadTokenForUpdate(ctx, tx, tokenDigest(req.AccessToken))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrTokenInvalid
			}
			return err
		}
		if now.Unix() > tok.AccessUntil || now.Unix() > tok.RefreshUntil {
			return ErrTokenInvalid
		}
		if tok.UserUID != uid {
			return ErrTokenInvalid
		}
		if req.ClientToken != nil && phpTruthy(*req.ClientToken) && *req.ClientToken != tok.ClientToken {
			return ErrTokenNotMatched
		}
		if userMissing {
			return ErrTokenInvalid
		}
		if u.Permission < 0 {
			return ErrUserBanned
		}
		if versionMissing || version != tok.Version {
			return ErrTokenInvalid
		}
		return s.insertLogTx(ctx, tx, yggLogEntry{Action: "validate", UserID: u.UID, IP: req.ClientIP, Time: now, Parameters: map[string]any{"clientTokenPresent": req.ClientToken != nil}})
	})
}

// Invalidate deletes one token by digest. Unknown tokens are a successful
// no-op (idempotent 204). The clientToken is never compared here.
func (s *Service) Invalidate(ctx context.Context, req InvalidateRequest) error {
	if req.AccessToken == "" {
		return nil
	}
	now := s.now()
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if err := s.lockModuleState(ctx, tx); err != nil {
			return err
		}
		tok, err := s.loadTokenForUpdate(ctx, tx, tokenDigest(req.AccessToken))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("go_yggdrasil_tokens")+" WHERE digest=?", tokenDigest(req.AccessToken)); err != nil {
			return err
		}
		return s.insertLogTx(ctx, tx, yggLogEntry{Action: "invalidate", UserID: tok.UserUID, IP: req.ClientIP, Time: now, Parameters: map[string]any{}})
	})
}

// --- signout -----------------------------------------------------------------

// Signout revokes every game token and join ticket of the account. The
// throttle and the shared password proof run first; signout allows banned
// accounts but still requires verification. An account without a version
// row has no revokable Go state and is left untouched.
func (s *Service) Signout(ctx context.Context, req SignoutRequest) error {
	if req.Username == "" || req.Password == "" {
		return ErrAuthEmpty
	}
	if err := s.EnforceRateLimit(ctx, req.Username); err != nil {
		return err
	}
	opts, err := s.opts.load(ctx)
	if err != nil {
		return err
	}
	err = s.Identity.WithYggdrasilPassword(ctx, req.Username, req.Password, identity.PasswordIntentSignout, func(proof *identity.PasswordProof) error {
		return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
			if err := s.lockModuleState(ctx, tx); err != nil {
				return err
			}
			u, err := s.lockUser(ctx, tx, proof.UID())
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return AuthNotExistedError(req.Username)
				}
				return err
			}
			// Banned is explicitly allowed for signout.
			if err := s.requireVerified(opts, u); err != nil {
				return err
			}
			if _, err := s.Identity.RecheckGamePasswordTx(ctx, tx, proof); err != nil {
				if errors.Is(err, identity.ErrStale) {
					return ErrAuthNotMatched
				}
				if errors.Is(err, identity.ErrNoVersion) {
					// No Go auth state exists for this account;
					// succeed without creating it.
					return s.insertLogTx(ctx, tx, yggLogEntry{Action: "signout", UserID: u.UID, IP: req.ClientIP, Time: s.now(), Parameters: map[string]any{}})
				}
				return err
			}
			now := s.now()
			if _, err := tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("go_yggdrasil_tokens")+" WHERE user_uid=?", u.UID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("go_yggdrasil_joins")+" WHERE user_uid=?", u.UID); err != nil {
				return err
			}
			return s.insertLogTx(ctx, tx, yggLogEntry{Action: "signout", UserID: u.UID, IP: req.ClientIP, Time: now, Parameters: map[string]any{}})
		})
	})
	if err != nil {
		// ErrNoAccount wraps ErrCredentials (identity), so it must be
		// checked first or the auth.not-existed refusal is unreachable.
		if errors.Is(err, identity.ErrNoAccount) {
			return AuthNotExistedError(req.Username)
		}
		if errors.Is(err, identity.ErrCredentials) {
			return ErrAuthNotMatched
		}
		return err
	}
	return nil
}
