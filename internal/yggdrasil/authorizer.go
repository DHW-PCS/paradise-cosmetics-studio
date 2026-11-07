package yggdrasil

import (
	"context"
	"database/sql"
	"errors"

	"blessing-skin-go/internal/gameauth"
)

// VerifyBearerToken performs the pre-transaction Bearer check for the
// texture upload/reset routes: JWT signature, issuer, subject and access
// window plus a current token-row read. It returns the credential context
// for GameUpload/GameReset, which recheck it inside the business
// transaction through RecheckCredentialTx/RecheckProfileTx; this call is
// never the final authorization. Any failure is the legacy Bearer refusal.
func (s *Service) VerifyBearerToken(ctx context.Context, accessToken string) (gameauth.GameAuth, error) {
	if accessToken == "" {
		return gameauth.GameAuth{}, ErrBearer
	}
	cl, err := s.jwt.parse(accessToken)
	if err != nil {
		return gameauth.GameAuth{}, ErrBearer
	}
	uid, err := parseUID(cl.Subject)
	if err != nil {
		return gameauth.GameAuth{}, ErrBearer
	}
	now := s.now()
	if now.Unix() > cl.ExpiresAt {
		return gameauth.GameAuth{}, ErrBearer
	}
	var creds gameauth.GameAuth
	err = s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if err := s.lockModuleState(ctx, tx); err != nil {
			return err
		}
		tok, user, version, verr := s.verifyTokenTx(ctx, tx, accessToken, now)
		if verr != nil {
			return verr
		}
		_ = tok
		creds = gameauth.GameAuth{UID: uid, Version: version, Permission: user.Permission, Banned: user.Permission < 0, AccessToken: accessToken}
		return nil
	})
	if err != nil {
		if apiErr, ok := err.(*APIError); ok && apiErr == ErrTokenInvalid {
			return gameauth.GameAuth{}, ErrBearer
		}
		if apiErr, ok := err.(*APIError); ok && apiErr == ErrUserBanned {
			return gameauth.GameAuth{}, ErrUserBanned
		}
		// SQL faults stay service errors; protocol refusals above are
		// already mapped to Bearer/banned.
		if _, ok := err.(*APIError); ok {
			return gameauth.GameAuth{}, ErrBearer
		}
		return gameauth.GameAuth{}, err
	}
	return creds, nil
}

// verifyTokenTx is the shared current-read token check: token row,
// access/refresh windows, locked user, ban state and locked auth version.
// It returns the token row, the current user and the current version.
func (s *Service) verifyTokenTx(ctx context.Context, tx *sql.Tx, accessToken string, now interface{ Unix() int64 }) (*tokenRow, *currentUser, int64, error) {
	cl, err := s.jwt.parse(accessToken)
	if err != nil {
		return nil, nil, 0, ErrBearer
	}
	uid, err := parseUID(cl.Subject)
	if err != nil {
		return nil, nil, 0, ErrBearer
	}
	if now.Unix() > cl.ExpiresAt {
		return nil, nil, 0, ErrBearer
	}
	// Frozen lock order: users -> version -> token (see
	// lockUserAndVersion). The verified JWT subject selects the
	// user/version to lock first; the locked DB token row remains
	// authoritative for UID/version. Deferred missing flags preserve
	// the original priority: token/window/UID refusals precede
	// user/version refusals, and banned precedes version comparison.
	user, version, userMissing, versionMissing, err := s.lockUserAndVersion(ctx, tx, uid)
	if err != nil {
		return nil, nil, 0, err
	}
	tok, err := s.loadTokenForUpdate(ctx, tx, tokenDigest(accessToken))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, 0, ErrBearer
		}
		return nil, nil, 0, err
	}
	if now.Unix() > tok.AccessUntil || now.Unix() > tok.RefreshUntil {
		return nil, nil, 0, ErrBearer
	}
	if tok.UserUID != uid {
		return nil, nil, 0, ErrBearer
	}
	if userMissing {
		return nil, nil, 0, ErrBearer
	}
	if user.Permission < 0 {
		return nil, nil, 0, ErrUserBanned
	}
	if versionMissing || version != tok.Version {
		return nil, nil, 0, ErrBearer
	}
	return tok, user, version, nil
}

// RecheckCredentialTx is the credential stage of the real Authorizer: the
// current version and token row are locked and checked against the JWT
// proof. It deliberately does not lock any player or binding row;
// GameUpload/GameReset call it after the users locks and before
// the texture/closet reads. The snapshot Permission/Banned fields of
// GameAuth are not used as the current conclusion.
func (s *Service) RecheckCredentialTx(ctx context.Context, tx *sql.Tx, creds gameauth.GameAuth) error {
	// The shared module-state lock is re-asserted here so a business
	// transaction that entered through the authorizer (GameUpload /
	// GameReset) holds it until commit even when the players hook was
	// not wired; re-locking in the same transaction is a no-op.
	if err := s.lockModuleState(ctx, tx); err != nil {
		return err
	}
	if creds.AccessToken == "" {
		return ErrBearer
	}
	tok, user, version, err := s.verifyTokenTx(ctx, tx, creds.AccessToken, s.now())
	if err != nil {
		return err
	}
	if creds.UID != 0 && creds.UID != user.UID {
		return ErrBearer
	}
	if creds.Version != 0 && creds.Version != version {
		return ErrBearer
	}
	_ = tok
	return nil
}

// RecheckProfileTx is the profile stage: the current player row and its
// UUID binding are locked (the same current-read the players package
// exposes as LockBindingTx) and the target proof is rechecked. The target
// is not required to equal the token's selected profile; selected-profile
// contracts belong to join/hasJoined/refresh only.
func (s *Service) RecheckProfileTx(ctx context.Context, tx *sql.Tx, creds gameauth.GameAuth, pid int64) error {
	var owner int64
	var name string
	if err := tx.QueryRowContext(ctx, "SELECT uid,name FROM "+s.Store.Table("players")+" WHERE pid=? FOR UPDATE", pid).Scan(&owner, &name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPlayerNotFound404
		}
		return err
	}
	binding, err := s.lockBindingTx(ctx, tx, pid)
	if err != nil {
		return err
	}
	if binding == nil {
		return ErrPlayerNotFound404
	}
	if owner != creds.UID {
		return ErrPlayerOwner
	}
	// Target proof: an explicit ProfileUUID wins; otherwise a UUID-form
	// Profile is compared as UUID, and any other Profile as the name.
	target := creds.ProfileUUID
	if target == "" {
		target = creds.Profile
	}
	if hex, ok := normalizeUUIDHex(target); ok {
		if hex != binding.UUIDHex {
			return ErrPlayerNotMatched
		}
		return nil
	}
	if creds.Profile != "" && creds.Profile != name {
		return ErrPlayerNotMatched
	}
	return nil
}

// Recheck runs both stages in sequence for direct callers. GameUpload and
// GameReset prefer the split stages when both are implemented, so the
// texture/closet reads can sit between them.
func (s *Service) Recheck(ctx context.Context, tx *sql.Tx, creds gameauth.GameAuth, pid int64) error {
	if err := s.RecheckCredentialTx(ctx, tx, creds); err != nil {
		return err
	}
	return s.RecheckProfileTx(ctx, tx, creds, pid)
}

// lockBindingTx is the locking current read of one binding row. It is the
// same FOR UPDATE read as players LockBindingTx, kept inside this package
// so players never has to import yggdrasil.
func (s *Service) lockBindingTx(ctx context.Context, tx *sql.Tx, pid int64) (*roleInfo, error) {
	var uuidHex string
	var version int64
	err := tx.QueryRowContext(ctx, "SELECT uuid,version FROM "+s.Store.Table("go_uuid_bindings")+" WHERE pid=? FOR UPDATE", pid).Scan(&uuidHex, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	dashed, ok := hexToDashed(uuidHex)
	if !ok {
		return nil, errors.New("yggdrasil: stored player binding is malformed")
	}
	return &roleInfo{PID: pid, UUIDDashed: dashed, UUIDHex: uuidHex, BindingVersion: version}, nil
}

// normalizeUUIDHex converts a dashed or hex UUID to lowercase hex form.
func normalizeUUIDHex(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	clean := make([]byte, 0, 32)
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '-' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			clean = append(clean, c)
			continue
		}
		return "", false
	}
	if len(clean) != 32 {
		return "", false
	}
	return string(clean), true
}
