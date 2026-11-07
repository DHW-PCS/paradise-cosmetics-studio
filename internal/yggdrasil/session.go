package yggdrasil

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
)

// JoinServerRequest is the session/minecraft/join input. SelectedProfile
// is the client-selected profile id in dashed or hex UUID form; the legacy
// uuid lookup has no other accepted form.
type JoinServerRequest struct {
	AccessToken     string
	SelectedProfile string
	ServerID        string
	ClientIP        string
}

// JoinServer writes the 120-second join ticket for the token's selected
// profile. Lock order: discovery (UUID -> binding -> player -> owner) ->
// users -> version -> token -> player/binding -> join row. The selected
// proof must still be the current binding: a rename/transfer that bumped
// the binding version invalidates the old selected binding here, exactly
// as refresh drops it. No Mojang fallback is attempted.
func (s *Service) JoinServer(ctx context.Context, req JoinServerRequest) error {
	if req.AccessToken == "" {
		return ErrTokenMissing
	}
	cl, err := s.jwt.parse(req.AccessToken)
	if err != nil {
		return ErrTokenMissing
	}
	if _, err := parseUID(cl.Subject); err != nil {
		return ErrTokenMissing
	}
	disc, err := s.discoverByUUID(ctx, req.SelectedProfile)
	if err != nil {
		if errors.Is(err, errProfileNotFound) {
			return UUIDInvalidError(req.SelectedProfile)
		}
		return err
	}
	now := s.now()
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if err := s.lockModuleState(ctx, tx); err != nil {
			return err
		}
		user, err := s.lockUser(ctx, tx, disc.UID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrTokenMissing
			}
			return err
		}
		var version int64
		if err := tx.QueryRowContext(ctx, "SELECT version FROM "+s.Store.Table("go_auth_versions")+" WHERE user_uid=? FOR UPDATE", user.UID).Scan(&version); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrTokenMissing
			}
			return err
		}
		tok, err := s.loadTokenForUpdate(ctx, tx, tokenDigest(req.AccessToken))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrTokenMissing
			}
			return err
		}
		if now.Unix() > tok.AccessUntil || now.Unix() > tok.RefreshUntil {
			return ErrTokenMissing
		}
		// Legacy join compares the token's bound profileId with the
		// requested profile before any owner conclusion: a token with
		// no (or a different) selected profile is player.not-matched
		// even when it belongs to another account.
		if !tok.HasSelected || MustDashed(req.SelectedProfile) != tok.SelectedUUID {
			return ErrPlayerNotMatchedForbidden
		}
		if tok.UserUID != user.UID || tok.Version != version {
			return ErrTokenMissing
		}
		if user.Permission < 0 {
			return ErrUserBanned
		}
		// Current player/binding re-read; the token's bound version must
		// still be the current version.
		var owner int64
		if err := tx.QueryRowContext(ctx, "SELECT uid FROM "+s.Store.Table("players")+" WHERE pid=? FOR UPDATE", disc.PID).Scan(&owner); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return UUIDInvalidError(req.SelectedProfile)
			}
			return err
		}
		if owner != user.UID {
			return ErrPlayerOwner
		}
		binding, err := s.lockBindingTx(ctx, tx, disc.PID)
		if err != nil {
			return err
		}
		if binding == nil || binding.UUIDHex != disc.UUIDHex {
			return UUIDInvalidError(req.SelectedProfile)
		}
		if !tok.HasBindingVer || tok.BindingVersion != binding.BindingVersion {
			return ErrPlayerNotMatchedForbidden
		}
		digest := concatDigest(strconv.FormatInt(disc.PID, 10), binding.UUIDHex, req.ServerID)
		_, err = tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("go_yggdrasil_joins")+" (digest,pid,profile_uuid,binding_version,user_uid,version,token_digest,server_id,ip,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE pid=VALUES(pid),profile_uuid=VALUES(profile_uuid),binding_version=VALUES(binding_version),user_uid=VALUES(user_uid),version=VALUES(version),token_digest=VALUES(token_digest),server_id=VALUES(server_id),ip=VALUES(ip),expires_at=VALUES(expires_at)",
			digest, disc.PID, binding.UUIDHex, binding.BindingVersion, user.UID, version, tokenDigest(req.AccessToken), req.ServerID, req.ClientIP, now.Unix()+120)
		if err != nil {
			return err
		}
		return s.insertLogTx(ctx, tx, yggLogEntry{Action: "join", UserID: user.UID, PlayerID: disc.PID, IP: req.ClientIP, Time: now, Parameters: map[string]any{"selectedProfile": binding.UUIDDashed, "profileId": disc.PID}})
	})
}

// HasJoinedServerRequest is the session/minecraft/hasJoined input.
type HasJoinedServerRequest struct {
	Username string
	ServerID string
	IP       *string
}

// HasJoinedServer returns the signed profile when a live join ticket for
// the named player on this server still matches every locked field, and
// (nil, false, nil) for the legacy 204 cases: no ticket, expired ticket,
// IP mismatch, name mismatch, or any stale token/binding association.
// SQL faults and RSA key failures are returned as errors, never 204.
//
// Frozen lock order: users -> version -> token -> player/binding -> join.
// The unlocked discovery only plans the work: it names the profile and
// reads the join row's token_digest without locking. Inside the
// transaction the token for that digest and the player/binding are
// locked before the join row, and the join row is then re-read with
// FOR UPDATE as the final current-read: every join field, including
// token_digest and binding_version, must still match the locked state.
// A join row that changed after discovery therefore yields the legacy
// 204 rather than being trusted from the unlocked read.
func (s *Service) HasJoinedServer(ctx context.Context, req HasJoinedServerRequest) (*SerializedProfile, bool, error) {
	disc, err := s.discoverByName(ctx, req.Username)
	if err != nil {
		if errors.Is(err, errProfileNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	now := s.now()
	digest := concatDigest(strconv.FormatInt(disc.PID, 10), disc.UUIDHex, req.ServerID)
	// Discovery (unlocked, plan only): which token the ticket names.
	var discTokenDigest []byte
	err = s.Store.DB.QueryRowContext(ctx, "SELECT token_digest FROM "+s.Store.Table("go_yggdrasil_joins")+" WHERE digest=?", digest).Scan(&discTokenDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var matched bool
	var doc *SerializedProfile
	err = s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if err := s.lockModuleState(ctx, tx); err != nil {
			return err
		}
		user, version, userMissing, versionMissing, err := s.lockUserAndVersion(ctx, tx, disc.UID)
		if err != nil {
			return err
		}
		if userMissing || versionMissing {
			return nil
		}
		// Current token associated with the ticket. The DB token row
		// is authoritative for UID/version; discovery only selected it.
		tok, err := s.loadTokenForUpdate(ctx, tx, discTokenDigest)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		if tok.UserUID != disc.UID || tok.Version != version {
			return nil
		}
		if now.Unix() > tok.AccessUntil || now.Unix() > tok.RefreshUntil {
			return nil
		}
		if user.Permission < 0 {
			return nil
		}
		// Current player/binding.
		var owner int64
		var name string
		var tidSkin, tidCape int64
		if err := tx.QueryRowContext(ctx, "SELECT uid,name,tid_skin,tid_cape FROM "+s.Store.Table("players")+" WHERE pid=? FOR UPDATE", disc.PID).Scan(&owner, &name, &tidSkin, &tidCape); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		if owner != disc.UID || name != req.Username {
			return nil
		}
		binding, err := s.lockBindingTx(ctx, tx, disc.PID)
		if err != nil {
			return err
		}
		if binding == nil || binding.UUIDHex != disc.UUIDHex {
			return nil
		}
		// Final current-read of the join row: it must still name this
		// profile, server, token and binding version exactly.
		var jDigest, jTokenDigest []byte
		var jPID, jBindingVersion, jUID, jVersion, jExpires int64
		var jUUID, jServerID string
		var jIP sql.NullString
		err = tx.QueryRowContext(ctx, "SELECT digest,pid,profile_uuid,binding_version,user_uid,version,token_digest,server_id,ip,expires_at FROM "+s.Store.Table("go_yggdrasil_joins")+" WHERE digest=? FOR UPDATE", digest).
			Scan(&jDigest, &jPID, &jUUID, &jBindingVersion, &jUID, &jVersion, &jTokenDigest, &jServerID, &jIP, &jExpires)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if jExpires < now.Unix() || jPID != disc.PID || jUUID != disc.UUIDHex || jBindingVersion != binding.BindingVersion || jUID != disc.UID || jVersion != version || jServerID != req.ServerID || string(jTokenDigest) != string(discTokenDigest) {
			return nil
		}
		if req.IP != nil && *req.IP != "" && jIP.String != *req.IP {
			return nil
		}
		skinHash, skinType, err := s.textureHashTypeTx(ctx, tx, tidSkin)
		if err != nil {
			return err
		}
		capeHash, _, err := s.textureHashTypeTx(ctx, tx, tidCape)
		if err != nil {
			return err
		}
		model := "default"
		if skinType != "" && skinType != "steve" {
			model = "slim"
		}
		opts, err := s.opts.load(ctx)
		if err != nil {
			return err
		}
		built, err := s.buildSerialized(binding.UUIDHex, name, skinHash, capeHash, model, opts, now, true)
		if err != nil {
			return err
		}
		matched = true
		doc = built
		return s.insertLogTx(ctx, tx, yggLogEntry{Action: "has_joined", UserID: user.UID, PlayerID: disc.PID, IP: nonzeroString(req.IP), Time: now, Parameters: map[string]any{"selectedProfile": binding.UUIDDashed, "profileId": disc.PID}})
	})
	if err != nil {
		return nil, false, err
	}
	return doc, matched, nil
}

func nonzeroString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
