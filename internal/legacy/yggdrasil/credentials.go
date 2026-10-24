package yggdrasil

import (
	"blessing-skin-go/internal/legacy/password"
	"blessing-skin-go/internal/legacy/users"
	"context"
)

// SignoutCredentials preserves the native player-name/email lookup and permits
// banned users to revoke their own game tokens. Verification policy still
// applies. UID-based ledger revocation survives email changes and stale indexes.
func (s *Store) SignoutCredentials(ctx context.Context, repo *users.Repo, hasher *password.Hasher, identification, raw string, requireVerification bool) error {
	var user *users.User
	var ok bool
	var e error
	if users.EmailLooksLikeEmail(identification) {
		user, ok, e = repo.ByEmail(ctx, identification)
	} else {
		user, ok, e = repo.ByPlayerName(ctx, identification)
	}
	if e != nil {
		return e
	}
	if !ok {
		return ErrDenied
	}
	passed, e := hasher.Verify(raw, user.Password)
	if e != nil {
		return e
	}
	if !passed || (requireVerification && !user.Verified) {
		return ErrDenied
	}
	return s.Signout(ctx, user.UID)
}
