// Package gameauth holds the shared game-credential seam between the
// core player business and the Yggdrasil verifier. It exists as its own
// package so neither side needs to import the other: players keeps type
// aliases for compatibility, and yggdrasil implements the stage
// interfaces against these exact types.
package gameauth

import (
	"context"
	"database/sql"
)

// GameAuth is the verified credential context handed to player business
// code. Profile is the player name, or (when ProfileUUID is empty and
// Profile parses as a UUID) the target UUID. ProfileUUID, when set, is
// the trusted target UUID parsed from the request in dashed or hex form
// and takes precedence for target discovery. AccessToken carries the raw
// game token for the real Yggdrasil verifier; test doubles ignore it.
// Snapshot Permission/Banned fields are never the current authorization
// conclusion; the in-transaction stages recheck the current state.
type GameAuth struct {
	UID         int64
	Version     int64
	Permission  int
	Banned      bool
	Profile     string
	ProfileUUID string
	AccessToken string
}

// Authorizer rechecks a synthetic game credential inside the business
// transaction. A nil authorizer is rejected, never treated as a bypass.
type Authorizer interface {
	Recheck(ctx context.Context, tx *sql.Tx, creds GameAuth, pid int64) error
}

// CredentialAuthorizer is the first authorization stage: lock and recheck
// the current auth version and game token inside the business
// transaction, without locking any profile or binding.
type CredentialAuthorizer interface {
	RecheckCredentialTx(ctx context.Context, tx *sql.Tx, creds GameAuth) error
}

// ProfileAuthorizer is the second stage: after the texture/closet reads
// (upload) the current player row and its UUID binding are locked and
// the target proof is rechecked. An Authorizer implementing only Recheck
// is called at this stage instead.
type ProfileAuthorizer interface {
	RecheckProfileTx(ctx context.Context, tx *sql.Tx, creds GameAuth, pid int64) error
}
