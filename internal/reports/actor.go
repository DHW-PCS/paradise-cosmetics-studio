// Actor entry points for M4-03 core APIs (admin reports slice).
//
// ManageActor is the frozen GET /admin/reports entry: scope is
// ReportsManagement.Read or ReportsManagement.ReadWrite (AnyOf), and
// the current admin permission is rechecked from the rechecked user.
// ReviewActor is the frozen PUT /admin/reports/{report} entry:
// scope is exactly ReportsManagement.ReadWrite, and all three
// actions (delete, ban, reject) are covered. The original Manage
// entry keeps its signature and semantics (the browser HTTP layer
// gates admin) and shares the manageTx kernel; the original Review
// entry is a browser wrapper for ReviewActor. Neither forges a
// BrowserSession for an OAuth actor.
//
// ReviewActor lock order: discovery -> hash (delete only) ->
// Actor.PrepareTx -> users ascending -> Actor.RecheckTx ->
// texture/closet/players (delete) or players (ban) -> report row. A
// non-PENDING report returns success with the current status after
// the permission check and changes nothing: no score, texture,
// ban or outbox writes run for any of the three actions. No
// verified check is added.
package reports

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"blessing-skin-go/internal/closet"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/textures"
	"blessing-skin-go/internal/users"
)

var (
	reportsManagementReadScope  = identity.ScopeRequirement{AnyOf: []string{"ReportsManagement.Read", "ReportsManagement.ReadWrite"}}
	reportsManagementWriteScope = identity.ScopeRequirement{AllOf: []string{"ReportsManagement.ReadWrite"}}
)

// TextureDeleteActorTx is the closet capability ReviewActor needs
// for the delete action when the texture still exists. The production
// implementation is *closet.Service. All methods borrow the caller's
// transaction without committing or requiring a BrowserSession.
// ReviewActor runs
// TextureDeleteParticipantsTx in the same transaction before
// PrepareTx, locks the returned hash with Textures.LockHash, merges
// the returned UIDs into its ascending users pre-lock, rechecks
// ReportsManagement.ReadWrite, then locks deletion resources before
// locking the report. DeleteTextureActorTx runs only after the report's
// current permission, participant and PENDING checks pass.
// Resource ErrNotFound/ErrConflict is deferred until that status check;
// SQL errors are always returned, including for non-PENDING reports.
type TextureDeleteActorTx interface {
	TextureDeleteParticipantsTx(ctx context.Context, tx *sql.Tx, tid int64) (hash string, uids []int64, err error)
	LockTextureDeleteResourcesTx(ctx context.Context, tx *sql.Tx, tid int64) error
	DeleteTextureActorTx(ctx context.Context, tx *sql.Tx, actor identity.Actor, tid int64) error
}

// recheckActor runs PrepareTx -> LockUsersTx -> RecheckTx in the
// caller's transaction and returns the current user.
func (s *Service) recheckActor(ctx context.Context, tx *sql.Tx, actor identity.Actor, req identity.ScopeRequirement, participants ...int64) (*identity.User, error) {
	if actor == nil || actor.UID() == 0 {
		return nil, identity.ErrSession
	}
	if err := actor.PrepareTx(ctx, tx); err != nil {
		return nil, err
	}
	all := append([]int64{actor.UID()}, participants...)
	if err := s.Identity.LockUsersTx(ctx, tx, all); err != nil {
		return nil, err
	}
	current, err := actor.RecheckTx(ctx, tx, req)
	if err != nil {
		return nil, err
	}
	if current == nil || current.UID != actor.UID() {
		return nil, identity.ErrSession
	}
	return current, nil
}

// lockedPermission reads the current permission of a user already
// locked by the ascending pre-lock.
func (s *Service) lockedPermission(ctx context.Context, tx *sql.Tx, uid int64) (int, error) {
	var permission int
	if err := tx.QueryRowContext(ctx, "SELECT permission FROM "+s.Store.Table("users")+" WHERE uid=? FOR UPDATE", uid).Scan(&permission); errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	} else if err != nil {
		return 0, err
	}
	return permission, nil
}

// lockUploaderPlayersTx locks ban timestamp targets before the report row.
// The timestamp update waits until the report's PENDING check succeeds.
func (s *Service) lockUploaderPlayersTx(ctx context.Context, tx *sql.Tx, uid int64) error {
	rows, err := tx.QueryContext(ctx, "SELECT pid FROM "+s.Store.Table("players")+" WHERE uid=? ORDER BY pid FOR UPDATE", uid)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var pid int64
		if err := rows.Scan(&pid); err != nil {
			return err
		}
	}
	return rows.Err()
}

// ManageActor returns the frozen admin reports paginator for an
// admin Actor, authorized and read inside the single business
// transaction.
func (s *Service) ManageActor(ctx context.Context, actor identity.Actor, page int, query, path string) (*ManagePage, error) {
	var result *ManagePage
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		current, err := s.recheckActor(ctx, tx, actor, reportsManagementReadScope)
		if err != nil {
			return err
		}
		if current.Permission < 1 {
			return ErrNoPermission
		}
		result, err = s.manageTx(ctx, tx, page, query, path)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// textureTx reads one texture row inside tx, mirroring
// textures.Service.Get (including its missing-texture tolerance at
// the caller).
func (s *Service) textureTx(ctx context.Context, tx *sql.Tx, tid int64) (*textures.Texture, error) {
	var row textures.Texture
	var uploadAt time.Time
	err := tx.QueryRowContext(ctx, "SELECT tid,name,type,hash,size,uploader,public,upload_at,likes FROM "+s.Store.Table("textures")+" WHERE tid=?", tid).
		Scan(&row.TID, &row.Name, &row.Type, &row.Hash, &row.Size, &row.Uploader, &row.Public, &uploadAt, &row.Likes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, textures.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	row.UploadAt = uploadAt.In(s.Site.Location).Format("2006-01-02 15:04:05")
	return &row, nil
}

// briefTx reads one nested user row for the frozen manage serialization
// (legacy User toArray minus password/remember_token). A missing
// uploader/informer row is tolerated as nil, like the belongsTo
// relations.
func (s *Service) briefTx(ctx context.Context, tx *sql.Tx, uid int64) (*users.User, error) {
	var user users.User
	var lastSign, registered time.Time
	var locale sql.NullString
	err := tx.QueryRowContext(ctx, "SELECT uid,email,nickname,avatar,score,permission,ip,is_dark_mode,last_sign_at,register_at,verified,locale FROM "+s.Store.Table("users")+" WHERE uid=?", uid).
		Scan(&user.UID, &user.Email, &user.Nickname, &user.Avatar, &user.Score, &user.Permission, &user.IP, &user.IsDarkMode, &lastSign, &registered, &user.Verified, &locale)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if locale.Valid {
		value := locale.String
		user.Locale = &value
	}
	user.LastSignAt = lastSign.UTC().Format("2006-01-02T15:04:05.000000Z")
	user.RegisterAt = registered.UTC().Format("2006-01-02T15:04:05.000000Z")
	return &user, nil
}

// ReviewActor resolves a report exactly once for an admin Actor:
// reject, ban or delete. See the package comment for the
// non-PENDING and texture-delete semantics.
func (s *Service) ReviewActor(ctx context.Context, actor identity.Actor, id int64, action string) (ReviewResult, error) {
	if action != "delete" && action != "ban" && action != "reject" {
		return ReviewResult{}, ErrNoPermission
	}
	options, err := s.Site.Options(ctx)
	if err != nil {
		return ReviewResult{}, err
	}
	modification := site.Number(options["reporter_score_modification"])
	reward := site.Number(options["reporter_reward_score"])
	var result ReviewResult
	err = s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if actor == nil {
			return identity.ErrSession
		}
		// Discovery only fixes the participant set; it never authorizes.
		var discovered Report
		if err := tx.QueryRowContext(ctx, "SELECT id,tid,uploader,reporter,reason,status,report_at FROM "+s.Store.Table("reports")+" WHERE id=?", id).
			Scan(&discovered.ID, &discovered.TID, &discovered.Uploader, &discovered.Reporter, &discovered.Reason, &discovered.Status, new(time.Time)); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		participants := []int64{discovered.Uploader, discovered.Reporter}
		deleteResources := false
		if action == "delete" {
			// Closet deletion requires its participant discovery and
			// hash lock before PrepareTx, merged into the ascending
			// users pre-lock below. A missing texture needs neither:
			// the pending delete of an already-removed texture and
			// every non-PENDING outcome take their existing paths
			// after the recheck, with no closet writes.
			var exists int64
			if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("textures")+" WHERE tid=?", discovered.TID).Scan(&exists); err != nil {
				return err
			}
			if exists > 0 {
				hash, uids, err := s.Closet.TextureDeleteParticipantsTx(ctx, tx, discovered.TID)
				if err != nil {
					return err
				}
				if _, err := s.Textures.LockHash(ctx, tx, hash); err != nil {
					return err
				}
				participants = append(participants, uids...)
				deleteResources = true
			}
		}
		current, err := s.recheckActor(ctx, tx, actor, reportsManagementWriteScope, participants...)
		if err != nil {
			return err
		}
		var deleteLockErr error
		if deleteResources {
			deleteLockErr = s.Closet.LockTextureDeleteResourcesTx(ctx, tx, discovered.TID)
			if deleteLockErr != nil && !errors.Is(deleteLockErr, closet.ErrNotFound) && !errors.Is(deleteLockErr, closet.ErrConflict) {
				return deleteLockErr
			}
		} else if action == "ban" {
			if err := s.lockUploaderPlayersTx(ctx, tx, discovered.Uploader); err != nil {
				return err
			}
		}
		var report Report
		var at time.Time
		if err = tx.QueryRowContext(ctx, "SELECT id,tid,uploader,reporter,reason,status,report_at FROM "+s.Store.Table("reports")+" WHERE id=? FOR UPDATE", id).
			Scan(&report.ID, &report.TID, &report.Uploader, &report.Reporter, &report.Reason, &report.Status, &at); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if report.Uploader != discovered.Uploader || report.Reporter != discovered.Reporter || report.TID != discovered.TID {
			return identity.ErrStale
		}
		if current.Permission < 1 {
			return ErrNoPermission
		}
		if report.Status != Pending {
			result.Status = report.Status
			return nil
		}
		if deleteLockErr != nil {
			return deleteLockErr
		}
		if action == "reject" {
			if modification > 0 {
				if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score-? WHERE uid=?", modification, report.Reporter); err != nil {
					return err
				}
			}
			result.Status = Rejected
			_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("reports")+" SET status=? WHERE id=?", result.Status, id)
			return err
		}
		if action == "ban" {
			permission, err := s.lockedPermission(ctx, tx, report.Uploader)
			if err != nil {
				return err
			}
			if current.Permission <= permission {
				// Frozen ReportController::review treats an actor who is
				// not strictly above the uploader as a business rejection
				// (200 + code 1), not as a forbidden-request error.
				return ErrBanOutranking
			}
			if err = s.Identity.RevokeUID(ctx, tx, report.Uploader); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET permission=-1 WHERE uid=?", report.Uploader); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("players")+" SET last_modified=? WHERE uid=?", s.Now().In(s.Site.Location), report.Uploader); err != nil {
				return err
			}
		}
		if action == "delete" {
			var exists int64
			if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("textures")+" WHERE tid=?", report.TID).Scan(&exists); err != nil {
				return err
			}
			if exists == 0 {
				// Texture already deleted by its uploader: return the
				// reporter's suspended score but never pay the informer
				// reward.
				if modification < 0 {
					if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score-? WHERE uid=?", modification, report.Reporter); err != nil {
						return err
					}
				}
				result.Status = Resolved
				result.TextureAlreadyDeleted = true
				_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("reports")+" SET status=? WHERE id=?", result.Status, id)
				return err
			}
			result.Status = Resolved
			if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("reports")+" SET status=? WHERE id=?", result.Status, id); err != nil {
				return err
			}
			if err = s.Closet.DeleteTextureActorTx(ctx, tx, actor, report.TID); err != nil {
				return err
			}
			return applyReviewScore(ctx, tx, s, report.Reporter, modification, reward)
		}
		if err = applyReviewScore(ctx, tx, s, report.Reporter, modification, reward); err != nil {
			return err
		}
		result.Status = Resolved
		_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("reports")+" SET status=? WHERE id=?", result.Status, id)
		return err
	})
	return result, err
}
