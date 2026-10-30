// Package reports owns texture reports, review actions and reporter scoring.
package reports

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"blessing-skin-go/internal/closet"
	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/searchstring"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/textures"
)

const (
	Pending  = 0
	Resolved = 1
	Rejected = 2
)

var (
	ErrNotFound     = errors.New("reports: report not found")
	ErrRepeated     = errors.New("reports: duplicate report")
	ErrNoPermission = errors.New("reports: no permission")
	ErrLackScore    = errors.New("reports: not enough score")
)

type Service struct {
	Store    *database.Store
	Identity *identity.Service
	Site     *site.Service
	Textures *textures.Service
	Closet   *closet.Service
	Now      func() time.Time
}

func New(store *database.Store, id *identity.Service, view *site.Service, tex *textures.Service, cl *closet.Service, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{Store: store, Identity: id, Site: view, Textures: tex, Closet: cl, Now: now}
}

type Report struct {
	ID       int64  `json:"id"`
	TID      int64  `json:"tid"`
	Uploader int64  `json:"uploader"`
	Reporter int64  `json:"reporter"`
	Reason   string `json:"reason"`
	Status   int64  `json:"status"`
	ReportAt string `json:"report_at"`
}

// Submit creates one pending report and applies the configured reporter score
// change in the same transaction.
func (s *Service) Submit(ctx context.Context, b *identity.BrowserSession, tid int64, reason string) error {
	if reason == "" {
		return ErrNotFound
	}
	options, err := s.Site.Options(ctx)
	if err != nil {
		return err
	}
	modification := site.Number(options["reporter_score_modification"])
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		actor, err := s.Identity.CheckBrowserTx(ctx, tx, b)
		if err != nil {
			return err
		}
		var uploader int64
		if err = tx.QueryRowContext(ctx, "SELECT uploader FROM "+s.Store.Table("textures")+" WHERE tid=? FOR UPDATE", tid).Scan(&uploader); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		var existing int64
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("reports")+" WHERE reporter=? AND tid=?", actor.UID, tid).Scan(&existing); err != nil {
			return err
		}
		if existing > 0 {
			return ErrRepeated
		}
		var score int64
		if err = tx.QueryRowContext(ctx, "SELECT score FROM "+s.Store.Table("users")+" WHERE uid=? FOR UPDATE", actor.UID).Scan(&score); err != nil {
			return err
		}
		if modification < 0 && score < -modification {
			return ErrLackScore
		}
		if modification != 0 {
			if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score+? WHERE uid=?", modification, actor.UID); err != nil {
				return err
			}
		}
		now := s.Now().In(s.Site.Location)
		_, err = tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("reports")+" (tid,uploader,reporter,reason,status,report_at) VALUES (?,?,?,?,?,?)", tid, uploader, actor.UID, reason, Pending, now)
		return err
	})
}

// Track lists the current user's reports newest first, paginated 10 per page
// like the frozen ReportController::track paginate(10).
func (s *Service) Track(ctx context.Context, b *identity.BrowserSession, page int, path string) (*searchstring.Paginator, error) {
	if page < 1 {
		page = 1
	}
	var total int
	if err := s.Store.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("reports")+" WHERE reporter=?", b.User.UID).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := s.Store.DB.QueryContext(ctx, "SELECT id,tid,uploader,reporter,reason,status,report_at FROM "+s.Store.Table("reports")+" WHERE reporter=? ORDER BY report_at DESC LIMIT ? OFFSET ?", b.User.UID, trackPerPage, (page-1)*trackPerPage)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Report{}
	for rows.Next() {
		var report Report
		var at time.Time
		if err = rows.Scan(&report.ID, &report.TID, &report.Uploader, &report.Reporter, &report.Reason, &report.Status, &at); err != nil {
			return nil, err
		}
		report.ReportAt = at.In(s.Site.Location).Format("2006-01-02 15:04:05")
		out = append(out, report)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return searchstring.NewPaginator(out, page, trackPerPage, total, path), nil
}

type ManageItem struct {
	Report
	Texture         *textures.Texture `json:"texture"`
	TextureUploader *UploaderBrief    `json:"texture_uploader"`
	Informer        *UploaderBrief    `json:"informer"`
}

type UploaderBrief struct {
	UID      int64  `json:"uid"`
	Nickname string `json:"nickname"`
}

// ManagePage is the shared Laravel-shaped paginator.
type ManagePage = searchstring.Paginator

const (
	managePerPage = 9  // frozen ReportController::manage paginate(9)
	trackPerPage  = 10 // frozen ReportController::track paginate(10)
)

func reportSchema(location *time.Location, now func() time.Time) searchstring.Schema {
	return searchstring.Schema{
		Columns: []searchstring.Column{
			{Name: "id"}, {Name: "tid"}, {Name: "uploader"}, {Name: "reporter"},
			{Name: "reason"}, {Name: "status"},
			{Name: "report_at", Date: true, Boolean: true},
		},
		Location: location,
		Now:      now,
	}
}

// Manage applies the frozen report search DSL with joined texture/informer data.
func (s *Service) Manage(ctx context.Context, page int, query, path string) (*ManagePage, error) {
	if page < 1 {
		page = 1
	}
	resolved := searchstring.Build(query, reportSchema(s.Site.Location, s.Now))
	if resolved.Err != nil {
		return nil, resolved.Err
	}
	where := ""
	var args []any
	if !resolved.Invalid && resolved.Where != "" {
		where = " WHERE " + resolved.Where
		args = resolved.Args
	}
	order := ""
	if !resolved.Invalid && len(resolved.Order) > 0 {
		order = " ORDER BY "
		for i, entry := range resolved.Order {
			if i > 0 {
				order += ", "
			}
			order += entry.Column
			if entry.Desc {
				order += " DESC"
			} else {
				order += " ASC"
			}
		}
	}
	var total int
	if err := s.Store.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("reports")+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	listArgs := append(append([]any{}, args...), managePerPage, (page-1)*managePerPage)
	rows, err := s.Store.DB.QueryContext(ctx, "SELECT id,tid,uploader,reporter,reason,status,report_at FROM "+s.Store.Table("reports")+where+order+" LIMIT ? OFFSET ?", listArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var reports []Report
	for rows.Next() {
		var report Report
		var at time.Time
		if err = rows.Scan(&report.ID, &report.TID, &report.Uploader, &report.Reporter, &report.Reason, &report.Status, &at); err != nil {
			return nil, err
		}
		report.ReportAt = at.In(s.Site.Location).Format("2006-01-02 15:04:05")
		reports = append(reports, report)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	items := []ManageItem{}
	for _, report := range reports {
		item := ManageItem{Report: report}
		item.Texture, err = s.Textures.Get(ctx, report.TID)
		if err != nil && !errors.Is(err, textures.ErrNotFound) {
			return nil, err
		}
		item.TextureUploader, err = s.brief(ctx, report.Uploader)
		if err != nil {
			return nil, err
		}
		item.Informer, err = s.brief(ctx, report.Reporter)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	var data any = items
	if len(resolved.Select) > 0 && !resolved.Invalid {
		projected := make([]map[string]any, 0, len(items))
		for _, item := range items {
			projected = append(projected, projectReport(item, resolved.Select))
		}
		data = projected
	}
	return searchstring.NewPaginator(data, page, managePerPage, total, path), nil
}

// projectReport applies the frozen `fields:` keyword to a report row.
func projectReport(item ManageItem, columns []string) map[string]any {
	row := make(map[string]any, len(columns))
	for _, column := range columns {
		switch column {
		case "id":
			row["id"] = item.Report.ID
		case "tid":
			row["tid"] = item.Report.TID
		case "uploader":
			row["uploader"] = item.Report.Uploader
		case "reporter":
			row["reporter"] = item.Report.Reporter
		case "reason":
			row["reason"] = item.Report.Reason
		case "status":
			row["status"] = item.Report.Status
		case "report_at":
			row["report_at"] = item.Report.ReportAt
		}
	}
	return row
}

func (s *Service) brief(ctx context.Context, uid int64) (*UploaderBrief, error) {
	var nickname string
	err := s.Store.DB.QueryRowContext(ctx, "SELECT nickname FROM "+s.Store.Table("users")+" WHERE uid=?", uid).Scan(&nickname)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &UploaderBrief{UID: uid, Nickname: nickname}, nil
}

type ReviewResult struct {
	Status                int64
	TextureAlreadyDeleted bool
}

// Review resolves a pending report exactly once: reject, ban or delete.
func (s *Service) Review(ctx context.Context, b *identity.BrowserSession, id int64, action string) (ReviewResult, error) {
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
		var report Report
		var at time.Time
		if err = tx.QueryRowContext(ctx, "SELECT id,tid,uploader,reporter,reason,status,report_at FROM "+s.Store.Table("reports")+" WHERE id=? FOR UPDATE", id).
			Scan(&report.ID, &report.TID, &report.Uploader, &report.Reporter, &report.Reason, &report.Status, &at); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		actor, err := s.Identity.CheckBrowserTx(ctx, tx, b)
		if err != nil {
			return err
		}
		if actor.Permission < 1 {
			return ErrNoPermission
		}
		if report.Status != Pending {
			result.Status = report.Status
			return nil
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
			var permission int
			if err = tx.QueryRowContext(ctx, "SELECT permission FROM "+s.Store.Table("users")+" WHERE uid=? FOR UPDATE", report.Uploader).Scan(&permission); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ErrNotFound
				}
				return err
			}
			if actor.Permission <= permission {
				return ErrNoPermission
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
				// Texture already deleted by its uploader: return the reporter's
				// suspended score but never pay the informer reward.
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
			if err = s.Closet.DeleteTextureTx(ctx, tx, b, report.TID); err != nil {
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

// applyReviewScore returns the suspended deposit and pays the resolution award.
func applyReviewScore(ctx context.Context, tx *sql.Tx, s *Service, reporter, modification, reward int64) error {
	if modification < 0 {
		if _, err := tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score-? WHERE uid=?", modification, reporter); err != nil {
			return err
		}
	}
	if reward != 0 {
		if _, err := tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score+? WHERE uid=?", reward, reporter); err != nil {
			return err
		}
	}
	return nil
}
