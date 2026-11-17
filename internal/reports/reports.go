// Package reports owns texture reports, review actions and reporter scoring.
package reports

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"paradise-cosmetics-studio/internal/database"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/searchstring"
	"paradise-cosmetics-studio/internal/site"
	"paradise-cosmetics-studio/internal/textures"
	"paradise-cosmetics-studio/internal/users"
)

const (
	Pending  = 0
	Resolved = 1
	Rejected = 2
)

var (
	ErrNotFound      = errors.New("reports: report not found")
	ErrRepeated      = errors.New("reports: duplicate report")
	ErrNoPermission  = errors.New("reports: no permission")
	ErrBanOutranking = errors.New("reports: ban target outranks actor")
	ErrLackScore     = errors.New("reports: not enough score")
)

type Service struct {
	Store    *database.Store
	Identity *identity.Service
	Site     *site.Service
	Textures *textures.Service
	// Closet is the texture-deletion Tx capability for ReviewActor.
	// Its concrete type is *closet.Service in production wiring; the
	// interface requires the Actor Tx entry at compile time, so a
	// closet build without DeleteTextureActorTx cannot be wired here.
	Closet TextureDeleteActorTx
	Now    func() time.Time
}

func New(store *database.Store, id *identity.Service, view *site.Service, tex *textures.Service, cl TextureDeleteActorTx, now func() time.Time) *Service {
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
	TextureUploader *users.User       `json:"texture_uploader"`
	Informer        *users.User       `json:"informer"`
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
// It shares the manageTx kernel with ManageActor; the browser HTTP
// layer gates admin access for this entry, as before.
func (s *Service) Manage(ctx context.Context, page int, query, path string) (*ManagePage, error) {
	var result *ManagePage
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		var err error
		result, err = s.manageTx(ctx, tx, page, query, path)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) manageTx(ctx context.Context, tx *sql.Tx, page int, query, path string) (*ManagePage, error) {
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
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("reports")+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	listArgs := append(append([]any{}, args...), managePerPage, (page-1)*managePerPage)
	rows, err := tx.QueryContext(ctx, "SELECT id,tid,uploader,reporter,reason,status,report_at FROM "+s.Store.Table("reports")+where+order+" LIMIT ? OFFSET ?", listArgs...)
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
		item.Texture, err = s.textureTx(ctx, tx, report.TID)
		if err != nil && !errors.Is(err, textures.ErrNotFound) {
			return nil, err
		}
		item.TextureUploader, err = s.briefTx(ctx, tx, report.Uploader)
		if err != nil {
			return nil, err
		}
		item.Informer, err = s.briefTx(ctx, tx, report.Reporter)
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

type ReviewResult struct {
	Status                int64
	TextureAlreadyDeleted bool
}

// Review is the browser wrapper for ReviewActor; it shares the same
// business transaction kernel (including the non-PENDING early
// success) and never forges an OAuth actor.
func (s *Service) Review(ctx context.Context, b *identity.BrowserSession, id int64, action string) (ReviewResult, error) {
	actor, err := s.Identity.NewBrowserActor(b)
	if err != nil {
		return ReviewResult{}, err
	}
	return s.ReviewActor(ctx, actor, id, action)
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
