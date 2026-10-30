// Package users owns the admin user search/list read model.
package users

import (
	"context"
	"database/sql"
	"time"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/searchstring"
	"blessing-skin-go/internal/site"
)

type Service struct {
	Store *database.Store
	Site  *site.Service
	Now   func() time.Time
}

func New(store *database.Store, view *site.Service, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{Store: store, Site: view, Now: now}
}

// User mirrors the frozen JSON serialization (dates use Carbon's default JSON
// format instead of the player model's custom one).
type User struct {
	UID        int64   `json:"uid"`
	Email      string  `json:"email"`
	Nickname   string  `json:"nickname"`
	Avatar     int64   `json:"avatar"`
	Score      int64   `json:"score"`
	Permission int64   `json:"permission"`
	IP         string  `json:"ip"`
	IsDarkMode bool    `json:"is_dark_mode"`
	LastSignAt string  `json:"last_sign_at"`
	RegisterAt string  `json:"register_at"`
	Verified   bool    `json:"verified"`
	Locale     *string `json:"locale"`
}

// Page is the shared Laravel-shaped paginator; fields: projected rows are
// returned through the same paginator as full User objects.
type Page = searchstring.Paginator

func schema(location *time.Location, now func() time.Time) searchstring.Schema {
	return searchstring.Schema{
		Columns: []searchstring.Column{
			{Name: "uid"},
			{Name: "email", Searchable: true},
			{Name: "nickname", Searchable: true},
			{Name: "avatar"},
			{Name: "score"},
			{Name: "permission"},
			{Name: "ip"},
			{Name: "last_sign_at", Date: true, Boolean: true},
			{Name: "register_at", Date: true, Boolean: true},
			{Name: "verified", Boolean: true},
			{Name: "is_dark_mode", Boolean: true},
		},
		Location: location,
		Now:      now,
	}
}

const perPage = 10

// List applies the frozen full search DSL to users with 10 per page.
func (s *Service) List(ctx context.Context, page int, query, path string) (*Page, error) {
	if page < 1 {
		page = 1
	}
	resolved := searchstring.Build(query, schema(s.Site.Location, s.Now))
	if resolved.Err != nil {
		return nil, resolved.Err
	}
	where := ""
	var args []any
	if !resolved.Invalid && resolved.Where != "" {
		where = " WHERE " + resolved.Where
		args = resolved.Args
	}
	var total int
	if err := s.Store.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("users")+where, args...).Scan(&total); err != nil {
		return nil, err
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
	rows, err := s.Store.DB.QueryContext(ctx, "SELECT uid,email,nickname,avatar,score,permission,ip,is_dark_mode,last_sign_at,register_at,verified,locale FROM "+s.Store.Table("users")+where+order+" LIMIT ? OFFSET ?", append(args, perPage, (page-1)*perPage)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := []User{}
	for rows.Next() {
		var user User
		var lastSign, registered time.Time
		var locale sql.NullString
		if err = rows.Scan(&user.UID, &user.Email, &user.Nickname, &user.Avatar, &user.Score, &user.Permission, &user.IP, &user.IsDarkMode, &lastSign, &registered, &user.Verified, &locale); err != nil {
			return nil, err
		}
		if locale.Valid {
			value := locale.String
			user.Locale = &value
		}
		user.LastSignAt = lastSign.UTC().Format("2006-01-02T15:04:05.000000Z")
		user.RegisterAt = registered.UTC().Format("2006-01-02T15:04:05.000000Z")
		users = append(users, user)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	var data any = users
	if len(resolved.Select) > 0 && !resolved.Invalid {
		projected := make([]map[string]any, 0, len(users))
		for _, user := range users {
			projected = append(projected, project(user, resolved.Select))
		}
		data = projected
	}
	return searchstring.NewPaginator(data, page, perPage, total, path), nil
}

// project keeps the JSON field names of a full User row but only the columns
// named by the frozen `fields:` keyword.
func project(user User, columns []string) map[string]any {
	row := make(map[string]any, len(columns))
	for _, column := range columns {
		switch column {
		case "uid":
			row["uid"] = user.UID
		case "email":
			row["email"] = user.Email
		case "nickname":
			row["nickname"] = user.Nickname
		case "avatar":
			row["avatar"] = user.Avatar
		case "score":
			row["score"] = user.Score
		case "permission":
			row["permission"] = user.Permission
		case "ip":
			row["ip"] = user.IP
		case "is_dark_mode":
			row["is_dark_mode"] = user.IsDarkMode
		case "last_sign_at":
			row["last_sign_at"] = user.LastSignAt
		case "register_at":
			row["register_at"] = user.RegisterAt
		case "verified":
			row["verified"] = user.Verified
		case "locale":
			row["locale"] = user.Locale
		}
	}
	return row
}
