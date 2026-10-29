// Package site owns the read models needed by the first browser slice.
package site

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"blessing-skin-go/internal/config"
	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
)

type Service struct {
	Store          *database.Store
	Identity       *identity.Service
	OptionSnapshot map[string]string
	Location       *time.Location
}

// LoadOptionSnapshot accepts an authoritative JSON export, never executable options.php.
func LoadOptionSnapshot(path string) (map[string]string, error) {
	values := map[string]string{}
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read declared options snapshot")
	}
	if err = json.Unmarshal(b, &values); err != nil || values == nil {
		return nil, fmt.Errorf("options snapshot must be a JSON object of text values")
	}
	return values, nil
}

func (s *Service) Options(ctx context.Context) (map[string]any, error) {
	// Defaults from the frozen 6.0.2 config/options.php for this slice.
	values := map[string]any{
		"site_name": "Blessing Skin", "site_url": "", "navbar_color": "cyan", "sidebar_color": "dark-maroon",
		"copyright_prefer": "0", "copyright_text": `<b>Copyright &copy; {year} <a href="{site_url}">{site_name}</a>.</b> All rights reserved.`,
		"announcement": "Welcome to Blessing Skin {version}!", "user_initial_score": "1000", "sign_score": "10,100", "return_score": true,
		"score_per_storage": true, "score_per_player": "100", "score_per_closet_item": "0", "sign_after_zero": false, "sign_gap_time": "24", "require_verification": false,
	}
	if s.OptionSnapshot != nil {
		for key, value := range s.OptionSnapshot {
			values[key] = config.OptionValue(value)
		}
		return values, nil
	}

	rows, err := s.Store.DB.QueryContext(ctx, "SELECT option_name,option_value FROM "+s.Store.Table("options"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key, value string
		if err = rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		values[key] = config.OptionValue(value)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func LocalizedOption(options map[string]any, key, locale string) any {
	if value, exists := options[key+"_"+locale]; exists {
		return value
	}
	return options[key]
}

func Number(value any) int64 {
	switch v := value.(type) {
	case bool:
		if v {
			return 1
		}
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	}
	return 0
}
func Truth(value any) bool {
	if value == nil {
		return false
	}
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return v != "" && v != "0"
	}
	return true
}

type ScoreInfo struct {
	User struct {
		Score      int64  `json:"score"`
		LastSignAt string `json:"lastSignAt"`
	} `json:"user"`
	Rate struct {
		Storage int64 `json:"storage"`
		Players int64 `json:"players"`
	} `json:"rate"`
	Usage struct {
		Players int64 `json:"players"`
		Storage int64 `json:"storage"`
	} `json:"usage"`
	SignAfterZero bool  `json:"signAfterZero"`
	SignGapTime   int64 `json:"signGapTime"`
}

func (s *Service) Score(ctx context.Context, uid int64) (*ScoreInfo, error) {
	options, err := s.Options(ctx)
	if err != nil {
		return nil, err
	}
	out := &ScoreInfo{}
	var last time.Time
	err = s.Store.DB.QueryRowContext(ctx, "SELECT score,last_sign_at,(SELECT COUNT(*) FROM "+s.Store.Table("players")+" WHERE uid=u.uid),(SELECT COALESCE(SUM(size),0) FROM "+s.Store.Table("textures")+" WHERE uploader=u.uid) FROM "+s.Store.Table("users")+" u WHERE uid=?", uid).Scan(&out.User.Score, &last, &out.Usage.Players, &out.Usage.Storage)
	if err != nil {
		return nil, err
	}
	out.User.LastSignAt = last.In(s.Location).Format(time.RFC3339)
	out.Rate.Storage = Number(options["score_per_storage"])
	out.Rate.Players = Number(options["score_per_player"])
	out.SignAfterZero = Truth(options["sign_after_zero"])
	out.SignGapTime = Number(options["sign_gap_time"])
	return out, nil
}

type UserRow struct {
	identity.User
	Locale     *string `json:"locale"`
	Score      int64   `json:"score"`
	RegisterAt string  `json:"register_at"`
}
type UserPage struct {
	Data        []UserRow `json:"data"`
	CurrentPage int       `json:"current_page"`
	LastPage    int       `json:"last_page"`
	From        *int      `json:"from"`
	To          *int      `json:"to"`
	Total       int       `json:"total"`
}

func (s *Service) Users(ctx context.Context, page int, q string) (*UserPage, error) {
	out := &UserPage{Data: []UserRow{}, CurrentPage: page, LastPage: 1}
	where := ""
	var args []any
	if q != "" {
		where = " WHERE email LIKE ? OR nickname LIKE ?"
		args = []any{"%" + q + "%", "%" + q + "%"}
	}
	if err := s.Store.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("users")+where, args...).Scan(&out.Total); err != nil {
		return nil, err
	}
	if out.Total > 0 {
		out.LastPage = (out.Total + 9) / 10
	}
	args = append(args, (page-1)*10)
	rows, err := s.Store.DB.QueryContext(ctx, "SELECT uid,email,nickname,permission,verified,locale,is_dark_mode,score,register_at FROM "+s.Store.Table("users")+where+" ORDER BY uid LIMIT 10 OFFSET ?", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var row UserRow
		var registered time.Time
		var locale sql.NullString
		if err = rows.Scan(&row.UID, &row.Email, &row.Nickname, &row.Permission, &row.Verified, &locale, &row.DarkMode, &row.Score, &registered); err != nil {
			return nil, err
		}
		if locale.Valid {
			row.Locale = &locale.String
		}
		row.RegisterAt = registered.In(s.Location).Format("2006-01-02 15:04:05")
		out.Data = append(out.Data, row)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(out.Data) > 0 {
		from := (page-1)*10 + 1
		to := from + len(out.Data) - 1
		out.From = &from
		out.To = &to
	}
	return out, nil
}

// ToggleDarkMode rechecks the current credential inside the owning write transaction.
func (s *Service) ToggleDarkMode(ctx context.Context, b *identity.BrowserSession) error {
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err := s.Identity.CheckBrowserTx(ctx, tx, b); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET is_dark_mode=NOT is_dark_mode WHERE uid=?", b.User.UID)
		return err
	})
}

func LocaleTag(locale string) string { return strings.ReplaceAll(locale, "_", "-") }
