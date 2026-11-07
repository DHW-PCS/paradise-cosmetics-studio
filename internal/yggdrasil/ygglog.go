package yggdrasil

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// yggLogEntry is one allowlisted audit row. parameters carries only
// allowlisted keys; amounts such as tokens and passwords never arrive here.
type yggLogEntry struct {
	Action     string
	UserID     int64
	PlayerID   int64
	IP         string
	Time       time.Time
	Parameters map[string]any
}

// logParamAllowlist fixes the keys that may be persisted in parameters.
// Anything outside this set is dropped before storage.
// logParamAllowlist keys are lowercase; lookups lowercase the candidate
// key, so the check is case-insensitive while stored keys keep their
// original case.
var logParamAllowlist = map[string]bool{
	"clienttokenpresent": true,
	"requestuser":        true,
	"selectedprofile":    true,
	"profileid":          true,
	"reason":             true,
}

func sanitizeParameters(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	out := map[string]any{}
	for k, v := range in {
		if logParamAllowlist[strings.ToLower(k)] {
			out[k] = v
		}
	}
	return out
}

func (s *Service) insertLogTx(ctx context.Context, tx *sql.Tx, entry yggLogEntry) error {
	if !s.Verbose {
		return nil
	}
	raw, err := json.Marshal(sanitizeParameters(entry.Parameters))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("ygg_log")+" (action,user_id,player_id,parameters,ip,time) VALUES (?,?,?,?,?,?)",
		entry.Action, entry.UserID, entry.PlayerID, string(raw), entry.IP, entry.Time)
	return err
}

// StoredLog is one ygg_log row as returned to the admin log reader. The
// historical parameters text is returned as stored so batch4 can render
// the desensitized view; the service itself never adds secrets to it.
type StoredLog struct {
	ID         int64  `json:"id"`
	Action     string `json:"action"`
	UserID     int64  `json:"user_id"`
	PlayerID   int64  `json:"player_id"`
	Parameters string `json:"parameters"`
	IP         string `json:"ip"`
	Time       string `json:"time"`
}

// SanitizeStoredParameters renders one historical parameters text with
// only allowlisted keys kept. Unparseable history renders as an empty
// object instead of leaking raw text to the admin page.
func SanitizeStoredParameters(raw string) string {
	var decoded map[string]any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil || decoded == nil {
		return "{}"
	}
	out, err := json.Marshal(sanitizeParameters(decoded))
	if err != nil {
		return "{}"
	}
	return string(out)
}

// ListLogs returns the newest log rows up to limit. History is preserved
// as stored; callers desensitize on render.
func (s *Service) ListLogs(ctx context.Context, limit int) ([]StoredLog, error) {
	return s.ListLogsPage(ctx, limit, 0)
}

// ListLogsPage returns log rows newest-first by time (legacy
// orderByDesc('time')), up to limit rows skipping offset rows.
func (s *Service) ListLogsPage(ctx context.Context, limit, offset int) ([]StoredLog, error) {
	if limit < 1 {
		limit = 10
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.Store.DB.QueryContext(ctx, "SELECT id,action,user_id,player_id,parameters,ip,time FROM "+s.Store.Table("ygg_log")+" ORDER BY time DESC, id DESC LIMIT ? OFFSET ?", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredLog
	for rows.Next() {
		var row StoredLog
		var tm time.Time
		if err = rows.Scan(&row.ID, &row.Action, &row.UserID, &row.PlayerID, &row.Parameters, &row.IP, &tm); err != nil {
			return nil, err
		}
		row.Time = tm.Format("2006-01-02 15:04:05")
		out = append(out, row)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []StoredLog{}
	}
	return out, nil
}
