package yggdrasil

import (
	"context"
	"database/sql"

	"paradise-cosmetics-studio/internal/config"
	"paradise-cosmetics-studio/internal/database"
)

// options is the central read layer for ygg_* options. It never seeds
// defaults: a missing key stays missing and the caller applies the frozen
// legacy semantic (0 / no limit / 403-on-non-empty) for that key. The only
// code default is ygg_tokens_limit=10.
type options struct {
	store    *database.Store
	snapshot map[string]string
}

func newOptions(store *database.Store, snapshot map[string]string) options {
	return options{store: store, snapshot: snapshot}
}

// load reads the current option map: authoritative snapshot when present,
// otherwise the live options table. Every value passes through the same
// OptionValue conversion the site layer uses. Option keys keep their
// legacy names; nothing is seeded beyond the frozen semantics.
func (o options) load(ctx context.Context) (map[string]any, error) {
	if o.snapshot != nil {
		out := make(map[string]any, len(o.snapshot))
		for key, value := range o.snapshot {
			out[key] = config.OptionValue(value)
		}
		return out, nil
	}
	rows, err := o.store.DB.QueryContext(ctx, "SELECT option_name,option_value FROM "+o.store.Table("options"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]any{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		out[key] = config.OptionValue(value)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func optionPresent(opts map[string]any, key string) (any, bool) {
	v, ok := opts[key]
	return v, ok
}

// optionInt parses an option as the legacy (int) cast: bools become 1/0,
// strings parse as decimal, everything else (including missing) becomes 0.
func optionInt(v any, present bool) int64 {
	if !present || v == nil {
		return 0
	}
	switch t := v.(type) {
	case bool:
		if t {
			return 1
		}
		return 0
	case string:
		n, err := parseDecimal(t)
		if err != nil {
			return 0
		}
		return n
	case int64:
		return t
	case int:
		return int64(t)
	}
	return 0
}

func parseDecimal(s string) (int64, error) {
	s = trimSpace(s)
	if s == "" {
		return 0, errNotNumber
	}
	neg := false
	if s[0] == '-' || s[0] == '+' {
		neg = s[0] == '-'
		s = s[1:]
	}
	if s == "" {
		return 0, errNotNumber
	}
	var n int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, errNotNumber
		}
		if n > (1<<62-1)/10 {
			// Overflow saturates like a large int; legacy PHP would
			// widen to float but the observable comparison stays
			// "very large". Return the largest we tracked.
			return n, nil
		}
		n = n*10 + int64(c-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}

var errNotNumber = &numberError{}

type numberError struct{}

func (*numberError) Error() string { return "not a number" }

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\n' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// optionString returns the textual option value; missing or null is "".
func optionString(v any, present bool) string {
	if !present || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// optionTruthy mirrors the legacy if (option(...)) check.
func optionTruthy(v any, present bool) bool {
	if !present || v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != "" && t != "0"
	default:
		return true
	}
}

// optionFromTx reads one option inside the caller's transaction, following
// the site read model: the last row in id order wins.
func optionFromTx(ctx context.Context, tx *sql.Tx, store *database.Store, key string) (any, bool, error) {
	rows, err := tx.QueryContext(ctx, "SELECT option_value FROM "+store.Table("options")+" WHERE option_name=? ORDER BY id", key)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var found string
	var present bool
	for rows.Next() {
		var v string
		if err = rows.Scan(&v); err != nil {
			return nil, false, err
		}
		found = v
		present = true
	}
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	if !present {
		return nil, false, nil
	}
	// Apply the same OptionValue conversion the site layer uses.
	return convertOptionValue(found), true, nil
}

func convertOptionValue(s string) any {
	switch lowerASCII(s) {
	case "true", "(true)":
		return true
	case "false", "(false)":
		return false
	case "null", "(null)":
		return nil
	default:
		return s
	}
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
