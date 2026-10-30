package searchstring

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"
)

// registeredDateDeviation lists inputs whose frozen behaviour is deliberately
// not ported (M3-DATE-NL-01): Carbon's natural-language parser and its
// throw-on-unparseable-month path. They are asserted, with their Go result, by
// TestKnownOracleDifferences.
var registeredDateDeviation = map[string]bool{
	"last_modified='next monday'": true,
	"last_modified=tomorrow":      true,
	"last_modified='2 days ago'":  true,
	"last_modified=today":         true,
	"last_modified='XYZ 2020'":    true,
}

// oracleCase is generated from the frozen PHP library
// (laravel-search-string v1.1.3 + hoa/compiler + Laravel 8.75/Carbon) using the
// same schema. Regenerate with the local oracle; never derive expectations from
// this package's output.
type oracleCase struct {
	Invalid bool     `json:"invalid"`
	Where   string   `json:"where"`
	Args    []any    `json:"args"`
	Order   []Order  `json:"order"`
	Limit   *int     `json:"limit"`
	Offset  *int     `json:"offset"`
	Select  []string `json:"select"`
}

func playerSchema() Schema {
	return Schema{
		Columns: []Column{
			{Name: "pid"},
			{Name: "uid"},
			{Name: "tid_skin", Pattern: `^(?:tid_)?skin$`},
			{Name: "tid_cape", Pattern: `^(?:tid_)?cape$`},
			{Name: "name", Searchable: true},
			{Name: "last_modified", Date: true, Boolean: true},
		},
		Location: time.FixedZone("CST", 8*60*60),
		// The oracle ran under Carbon::setTestNow('2026-01-01 00:00:00').
		Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.FixedZone("CST", 8*60*60)) },
	}
}

func normalizeJSONNumbers(value any) any {
	switch typed := value.(type) {
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = normalizeJSONNumbers(item)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for key, item := range typed {
			out[key] = normalizeJSONNumbers(item)
		}
		return out
	case float64:
		if typed == float64(int64(typed)) {
			return int64(typed)
		}
		return typed
	case json.Number:
		if integer, err := typed.Int64(); err == nil {
			return integer
		}
		if number, err := typed.Float64(); err == nil {
			return number
		}
	}
	return value
}

func TestFrozenOraclePlayers(t *testing.T) {
	raw, err := os.ReadFile("testdata/players_oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases map[string]oracleCase
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var generic map[string]map[string]any
	if err = decoder.Decode(&generic); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for input, fields := range generic {
		if args, ok := fields["args"].([]any); ok {
			normalized := make([]any, len(args))
			for i, value := range args {
				normalized[i] = normalizeJSONNumbers(value)
			}
			entry := cases[input]
			entry.Args = normalized
			cases[input] = entry
		}
	}
	schema := playerSchema()
	for input, want := range cases {
		if registeredDateDeviation[input] {
			// Asserted separately by TestKnownOracleDifferences.
			continue
		}
		got := Build(input, schema)
		empty := got.Where == "" && len(got.Args) == 0 && len(got.Order) == 0 && got.Limit == nil && got.Offset == nil && len(got.Select) == 0
		if want.Invalid {
			// A caught keyword error leaves the frozen builder untouched, which is
			// behaviourally identical to the all-results fallback.
			if got.Invalid || empty {
				continue
			}
			t.Errorf("%q: expected no constraints, got %#v", input, got)
			continue
		}
		if got.Invalid {
			t.Errorf("%q: invalid=%v, want false", input, got.Invalid)
			continue
		}
		if got.Where != want.Where {
			t.Errorf("%q: where=%q, want %q", input, got.Where, want.Where)
		}
		if !reflect.DeepEqual(got.Args, want.Args) && !(len(got.Args) == 0 && len(want.Args) == 0) {
			t.Errorf("%q: args=%#v, want %#v", input, got.Args, want.Args)
		}
		if !reflect.DeepEqual(got.Order, want.Order) && !(len(got.Order) == 0 && len(want.Order) == 0) {
			t.Errorf("%q: order=%#v, want %#v", input, got.Order, want.Order)
		}
		if !equalIntPtr(got.Limit, want.Limit) {
			t.Errorf("%q: limit=%v, want %v", input, deref(got.Limit), deref(want.Limit))
		}
		if !equalIntPtr(got.Offset, want.Offset) {
			t.Errorf("%q: offset=%v, want %v", input, deref(got.Offset), deref(want.Offset))
		}
		if !reflect.DeepEqual(got.Select, want.Select) && !(len(got.Select) == 0 && len(want.Select) == 0) {
			t.Errorf("%q: select=%#v, want %#v", input, got.Select, want.Select)
		}
	}
}

func deref(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func equalIntPtr(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// TestKnownOracleDifferences pins the deviations from the frozen implementation
// that the user approved for M3 (registered as M3-DATE-NL-01 in the M3 closure
// record). Every other oracle case must match the frozen library exactly.
func TestKnownOracleDifferences(t *testing.T) {
	schema := playerSchema()
	// Natural language is not ported: Carbon::parse resolves it relative to
	// "now" while this port falls back to a literal comparison.
	for _, input := range []string{
		"last_modified='next monday'",
		"last_modified=tomorrow",
		"last_modified='2 days ago'",
		"last_modified=today",
	} {
		got := Build(input, schema)
		if got.Invalid || got.Where != "last_modified = ?" {
			t.Errorf("%q: natural language should fall back to a literal comparison, got %#v", input, got)
		}
	}
	// Carbon::parse throws on a leading non-month word; the frozen builder
	// therefore drops the whole query. This port treats it as a literal.
	if got := Build("last_modified='XYZ 2020'", schema); got.Invalid || got.Where != "last_modified = ?" {
		t.Errorf("XYZ 2020 handling changed: %#v", got)
	}
	// HoaCompiler treats "0" as empty input (PHP falsy); production therefore
	// returns all results. The direct-parser oracle bypasses that layer.
	if got := Build("0", schema); got.Where != "" || got.Invalid {
		t.Fatalf("q=0 handling changed: %#v", got)
	}
	// Laravel binds dates with Grammar::getDateFormat() == "Y-m-d H:i:s", so
	// microseconds are truncated by the frozen implementation as well.
	if got := Build("last_modified='2020-01-02 12:30:45.123'", schema); len(got.Args) != 1 || got.Args[0] != "2020-01-02 12:30:45" {
		t.Fatalf("microsecond literal handling changed: %#v", got.Args)
	}
}

func TestApprovedRequestErrors(t *testing.T) {
	schema := playerSchema()
	for _, query := range []string{"sort:unknown", "fields:unknown", "name:(a or b)", "name.foo:(a or b)", "unknown:value name:(a or b)", "sort:pid,unknown", "name:Alice fields:unknown", "sort:unknown limit:abc"} {
		if got := Build(query, schema); got.Err != ErrInvalidQuery {
			t.Errorf("%q: wanted request error, got %#v", query, got)
		}
	}
	for _, query := range []string{"unknown:value", "name:(", "name:(a and)", "name.foo:(a and)", "name:(())", "unknown:value sort:unknown", "limit:abc", "fields:pid,unknown", "sort:name limit:abc", "unknown:(a or b)", "fields:unknown fields:name", "sort:unknown sort:pid"} {
		if got := Build(query, schema); got.Err != nil {
			t.Errorf("%q: existing fallback/valid query rejected: %#v", query, got)
		}
	}
}
