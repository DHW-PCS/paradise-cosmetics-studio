package searchstring

import (
	"testing"
	"time"
)

// frozenProbeLocation is the timezone the DateWithPrecision probe ran under.
var frozenProbeLocation = time.FixedZone("CST", 8*60*60)

// frozenProbeNow is Carbon::setTestNow(...) from the probe harness.
func frozenProbeNow() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, frozenProbeLocation)
}

// TestDatePrecisionMatchesFrozenProbe covers precision detection, calendar
// overflow and the two-digit-year pivot against date_probe.php output.
func TestDatePrecisionMatchesFrozenProbe(t *testing.T) {
	type want struct {
		precision datePrecision
		start     string
		end       string
		parsed    bool
	}
	cases := map[string]want{
		"2020-02-31":           {precisionDay, "2020-03-02 00:00:00", "2020-03-02 23:59:59", true},
		"2020-02-30":           {precisionDay, "2020-03-01 00:00:00", "2020-03-01 23:59:59", true},
		"2020-04-31":           {precisionDay, "2020-05-01 00:00:00", "2020-05-01 23:59:59", true},
		"2019-02-29":           {precisionDay, "2019-03-01 00:00:00", "2019-03-01 23:59:59", true},
		"2020-02-29":           {precisionDay, "2020-02-29 00:00:00", "2020-02-29 23:59:59", true},
		"2020-00-10":           {precisionDay, "2019-12-10 00:00:00", "2019-12-10 23:59:59", true},
		"2020-01-00":           {precisionDay, "2019-12-31 00:00:00", "2019-12-31 23:59:59", true},
		"2020-13-01":           {parsed: false},
		"2020-02-32":           {parsed: false},
		"2020-01-02 24:00":     {precisionDay, "2020-01-03 00:00:00", "2020-01-03 23:59:59", true},
		"2020-01-02 25:00":     {parsed: false},
		"2020-01-02 12:60":     {parsed: false},
		"2020-01-02 12:30:60":  {precisionMinute, "2020-01-02 12:31:00", "2020-01-02 12:31:59", true},
		"69":                   {precisionYear, "2069-01-01 00:00:00", "2069-12-31 23:59:59", true},
		"70":                   {precisionYear, "1970-01-01 00:00:00", "1970-12-31 23:59:59", true},
		"99":                   {precisionYear, "1999-01-01 00:00:00", "1999-12-31 23:59:59", true},
		"00":                   {precisionYear, "2000-01-01 00:00:00", "2000-12-31 23:59:59", true},
		"01-69":                {precisionMonth, "2069-01-01 00:00:00", "2069-01-31 23:59:59", true},
		"01-70":                {precisionMonth, "1970-01-01 00:00:00", "1970-01-31 23:59:59", true},
		"Jan 69":               {precisionMonth, "2069-01-01 00:00:00", "2069-01-31 23:59:59", true},
		"2020-01-02 12:30":     {precisionMinute, "2020-01-02 12:30:00", "2020-01-02 12:30:59", true},
		"2020-01-02 12:30:45":  {precisionSecond, "2020-01-02 12:30:45", "2020-01-02 12:30:45", true},
		"2020-01-02T12:30:45Z": {precisionSecond, "2020-01-02 12:30:45", "2020-01-02 12:30:45", true},
		"2020-001":             {precisionDay, "2020-01-01 00:00:00", "2020-01-01 23:59:59", true},
		"20200102":             {precisionDay, "2020-01-02 00:00:00", "2020-01-02 23:59:59", true},
		"1/2/2020":             {precisionDay, "2020-01-02 00:00:00", "2020-01-02 23:59:59", true},
		"Jan 5 2020":           {precisionDay, "2020-01-05 00:00:00", "2020-01-05 23:59:59", true},
		"Jan 5, 2020":          {precisionDay, "2020-01-05 00:00:00", "2020-01-05 23:59:59", true},
		"5 January 2020":       {precisionDay, "2020-01-05 00:00:00", "2020-01-05 23:59:59", true},
		"2020/02/31":           {precisionDay, "2020-03-02 00:00:00", "2020-03-02 23:59:59", true},
		"2020 02 31":           {parsed: false},
		"2020-0012":            {parsed: false},
		"10000-01-01":          {parsed: false},
		"3. März 2020":         {parsed: false},
		"2020年1月2日":            {parsed: false},
		"notadate":             {parsed: false},
	}
	for input, expected := range cases {
		parsed, ok := parseDate(input, frozenProbeLocation)
		if ok != expected.parsed {
			t.Errorf("%q: parsed=%v, want %v", input, ok, expected.parsed)
			continue
		}
		if !ok {
			continue
		}
		start, end := formatDate(parsed.start, frozenProbeLocation), formatDate(parsed.end, frozenProbeLocation)
		if start != expected.start || end != expected.end {
			t.Errorf("%q: got %s..%s, want %s..%s", input, start, end, expected.start, expected.end)
		}
		if parsed.exact != (expected.precision <= precisionSecond) {
			t.Errorf("%q: exact=%v for precision %v", input, parsed.exact, expected.precision)
		}
	}
}

// TestNullDateUsesCurrentPrecisionWindow covers the frozen
// Carbon::parse(null) behaviour at several clock instants.
func TestNullDateUsesCurrentPrecisionWindow(t *testing.T) {
	schema := Schema{
		Columns:  []Column{{Name: "last_modified", Date: true, Boolean: true}},
		Location: frozenProbeLocation,
	}
	cases := []struct {
		now        time.Time
		start, end string
	}{
		{time.Date(2026, 1, 1, 0, 0, 0, 0, frozenProbeLocation), "2026-01-01 00:00:00", "2026-01-01 23:59:59"},
		{time.Date(2026, 3, 15, 8, 0, 0, 0, frozenProbeLocation), "2026-03-15 08:00:00", "2026-03-15 08:59:59"},
	}
	for _, input := range []string{"last_modified=NULL", "last_modified=''", "last_modified=' '"} {
		clock := cases[0].now
		scoped := schema
		scoped.Now = func() time.Time { return clock }
		got := Build(input, scoped)
		if got.Where != "(last_modified >= ? AND last_modified <= ?)" || got.Args[0] != "2026-01-01 00:00:00" {
			t.Errorf("%q: empty value should resolve to now, got %#v", input, got)
		}
	}
	for _, item := range cases {
		clock := item.now
		scoped := schema
		scoped.Now = func() time.Time { return clock }
		got := Build("last_modified=NULL", scoped)
		if got.Where != "(last_modified >= ? AND last_modified <= ?)" {
			t.Fatalf("%v: where=%q", item.now, got.Where)
		}
		if got.Args[0] != item.start || got.Args[1] != item.end {
			t.Errorf("%v: args=%v, want %s..%s", item.now, got.Args, item.start, item.end)
		}
	}
	// Sub-second "now" makes the precision micro, so the value binds exactly.
	micro := Schema{
		Columns:  []Column{{Name: "last_modified", Date: true, Boolean: true}},
		Location: frozenProbeLocation,
		Now:      func() time.Time { return time.Date(2026, 10, 30, 13, 20, 57, 123456000, frozenProbeLocation) },
	}
	got := Build("last_modified=NULL", micro)
	if got.Where != "last_modified = ?" || len(got.Args) != 1 || got.Args[0] != "2026-10-30 13:20:57" {
		t.Fatalf("micro-precision NULL mismatch: %#v", got)
	}
}
