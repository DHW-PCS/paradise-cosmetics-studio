package searchstring

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// datePrecision mirrors DateWithPrecision::FORMATS_PER_PRECISIONS order.
type datePrecision int

const (
	precisionMicro datePrecision = iota
	precisionSecond
	precisionMinute
	precisionHour
	precisionDay
	precisionMonth
	precisionYear
)

type parsedDate struct {
	start, end time.Time
	exact      bool
}

type dateFormat struct {
	format    string // PHP format as used by DateWithPrecision
	precision datePrecision
}

// frozenDateFormats follows DateWithPrecision::FORMATS_PER_PRECISIONS in its
// declared order. Carbon validates each candidate with a per-token regex before
// createFromFormat, so the order is observable and must not be reordered.
var frozenDateFormats = []dateFormat{
	{"Y-m-d H:i:s.u", precisionMicro},
	{"Y-m-d H:i:s", precisionSecond},
	{"Y-m-d H:i", precisionMinute},
	{"Y-m-d H", precisionHour},
	{"Y-m-d", precisionDay},
	{"Y-m", precisionMonth},
	{"Y/m", precisionMonth},
	{"Y m", precisionMonth},
	{"m-Y", precisionMonth},
	{"m/Y", precisionMonth},
	{"m Y", precisionMonth},
	{"m-y", precisionMonth},
	{"m/y", precisionMonth},
	{"m y", precisionMonth},
	{"Y-n", precisionMonth},
	{"Y/n", precisionMonth},
	{"Y n", precisionMonth},
	{"n-Y", precisionMonth},
	{"n/Y", precisionMonth},
	{"n Y", precisionMonth},
	{"n-y", precisionMonth},
	{"n/y", precisionMonth},
	{"n y", precisionMonth},
	{"Y M", precisionMonth},
	{"M Y", precisionMonth},
	{"y M", precisionMonth},
	{"M y", precisionMonth},
	{"Y F", precisionMonth},
	{"F Y", precisionMonth},
	{"y F", precisionMonth},
	{"F y", precisionMonth},
	{"Y", precisionYear},
	{"y", precisionYear},
}

// carbonTokenPatterns reproduces Carbon::$regexFormats for the tokens used by
// the frozen formats above. The regex is the gate that decides whether a value
// is parsed as a date at all, so it is part of the observable behaviour.
var carbonTokenPatterns = map[byte]string{
	'Y': `[0-9]{4}`,
	'y': `[0-9]{2}`,
	'm': `(?:1[012]|0[1-9])`,
	'n': `(?:1[012]|[1-9])`,
	'd': `(?:3[01]|[12][0-9]|0[1-9])`,
	'H': `(?:2[0-3]|[01][0-9])`,
	'i': `[0-5][0-9]`,
	's': `[0-5][0-9]`,
	'u': `[0-9]{1,6}`,
	'M': `[a-zA-Z]{3}`,
	'F': `[a-zA-Z]{2,}`,
}

// lenientNumeric* match Carbon::parse's numeric forms, including the calendar
// overflow it accepts (day 0/31-in-February, hour 24, second 60). Month 13,
// day 32, hour 25, minute 60 and five-digit years are rejected, matching the
// frozen probes.
var (
	lenientDash  = regexp.MustCompile(`^([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})(?:[ T]([0-9]{1,2}):([0-9]{2})(?::([0-9]{1,2})(?:\.([0-9]{1,6}))?)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)?$`)
	lenientSlash = regexp.MustCompile(`^([0-9]{4})/([0-9]{1,2})/([0-9]{1,2})(?:[ T]([0-9]{1,2}):([0-9]{2})(?::([0-9]{1,2})(?:\.([0-9]{1,6}))?)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)?$`)
	lenientMonth = regexp.MustCompile(`^([0-9]{1,2})/([0-9]{1,2})/([0-9]{4})$`)
	lenientDay   = regexp.MustCompile(`^([0-9]{4})-([0-9]{3})$`)
	lenientBasic = regexp.MustCompile(`^([0-9]{4})([0-9]{2})([0-9]{2})$`)
	// English month-name forms Carbon::parse accepts, in the combinations the
	// frozen probes exercise.
	lenientMonthFirst = regexp.MustCompile(`^([A-Za-z]{3,}) ([0-9]{1,2})(?:,)? ([0-9]{4})$`)
	lenientDayMonth   = regexp.MustCompile(`^([0-9]{1,2}) ([A-Za-z]{3,}) ([0-9]{4})$`)
)

var monthNames = map[string]time.Month{
	"jan": time.January, "january": time.January,
	"feb": time.February, "february": time.February,
	"mar": time.March, "march": time.March,
	"apr": time.April, "april": time.April,
	"may": time.May,
	"jun": time.June, "june": time.June,
	"jul": time.July, "july": time.July,
	"aug": time.August, "august": time.August,
	"sep": time.September, "september": time.September,
	"oct": time.October, "october": time.October,
	"nov": time.November, "november": time.November,
	"dec": time.December, "december": time.December,
}

type compiledFormat struct {
	regex     *regexp.Regexp
	tokens    []byte
	precision datePrecision
}

var (
	compiledOnce    sync.Once
	compiledFormats []compiledFormat
)

func compileFormats() {
	compiledFormats = make([]compiledFormat, 0, len(frozenDateFormats))
	for _, entry := range frozenDateFormats {
		var pattern strings.Builder
		pattern.WriteString("^")
		tokens := make([]byte, 0, len(entry.format))
		for i := 0; i < len(entry.format); i++ {
			c := entry.format[i]
			if replacement, ok := carbonTokenPatterns[c]; ok {
				pattern.WriteString("(" + replacement + ")")
				tokens = append(tokens, c)
				continue
			}
			pattern.WriteString(regexp.QuoteMeta(string(c)))
		}
		pattern.WriteString("$")
		compiledFormats = append(compiledFormats, compiledFormat{
			regex:     regexp.MustCompile(pattern.String()),
			tokens:    tokens,
			precision: entry.precision,
		})
	}
}

// parseDate mirrors DateWithPrecision: the frozen format table first, then a
// numeric Carbon::parse fallback. Natural language and locale-specific month
// names are intentionally not ported; such values fall back to a literal
// comparison (registered difference M3-DATE-NL-01).
func parseDate(text string, location *time.Location) (parsedDate, bool) {
	if location == nil {
		location = time.UTC
	}
	if text == "" {
		// Carbon::parse('') (and parse(null)) resolves to the current instant; the
		// caller supplies it through Schema.Now for the NULL path.
		return parsedDate{}, false
	}
	compiledOnce.Do(compileFormats)
	for _, entry := range compiledFormats {
		value, ok := entry.parse(text, location)
		if !ok {
			continue
		}
		return buildDateRange(value, entry.precision, location), true
	}
	if value, ok := parseLenientNumeric(text, location); ok {
		return buildDateRange(value, precisionOf(value), location), true
	}
	return parsedDate{}, false
}

func (c compiledFormat) parse(text string, location *time.Location) (time.Time, bool) {
	match := c.regex.FindStringSubmatch(text)
	if match == nil {
		return time.Time{}, false
	}
	year, month, day := 0, 1, 1
	hour, minute, second, nanosecond := 0, 0, 0, 0
	for index, token := range c.tokens {
		value := match[index+1]
		var err error
		switch token {
		case 'Y':
			year, err = strconv.Atoi(value)
		case 'y':
			year, err = strconv.Atoi(value)
			// PHP's 'y' pivots at 70 (00-69 => 2000-2069, 70-99 => 1970-1999).
			if err == nil {
				if year < 70 {
					year += 2000
				} else {
					year += 1900
				}
			}
		case 'm', 'n':
			month, err = strconv.Atoi(value)
		case 'd':
			day, err = strconv.Atoi(value)
		case 'H':
			hour, err = strconv.Atoi(value)
		case 'i':
			minute, err = strconv.Atoi(value)
		case 's':
			second, err = strconv.Atoi(value)
		case 'u':
			var micro int
			micro, err = strconv.Atoi(value)
			nanosecond = micro * 1000
			for digits := len(value); digits < 6 && err == nil; digits++ {
				nanosecond *= 10
			}
		case 'M', 'F':
			parsed, ok := monthNames[strings.ToLower(value)]
			if !ok {
				// Carbon's hasFormat regex accepts any letters here, but
				// createFromFormat then throws; treat it as "not a date".
				return time.Time{}, false
			}
			month = int(parsed)
		}
		if err != nil {
			return time.Time{}, false
		}
	}
	// time.Date normalises calendar overflow exactly like createFromFormat:
	// 2020-02-31 becomes 2020-03-02.
	return time.Date(year, time.Month(month), day, hour, minute, second, nanosecond, location), true
}

func parseLenientNumeric(text string, location *time.Location) (time.Time, bool) {
	if match := lenientDay.FindStringSubmatch(text); match != nil {
		year, _ := strconv.Atoi(match[1])
		ordinal, _ := strconv.Atoi(match[2])
		if ordinal < 1 || ordinal > 366 {
			return time.Time{}, false
		}
		return time.Date(year, 1, 1, 0, 0, 0, 0, location).AddDate(0, 0, ordinal-1), true
	}
	if match := lenientBasic.FindStringSubmatch(text); match != nil {
		year, _ := strconv.Atoi(match[1])
		month, _ := strconv.Atoi(match[2])
		day, _ := strconv.Atoi(match[3])
		if month > 12 || day > 31 {
			return time.Time{}, false
		}
		return time.Date(year, time.Month(month), day, 0, 0, 0, 0, location), true
	}
	if match := lenientMonthFirst.FindStringSubmatch(text); match != nil {
		month, ok := monthNames[strings.ToLower(match[1])]
		if !ok {
			return time.Time{}, false
		}
		day, _ := strconv.Atoi(match[2])
		year, _ := strconv.Atoi(match[3])
		if day > 31 {
			return time.Time{}, false
		}
		return time.Date(year, month, day, 0, 0, 0, 0, location), true
	}
	if match := lenientDayMonth.FindStringSubmatch(text); match != nil {
		month, ok := monthNames[strings.ToLower(match[2])]
		if !ok {
			return time.Time{}, false
		}
		day, _ := strconv.Atoi(match[1])
		year, _ := strconv.Atoi(match[3])
		if day > 31 {
			return time.Time{}, false
		}
		return time.Date(year, month, day, 0, 0, 0, 0, location), true
	}
	if match := lenientMonth.FindStringSubmatch(text); match != nil {
		month, _ := strconv.Atoi(match[1])
		day, _ := strconv.Atoi(match[2])
		year, _ := strconv.Atoi(match[3])
		if month > 12 || day > 31 {
			return time.Time{}, false
		}
		return time.Date(year, time.Month(month), day, 0, 0, 0, 0, location), true
	}
	match := lenientDash.FindStringSubmatch(text)
	if match == nil {
		match = lenientSlash.FindStringSubmatch(text)
	}
	if match == nil {
		return time.Time{}, false
	}
	year, _ := strconv.Atoi(match[1])
	month, _ := strconv.Atoi(match[2])
	day, _ := strconv.Atoi(match[3])
	hour, minute, second, nanosecond := 0, 0, 0, 0
	if match[4] != "" {
		hour, _ = strconv.Atoi(match[4])
		minute, _ = strconv.Atoi(match[5])
	}
	if match[6] != "" {
		second, _ = strconv.Atoi(match[6])
	}
	if match[7] != "" {
		micro, _ := strconv.Atoi(match[7])
		nanosecond = micro * 1000
		for digits := len(match[7]); digits < 6; digits++ {
			nanosecond *= 10
		}
	}
	// PHP's parser rejects these ranges but accepts the ones above them and
	// rolls the value over.
	if month > 12 || day > 31 || hour > 24 || minute > 59 || second > 60 {
		return time.Time{}, false
	}
	return time.Date(year, time.Month(month), day, hour, minute, second, nanosecond, location), true
}

// precisionOf mirrors DateWithPrecision::parseOriginal's precision detection
// after Carbon::parse: the first non-zero component wins, else micro.
func precisionOf(value time.Time) datePrecision {
	switch {
	case value.Nanosecond() != 0:
		return precisionMicro
	case value.Second() != 0:
		return precisionSecond
	case value.Minute() != 0:
		return precisionMinute
	case value.Hour() != 0:
		return precisionHour
	case value.Day() != 0:
		return precisionDay
	case int(value.Month()) != 0:
		return precisionMonth
	}
	return precisionYear
}

func buildDateRange(value time.Time, precision datePrecision, location *time.Location) parsedDate {
	value = value.In(location)
	year, month, day := value.Date()
	switch precision {
	case precisionMicro, precisionSecond:
		return parsedDate{start: value, end: value, exact: true}
	case precisionMinute:
		start := time.Date(year, month, day, value.Hour(), value.Minute(), 0, 0, location)
		return parsedDate{start: start, end: start.Add(time.Minute - time.Nanosecond)}
	case precisionHour:
		start := time.Date(year, month, day, value.Hour(), 0, 0, 0, location)
		return parsedDate{start: start, end: start.Add(time.Hour - time.Nanosecond)}
	case precisionDay:
		start := time.Date(year, month, day, 0, 0, 0, 0, location)
		return parsedDate{start: start, end: start.AddDate(0, 0, 1).Add(-time.Nanosecond)}
	case precisionMonth:
		start := time.Date(year, month, 1, 0, 0, 0, 0, location)
		return parsedDate{start: start, end: start.AddDate(0, 1, 0).Add(-time.Nanosecond)}
	default:
		start := time.Date(year, 1, 1, 0, 0, 0, 0, location)
		return parsedDate{start: start, end: start.AddDate(1, 0, 0).Add(-time.Nanosecond)}
	}
}

func formatDate(value time.Time, location *time.Location) string {
	if location != nil {
		value = value.In(location)
	}
	return value.Format("2006-01-02 15:04:05")
}
