// Package rules ports only explicitly audited PCRE configurations to RE2.
// Unsupported custom rules fail at configuration load and require a bridge.
package rules

import (
	"errors"
	"regexp"
	"unicode/utf8"
)

var ErrUnsupported = errors.New("rules: PCRE requires explicit compatibility review")

// Player compiles the frozen built-in player-name choices. Production's two
// custom regex options were empty in the M0 inventory, so none are invented.
func Player(rule, custom string) (*regexp.Regexp, error) {
	if custom != "" {
		return nil, ErrUnsupported
	}
	switch rule {
	case "official":
		return regexp.Compile(`^[A-Za-z0-9_]+$`)
	case "cjk":
		return regexp.Compile(`^[A-Za-z0-9_§\x{4e00}-\x{9fff}]+$`)
	default:
		return nil, ErrUnsupported
	}
}

// MatchPlayer mirrors PCRE's non-UCP whitespace set for the utf8 rule.
func MatchPlayer(rule, custom, value string) (bool, error) {
	if rule == "utf8" && custom == "" {
		return utf8.ValidString(value) && !regexp.MustCompile(`[\t\n\x0b\f\r ]`).MatchString(value), nil
	}
	r, e := Player(rule, custom)
	if e != nil {
		return false, e
	}
	return r.MatchString(value), nil
}
