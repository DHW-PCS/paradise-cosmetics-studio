// Package rules preserves the frozen player and texture name validation rules.
package rules

import (
	"errors"
	"unicode/utf8"

	"blessing-skin-go/internal/pcre"
)

func match(pattern, value string) (bool, error) {
	matched, err := pcre.Match(pattern, value)
	var execution *pcre.ExecutionError
	if errors.As(err, &execution) {
		return false, nil
	}
	return matched, err
}

// MatchPlayer follows PlayerName::passes, including the custom empty-rule
// default and the separate UTF encoding check for the utf8 choice.
func MatchPlayer(rule, custom, value string) (bool, error) {
	pattern := `/.*/`
	switch rule {
	case "official":
		pattern = `/^[A-Za-z0-9_]+$/`
	case "cjk":
		pattern = `/^[A-Za-z0-9_§\x{4e00}-\x{9fff}]+$/u`
	case "utf8":
		if !utf8.ValidString(value) {
			return false, nil
		}
		whitespace, err := match(`/\s/`, value)
		return !whitespace, err
	case "custom":
		if custom != "" && custom != "0" {
			pattern = custom
		}
	}
	return match(pattern, value)
}

// MatchTexture applies the optional configured PCRE; required/string
// validation belongs to the calling upload or rename operation.
func MatchTexture(pattern, value string) (bool, error) {
	if pattern == "" || pattern == "0" {
		return true, nil
	}
	return match(pattern, value)
}
