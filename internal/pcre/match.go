// Package pcre matches PHP-style delimited patterns with native PCRE2.
package pcre

import (
	"fmt"
	"strings"
)

// Match reports whether subject matches pattern. Invalid configuration and
// execution errors are distinct; neither is treated as a successful match.
func Match(pattern, subject string) (bool, error) {
	body, modifiers, err := split(pattern)
	if err != nil {
		return false, err
	}
	return match(body, modifiers, subject)
}

// ExecutionError reports a failed match, such as invalid UTF or exhausted PHP
// backtracking limits. PHP's validation rules treat these as non-matches.
type ExecutionError struct{ Code int }

func (e *ExecutionError) Error() string { return fmt.Sprintf("pcre: match failed (%d)", e.Code) }

func split(pattern string) (string, string, error) {
	pattern = strings.TrimLeft(pattern, " \t\n\r\v\f")
	if pattern == "" || strings.IndexByte(pattern, 0) >= 0 {
		return "", "", fmt.Errorf("pcre: empty pattern or null byte")
	}
	start := pattern[0]
	if start == '\\' || start >= '0' && start <= '9' || start >= 'a' && start <= 'z' || start >= 'A' && start <= 'Z' {
		return "", "", fmt.Errorf("pcre: invalid delimiter")
	}
	end := start
	switch start {
	case '(':
		end = ')'
	case '[':
		end = ']'
	case '{':
		end = '}'
	case '<':
		end = '>'
	}
	depth := 1
	for i := 1; i < len(pattern); i++ {
		if pattern[i] == '\\' {
			i++
			continue
		}
		if pattern[i] == end {
			depth--
			if depth == 0 {
				return pattern[1:i], pattern[i+1:], nil
			}
		} else if start != end && pattern[i] == start {
			depth++
		}
	}
	return "", "", fmt.Errorf("pcre: missing ending delimiter")
}
