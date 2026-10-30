package searchstring

import "strings"

// lexer mirrors the frozen Grammar.pp token definitions. Keywords are only
// recognized when followed by end-of-input, whitespace or a parenthesis
// (the original negative lookahead `(?![^\(\)\s])`).
type lexer struct {
	input string
	pos   int
	out   []token
}

func lex(input string) ([]token, bool) {
	l := &lexer{input: input}
	for l.pos < len(l.input) {
		if !l.next() {
			return nil, false
		}
	}
	l.out = append(l.out, token{kind: tokenEOF})
	return l.out, true
}

func isSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func isTermStop(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '\v', '\f', ':', '>', '<', '=', '"', '\'', '(', ')', '.', ',':
		return true
	}
	return false
}

func (l *lexer) peekByte(offset int) (byte, bool) {
	if l.pos+offset >= len(l.input) {
		return 0, false
	}
	return l.input[l.pos+offset], true
}

// keywordBoundary reports whether the character after a candidate keyword
// satisfies `(?![^\(\)\s])`.
func (l *lexer) keywordBoundary(next int) bool {
	if next >= len(l.input) {
		return true
	}
	b := l.input[next]
	return isSpace(b) || b == '(' || b == ')'
}

func (l *lexer) next() bool {
	b := l.input[l.pos]
	if isSpace(b) {
		l.pos++
		return true
	}
	switch b {
	case '\'', '"':
		quote := b
		start := l.pos + 1
		end := strings.IndexByte(l.input[start:], quote)
		if end < 0 {
			return false
		}
		l.out = append(l.out, token{kind: tokenString, text: l.input[start : start+end]})
		l.pos = start + end + 1
		return true
	case ':':
		l.out = append(l.out, token{kind: tokenAssign, text: ":"})
		l.pos++
		return true
	case '=':
		l.out = append(l.out, token{kind: tokenAssign, text: "="})
		l.pos++
		return true
	case '>':
		if n, ok := l.peekByte(1); ok && n == '=' {
			l.out = append(l.out, token{kind: tokenComparator, text: ">="})
			l.pos += 2
			return true
		}
		l.out = append(l.out, token{kind: tokenComparator, text: ">"})
		l.pos++
		return true
	case '<':
		if n, ok := l.peekByte(1); ok && n == '=' {
			l.out = append(l.out, token{kind: tokenComparator, text: "<="})
			l.pos += 2
			return true
		}
		l.out = append(l.out, token{kind: tokenComparator, text: "<"})
		l.pos++
		return true
	case '(':
		l.out = append(l.out, token{kind: tokenLParen})
		l.pos++
		return true
	case ')':
		l.out = append(l.out, token{kind: tokenRParen})
		l.pos++
		return true
	case '.':
		l.out = append(l.out, token{kind: tokenDot})
		l.pos++
		return true
	case ',':
		l.out = append(l.out, token{kind: tokenComma})
		l.pos++
		return true
	}
	if isDigit(b) {
		// Integer wins only when the lookahead allows it, then decimal.
		digits := l.pos
		for digits < len(l.input) && isDigit(l.input[digits]) {
			digits++
		}
		if l.keywordBoundary(digits) {
			l.out = append(l.out, token{kind: tokenInteger, text: l.input[l.pos:digits]})
			l.pos = digits
			return true
		}
		if digits < len(l.input) && l.input[digits] == '.' {
			frac := digits + 1
			for frac < len(l.input) && isDigit(l.input[frac]) {
				frac++
			}
			if frac > digits+1 && l.keywordBoundary(frac) {
				l.out = append(l.out, token{kind: tokenDecimal, text: l.input[l.pos:frac]})
				l.pos = frac
				return true
			}
		}
	}
	start := l.pos
	for l.pos < len(l.input) && !isTermStop(l.input[l.pos]) {
		l.pos++
	}
	if l.pos == start {
		return false
	}
	text := l.input[start:l.pos]
	switch text {
	case "and", "AND":
		if l.keywordBoundary(l.pos) {
			l.out = append(l.out, token{kind: tokenAnd, text: text})
			return true
		}
	case "or", "OR":
		if l.keywordBoundary(l.pos) {
			l.out = append(l.out, token{kind: tokenOr, text: text})
			return true
		}
	case "not", "NOT":
		if l.keywordBoundary(l.pos) {
			l.out = append(l.out, token{kind: tokenNot, text: text})
			return true
		}
	case "in", "IN":
		if l.keywordBoundary(l.pos) {
			l.out = append(l.out, token{kind: tokenIn, text: text})
			return true
		}
	case "NULL":
		if l.keywordBoundary(l.pos) {
			l.out = append(l.out, token{kind: tokenNull, text: text})
			return true
		}
	}
	l.out = append(l.out, token{kind: tokenTerm, text: text})
	return true
}
