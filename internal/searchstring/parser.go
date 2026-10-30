package searchstring

import "errors"

var errSyntax = errors.New("searchstring: invalid syntax")

type parser struct {
	toks []token
	pos  int
}

func parse(input string) (*Node, error) {
	toks, ok := lex(input)
	if !ok {
		return nil, errSyntax
	}
	p := &parser{toks: toks}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokenEOF {
		return nil, errSyntax
	}
	return node, nil
}

func (p *parser) peek() token { return p.toks[p.pos] }

func (p *parser) peekAt(offset int) token {
	if p.pos+offset >= len(p.toks) {
		return token{kind: tokenEOF}
	}
	return p.toks[p.pos+offset]
}

func (p *parser) advance() token {
	t := p.toks[p.pos]
	if t.kind != tokenEOF {
		p.pos++
	}
	return t
}

func (p *parser) parseOr() (*Node, error) {
	first, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	items := []*Node{first}
	for p.peek().kind == tokenOr {
		p.advance()
		next, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		items = append(items, next)
	}
	if len(items) == 1 {
		return items[0], nil
	}
	return &Node{Kind: KindOr, Children: items}, nil
}

func startsTerminal(k tokenKind) bool {
	switch k {
	case tokenTerm, tokenString, tokenInteger, tokenDecimal, tokenLParen, tokenNot:
		return true
	}
	return false
}

func (p *parser) parseAnd() (*Node, error) {
	first, err := p.parseTerminal()
	if err != nil {
		return nil, err
	}
	items := []*Node{first}
	for {
		if p.peek().kind == tokenAnd {
			p.advance()
			next, err := p.parseTerminal()
			if err != nil {
				return nil, err
			}
			items = append(items, next)
			continue
		}
		if !startsTerminal(p.peek().kind) {
			break
		}
		next, err := p.parseTerminal()
		if err != nil {
			return nil, err
		}
		items = append(items, next)
	}
	if len(items) == 1 {
		return items[0], nil
	}
	return &Node{Kind: KindAnd, Children: items}, nil
}

func (p *parser) expect(kind tokenKind) error {
	if p.peek().kind != kind {
		return errSyntax
	}
	p.advance()
	return nil
}

func (p *parser) parseTerminal() (*Node, error) {
	t := p.peek()
	switch t.kind {
	case tokenLParen:
		p.advance()
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if err = p.expect(tokenRParen); err != nil {
			return nil, err
		}
		return node, nil
	case tokenNot:
		p.advance()
		child, err := p.parseTerminal()
		if err != nil {
			return nil, err
		}
		return &Node{Kind: KindNot, Expr: child}, nil
	case tokenString, tokenInteger, tokenDecimal:
		p.advance()
		return &Node{Kind: KindSolo, Value: t.text}, nil
	case tokenTerm:
		p.advance()
		return p.parseAfterTerm(t.text)
	default:
		return nil, errSyntax
	}
}

func (p *parser) parseAfterTerm(key string) (*Node, error) {
	if p.peek().kind == tokenDot {
		for p.peek().kind == tokenDot {
			p.advance()
			if p.peek().kind != tokenTerm {
				return nil, errSyntax
			}
			p.advance()
		}
		if p.peek().kind == tokenAssign && p.peekAt(1).kind == tokenLParen {
			p.advance()
			return p.parseNestedRelationship(key)
		}
		if p.peek().kind == tokenAssign || p.peek().kind == tokenComparator {
			p.advance()
			if _, _, err := p.parseNullableScalar(); err != nil {
				return nil, err
			}
		}
		return &Node{Kind: KindRelationship, Key: key}, nil
	}
	switch p.peek().kind {
	case tokenIn:
		p.advance()
		if err := p.expect(tokenLParen); err != nil {
			return nil, err
		}
		values, err := p.parseScalarList()
		if err != nil {
			return nil, err
		}
		if err = p.expect(tokenRParen); err != nil {
			return nil, err
		}
		return &Node{Kind: KindList, Key: key, Values: values, IsIn: true}, nil
	case tokenAssign:
		p.advance()
		if p.peek().kind == tokenLParen {
			return p.parseNestedRelationship(key)
		}
		// Grammar order tries QueryNode before ListNode, so a single scalar is
		// a query; a trailing comma falls back to the list form.
		mark := p.pos
		value, isNull, err := p.parseNullableScalar()
		if err != nil {
			return nil, err
		}
		if !isNull && p.peek().kind == tokenComma {
			p.pos = mark
			values, err := p.parseScalarList()
			if err != nil {
				return nil, err
			}
			return &Node{Kind: KindList, Key: key, Values: values}, nil
		}
		return &Node{Kind: KindQuery, Key: key, Operator: "=", Value: value, Null: isNull}, nil
	case tokenComparator:
		operator := p.advance()
		value, isNull, err := p.parseNullableScalar()
		if err != nil {
			return nil, err
		}
		return &Node{Kind: KindQuery, Key: key, Operator: operator.text, Value: value, Null: isNull}, nil
	default:
		return &Node{Kind: KindSolo, Value: key}, nil
	}
}

func (p *parser) parseNestedRelationship(key string) (*Node, error) {
	p.advance() // LPAREN
	expression, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if err := p.expect(tokenRParen); err != nil {
		return nil, err
	}
	if p.peek().kind == tokenAssign || p.peek().kind == tokenComparator {
		p.advance()
		if p.peek().kind != tokenInteger {
			return nil, errSyntax
		}
		p.advance()
	}
	return &Node{Kind: KindRelationship, Key: key, Expr: expression}, nil
}

// parseNullableScalar parses Scalar or the NULL token.
func (p *parser) parseNullableScalar() (string, bool, error) {
	if p.peek().kind == tokenNull {
		p.advance()
		return "", true, nil
	}
	value, err := p.parseScalar()
	return value, false, err
}

func (p *parser) parseScalar() (string, error) {
	t := p.peek()
	switch t.kind {
	case tokenString, tokenInteger, tokenDecimal, tokenTerm:
		p.advance()
		return t.text, nil
	default:
		return "", errSyntax
	}
}

func (p *parser) parseScalarList() ([]string, error) {
	first, err := p.parseScalar()
	if err != nil {
		return nil, err
	}
	values := []string{first}
	for p.peek().kind == tokenComma {
		p.advance()
		next, err := p.parseScalar()
		if err != nil {
			return nil, err
		}
		values = append(values, next)
	}
	return values, nil
}
