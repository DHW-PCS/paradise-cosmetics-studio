// Package searchstring ports the frozen Blessing Skin 6.0.2 search string
// grammar (lorisleiva/laravel-search-string v1.1.3) for admin list filters.
//
// The parser reproduces Grammar.pp and its visitors: implicit AND, explicit
// and/or/not/in, quoted strings, comparisons, date precision ranges, keyword
// handling (sort/fields/limit/from) and the library's default fail policy
// (invalid input yields no constraints, i.e. all results). Known SQL failures
// return ErrInvalidQuery for a controlled HTTP request error.
package searchstring

import (
	"errors"
	"regexp"
	"time"
)

// ErrInvalidQuery identifies the approved request errors that would fail
// during SQL construction or execution in the frozen implementation.
var ErrInvalidQuery = errors.New("searchstring: invalid query")

// Kind is the node kind of a parsed search string expression.
type Kind string

const (
	KindEmpty        Kind = "empty"
	KindSolo         Kind = "solo"
	KindNot          Kind = "not"
	KindAnd          Kind = "and"
	KindOr           Kind = "or"
	KindQuery        Kind = "query"
	KindList         Kind = "list"
	KindRelationship Kind = "relationship"
)

// Node is the parsed case for the frozen Grammar.pp AST (after the Hoa
// converter). Relationship nodes are parsed so that unsupported relationship
// syntax is reported as invalid rather than silently treated as a term.
type Node struct {
	Kind     Kind
	Key      string
	Operator string // normalized '=' or comparator; query nodes only
	Value    string // scalar text (solo/query); never used for lists
	Null     bool   // nullable scalar was the NULL token
	Negated  bool   // solo/list negated by `not`
	Values   []string
	Expr     *Node
	Children []*Node
	IsIn     bool // list came from `key in (...)`
}

// Column describes one searchable column of a model. Pattern matches the key
// used in the query string and is the frozen library's key regex (without the
// PHP delimiters); an empty Pattern means the key must equal Name.
type Column struct {
	Name       string
	Pattern    string
	Searchable bool
	Boolean    bool
	Date       bool
}

// Schema declares the columns available to a search string.
type Schema struct {
	Columns  []Column
	Location *time.Location // date range timezone; nil means UTC
	// Now supplies the instant used when a date column receives NULL (the
	// frozen implementation parses NULL as "now"). Nil uses time.Now.
	Now func() time.Time
}

// Order is one ORDER BY entry after alias resolution.
type Order struct {
	Column string
	Desc   bool
}

// Result is the resolved SQL fragment for a search string. Where uses only
// schema column names and ? placeholders; Args matches the placeholders from
// left to right. Invalid reports the frozen library's fallback: the caller
// must ignore every other field and apply no constraints. Err takes precedence
// and must be returned to the caller instead of executing the query.
type Result struct {
	Where   string
	Args    []any
	Order   []Order
	Limit   *int
	Offset  *int
	Select  []string
	Invalid bool
	Err     error // ErrInvalidQuery requires a controlled request error.
}

// token kinds.
type tokenKind int

const (
	tokenEOF tokenKind = iota
	tokenAssign
	tokenComparator
	tokenAnd
	tokenOr
	tokenNot
	tokenIn
	tokenNull
	tokenString
	tokenLParen
	tokenRParen
	tokenDot
	tokenComma
	tokenInteger
	tokenDecimal
	tokenTerm
)

type token struct {
	kind tokenKind
	text string
}

// keyMatch compiles a column pattern once per column.
func (c Column) matches(key string) (bool, error) {
	if c.Pattern == "" {
		return c.Name == key, nil
	}
	re, err := regexp.Compile(c.Pattern)
	if err != nil {
		return false, err
	}
	return re.MatchString(key), nil
}
