package searchstring

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// keywordName returns the frozen default keyword for a key, if any.
func keywordName(key string) string {
	switch key {
	case "sort":
		return "order_by"
	case "fields":
		return "select"
	case "limit":
		return "limit"
	case "from":
		return "offset"
	}
	return ""
}

type rule struct {
	column  *Column
	keyword string
}

type builder struct {
	schema                      Schema
	nowFn                       func() time.Time
	rules                       map[*Node]rule
	order                       []Order
	limit                       *int
	offset                      *int
	selects                     []string
	err                         error
	orderInvalid, selectInvalid bool
}

// Build resolves a frozen search string against a schema. An empty or invalid
// string follows the library's default fail policy: no constraints at all.
func Build(input string, schema Schema) Result {
	if input == "" || input == "0" {
		return Result{}
	}
	node, err := parse(input)
	if err != nil {
		return Result{Invalid: true}
	}
	b := &builder{schema: schema, rules: map[*Node]rule{}, nowFn: schema.Now}
	if err = b.attach(node); err != nil {
		if errors.Is(err, ErrInvalidQuery) {
			return Result{Err: err}
		}
		return Result{Invalid: true}
	}
	if err = b.validate(node); err != nil {
		if errors.Is(err, ErrInvalidQuery) {
			return Result{Err: err}
		}
		return Result{Invalid: true}
	}
	node = removeNot(node, false)
	node = b.keywords(node)
	if b.orderInvalid || b.selectInvalid {
		return Result{Err: ErrInvalidQuery}
	}
	if b.err != nil {
		// The frozen library catches the invalid keyword and returns the
		// builder state that was already applied before the failure; the WHERE
		// builder never ran. Only the earlier keywords survive.
		return Result{Order: b.order, Limit: b.limit, Offset: b.offset, Select: b.selects}
	}
	node = optimize(node)
	where, err := b.where(node)
	if err != nil {
		return Result{Invalid: true}
	}
	out := Result{Order: b.order, Limit: b.limit, Offset: b.offset, Select: b.selects}
	if where != nil {
		out.Where = where.render(&out.Args)
	}
	return out
}

// Parse exposes the frozen grammar's converted AST for parity checks.
func Parse(input string) (*Node, error) {
	if input == "" || input == "0" {
		return &Node{Kind: KindEmpty}, nil
	}
	return parse(input)
}

// attach mirrors AttachRulesVisitor: solos match columns only, queries and
// lists match keywords first and then columns.
func (b *builder) attach(node *Node) error {
	switch node.Kind {
	case KindAnd, KindOr:
		for _, child := range node.Children {
			if err := b.attach(child); err != nil {
				return err
			}
		}
	case KindNot:
		return b.attach(node.Expr)
	case KindSolo:
		b.rules[node] = rule{column: b.columnRule(node.Value)}
	case KindQuery, KindList:
		if name := keywordName(node.Key); name != "" {
			b.rules[node] = rule{keyword: name}
			return nil
		}
		b.rules[node] = rule{column: b.columnRule(node.Key)}
	case KindRelationship:
		// No M3 schema declares relationship columns.
		if b.columnRule(node.Key) != nil {
			return ErrInvalidQuery
		}
	}
	return nil
}

func (b *builder) columnRule(key string) *Column {
	for i := range b.schema.Columns {
		ok, err := b.schema.Columns[i].matches(key)
		if err != nil {
			continue
		}
		if ok {
			return &b.schema.Columns[i]
		}
	}
	return nil
}

// validate mirrors ValidateRulesVisitor: query/list/relationship keys must be
// recognized; solos may fall back to the searchable text search.
func (b *builder) validate(node *Node) error {
	switch node.Kind {
	case KindAnd, KindOr:
		for _, child := range node.Children {
			if err := b.validate(child); err != nil {
				return err
			}
		}
	case KindNot:
		return b.validate(node.Expr)
	case KindQuery, KindList:
		if r := b.rules[node]; r.column == nil && r.keyword == "" {
			return fmt.Errorf("unrecognized key %q", node.Key)
		}
	case KindRelationship:
		return fmt.Errorf("unsupported relationship")
	}
	return nil
}

// removeNot mirrors RemoveNotSymbolVisitor: De Morgan, comparator reversal and
// solo/list negation.
func removeNot(node *Node, negate bool) *Node {
	switch node.Kind {
	case KindAnd, KindOr:
		children := make([]*Node, 0, len(node.Children))
		for _, child := range node.Children {
			children = append(children, removeNot(child, negate))
		}
		if negate {
			kind := KindOr
			if node.Kind == KindOr {
				kind = KindAnd
			}
			return &Node{Kind: kind, Children: children}
		}
		return &Node{Kind: node.Kind, Children: children}
	case KindNot:
		return removeNot(node.Expr, !negate)
	case KindSolo:
		if negate {
			node.Negated = !node.Negated
		}
		return node
	case KindList:
		if negate {
			node.Negated = !node.Negated
		}
		return node
	case KindQuery:
		if negate {
			node.Operator = reverseOperator(node.Operator)
		}
		return node
	case KindRelationship:
		return node
	}
	return node
}

func reverseOperator(operator string) string {
	switch operator {
	case "=":
		return "!="
	case "!=":
		return "="
	case ">":
		return "<="
	case ">=":
		return "<"
	case "<":
		return ">="
	case "<=":
		return ">"
	}
	return operator
}

func (b *builder) keywords(node *Node) *Node {
	if b.err != nil {
		return &Node{Kind: KindEmpty}
	}
	switch node.Kind {
	case KindAnd, KindOr:
		children := make([]*Node, 0, len(node.Children))
		for _, child := range node.Children {
			children = append(children, b.keywords(child))
		}
		return &Node{Kind: node.Kind, Children: children}
	case KindNot:
		return &Node{Kind: KindNot, Expr: b.keywords(node.Expr)}
	case KindQuery, KindList:
		r := b.rules[node]
		if r.keyword == "" {
			return node
		}
		b.applyKeyword(r.keyword, node)
		return &Node{Kind: KindEmpty}
	}
	return node
}

func (b *builder) applyKeyword(keyword string, node *Node) {
	if node.Null {
		b.fail()
		return
	}
	values := []string{node.Value}
	if node.Kind == KindList {
		values = node.Values
	}
	switch keyword {
	case "limit", "offset":
		if len(values) != 1 || !digits(values[0]) {
			b.fail()
			return
		}
		n, err := strconv.Atoi(values[0])
		if err != nil {
			b.fail()
			return
		}
		if keyword == "limit" {
			b.limit = &n
		} else {
			b.offset = &n
		}
	case "order_by":
		b.order = nil
		b.orderInvalid = false
		for _, value := range values {
			desc := strings.HasPrefix(value, "-")
			column := strings.TrimPrefix(value, "-")
			resolved, ok := b.resolveColumn(column)
			if !ok {
				b.orderInvalid = true
				continue
			}
			b.order = append(b.order, Order{Column: resolved, Desc: desc})
		}
	case "select":
		selected := map[string]bool{}
		for _, value := range values {
			resolved, ok := b.resolveColumn(value)
			if !ok {
				continue
			}
			selected[resolved] = true
		}
		b.selects = nil
		negated := node.Negated || node.Operator == "!="
		for _, column := range b.schema.Columns {
			wanted := selected[column.Name]
			if negated {
				wanted = !wanted
			}
			if wanted {
				b.selects = append(b.selects, column.Name)
			}
		}
		if len(b.selects) == 0 {
			b.selectInvalid = true
		} else {
			b.selectInvalid = false
		}
	}
}

func (b *builder) resolveColumn(value string) (string, bool) {
	for _, column := range b.schema.Columns {
		ok, err := column.matches(value)
		if err == nil && ok {
			return column.Name, true
		}
	}
	return "", false
}

func digits(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func (b *builder) fail() { b.err = errSyntax }

func optimize(node *Node) *Node {
	switch node.Kind {
	case KindAnd, KindOr:
		children := make([]*Node, 0, len(node.Children))
		for _, child := range node.Children {
			child = optimize(child)
			if child.Kind == KindEmpty {
				continue
			}
			if child.Kind == node.Kind {
				children = append(children, child.Children...)
				continue
			}
			children = append(children, child)
		}
		if len(children) == 0 {
			return &Node{Kind: KindEmpty}
		}
		if len(children) == 1 {
			return children[0]
		}
		return &Node{Kind: node.Kind, Children: children}
	case KindNot:
		child := optimize(node.Expr)
		if child.Kind == KindEmpty {
			return child
		}
		return &Node{Kind: KindNot, Expr: child}
	}
	return node
}

// whereNode is the canonical SQL tree. Rendering also appends bindings so the
// caller receives them in placeholder order.
type whereNode struct {
	kind     string // "cond", "null", "in", "group"
	groupOp  string // "AND" / "OR"
	children []*whereNode
	column   string
	operator string
	values   []any
	not      bool
}

func (w *whereNode) render(args *[]any) string {
	if w == nil {
		return ""
	}
	switch w.kind {
	case "group":
		parts := make([]string, 0, len(w.children))
		for _, child := range w.children {
			parts = append(parts, child.render(args))
		}
		return "(" + strings.Join(parts, " "+w.groupOp+" ") + ")"
	case "null":
		if w.not {
			return w.column + " IS NOT NULL"
		}
		return w.column + " IS NULL"
	case "in":
		marks := make([]string, len(w.values))
		for i, value := range w.values {
			marks[i] = "?"
			*args = append(*args, value)
		}
		if w.not {
			return w.column + " NOT IN (" + strings.Join(marks, ", ") + ")"
		}
		return w.column + " IN (" + strings.Join(marks, ", ") + ")"
	default:
		*args = append(*args, w.values...)
		return w.column + " " + w.operator + " ?"
	}
}

func (b *builder) where(node *Node) (*whereNode, error) {
	switch node.Kind {
	case KindEmpty:
		return nil, nil
	case KindAnd, KindOr:
		op := "AND"
		if node.Kind == KindOr {
			op = "OR"
		}
		children := make([]*whereNode, 0, len(node.Children))
		for _, child := range node.Children {
			part, err := b.where(child)
			if err != nil {
				return nil, err
			}
			if part != nil {
				children = append(children, part)
			}
		}
		if len(children) == 0 {
			return nil, nil
		}
		if len(children) == 1 {
			return children[0], nil
		}
		return &whereNode{kind: "group", groupOp: op, children: children}, nil
	case KindSolo:
		return b.solo(node), nil
	case KindQuery:
		return b.query(node), nil
	case KindList:
		return b.list(node), nil
	case KindNot:
		return b.where(node.Expr)
	}
	return nil, nil
}

func (b *builder) solo(node *Node) *whereNode {
	r := b.rules[node]
	if r.column != nil && r.column.Boolean && r.column.Date {
		return &whereNode{kind: "null", column: r.column.Name, not: !node.Negated}
	}
	if r.column != nil && r.column.Boolean {
		return &whereNode{kind: "cond", column: r.column.Name, operator: "=", values: []any{!node.Negated}}
	}
	var searchable []Column
	for _, column := range b.schema.Columns {
		if column.Searchable {
			searchable = append(searchable, column)
		}
	}
	if len(searchable) == 0 {
		return nil
	}
	operator, joiner := "LIKE", "OR"
	if node.Negated {
		operator, joiner = "NOT LIKE", "AND"
	}
	children := make([]*whereNode, 0, len(searchable))
	for _, column := range searchable {
		children = append(children, &whereNode{kind: "cond", column: column.Name, operator: operator, values: []any{"%" + node.Value + "%"}})
	}
	if len(children) == 1 {
		return children[0]
	}
	return &whereNode{kind: "group", groupOp: joiner, children: children}
}

func (b *builder) query(node *Node) *whereNode {
	r := b.rules[node]
	if r.column == nil {
		return nil
	}
	rule := *r.column
	if node.Null {
		// Frozen behaviour: a NULL value on a date column reaches
		// DateWithPrecision(null), which Carbon parses as "now"; the range is
		// now's precision window. Non-date columns keep SQL null semantics.
		if rule.Date {
			if condition, ok := b.nullDateCondition(rule, node.Operator); ok {
				return condition
			}
		}
		return &whereNode{kind: "null", column: rule.Name, not: node.Operator != "="}
	}
	value := numericValue(node.Value)
	if rule.Date {
		if condition, ok := b.dateCondition(rule, node.Operator, value); ok {
			return condition
		}
	}
	return &whereNode{kind: "cond", column: rule.Name, operator: node.Operator, values: []any{value}}
}

// nullDateCondition resolves a NULL scalar on a date column the way the frozen
// implementation does: Carbon::parse(null) yields the current instant, whose
// first non-zero component decides the precision window.
func (b *builder) nullDateCondition(column Column, operator string) (*whereNode, bool) {
	now := b.now().In(b.location())
	return b.rangeCondition(column, operator, parsedDate{
		start: buildDateRange(now, precisionOf(now), b.location()).start,
		end:   buildDateRange(now, precisionOf(now), b.location()).end,
		exact: precisionOf(now) <= precisionSecond,
	})
}

func (b *builder) now() time.Time {
	if b.nowFn != nil {
		return b.nowFn()
	}
	return time.Now()
}

func (b *builder) location() *time.Location {
	if b.schema.Location != nil {
		return b.schema.Location
	}
	return time.UTC
}

func (b *builder) dateCondition(column Column, operator string, value any) (*whereNode, bool) {
	text := dateText(value)
	if strings.TrimSpace(text) == "" {
		// Carbon::parse('') and parse(' ') both resolve to the current instant.
		return b.nullDateCondition(column, operator)
	}
	parsed, ok := parseDate(text, b.schema.Location)
	if !ok {
		return nil, false
	}
	return b.rangeCondition(column, operator, parsed)
}

func (b *builder) rangeCondition(column Column, operator string, parsed parsedDate) (*whereNode, bool) {
	if parsed.exact {
		return &whereNode{kind: "cond", column: column.Name, operator: operator, values: []any{formatDate(parsed.start, b.schema.Location)}}, true
	}
	switch operator {
	case "<", ">=":
		return &whereNode{kind: "cond", column: column.Name, operator: operator, values: []any{formatDate(parsed.start, b.schema.Location)}}, true
	case ">", "<=":
		return &whereNode{kind: "cond", column: column.Name, operator: operator, values: []any{formatDate(parsed.end, b.schema.Location)}}, true
	}
	if operator == "!=" {
		// Frozen BuildColumnsVisitor joins both conditions with AND, making the
		// range impossible; reproduced verbatim.
		return &whereNode{kind: "group", groupOp: "AND", children: []*whereNode{
			{kind: "cond", column: column.Name, operator: "<", values: []any{formatDate(parsed.start, b.schema.Location)}},
			{kind: "cond", column: column.Name, operator: ">", values: []any{formatDate(parsed.end, b.schema.Location)}},
		}}, true
	}
	return &whereNode{kind: "group", groupOp: "AND", children: []*whereNode{
		{kind: "cond", column: column.Name, operator: ">=", values: []any{formatDate(parsed.start, b.schema.Location)}},
		{kind: "cond", column: column.Name, operator: "<=", values: []any{formatDate(parsed.end, b.schema.Location)}},
	}}, true
}

func (b *builder) list(node *Node) *whereNode {
	r := b.rules[node]
	if r.column == nil {
		return nil
	}
	values := make([]any, len(node.Values))
	for i, value := range node.Values {
		values[i] = value
	}
	return &whereNode{kind: "in", column: r.column.Name, values: values, not: node.Negated}
}

// numericValue mirrors PHP's is_numeric conversion in mapValue.
func numericValue(value string) any {
	trimmed := strings.TrimLeft(value, " \t\n\r\v\f")
	if trimmed == "" {
		return value
	}
	if !phpNumeric(trimmed) {
		return value
	}
	if integer, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		return integer
	}
	if number, err := strconv.ParseFloat(trimmed, 64); err == nil {
		if number == math.Trunc(number) && number >= math.MinInt64 && number <= math.MaxInt64 {
			return int64(number)
		}
		return number
	}
	return value
}

// phpNumeric follows the decimal subset of PHP 7/8 is_numeric: optional
// leading whitespace, sign, digits with optional fraction, optional exponent.
func phpNumeric(value string) bool {
	i := 0
	if i < len(value) && (value[i] == '+' || value[i] == '-') {
		i++
	}
	digitsBefore := 0
	for i < len(value) && value[i] >= '0' && value[i] <= '9' {
		i++
		digitsBefore++
	}
	digitsAfter := 0
	if i < len(value) && value[i] == '.' {
		i++
		for i < len(value) && value[i] >= '0' && value[i] <= '9' {
			i++
			digitsAfter++
		}
	}
	if digitsBefore == 0 && digitsAfter == 0 {
		return false
	}
	if i < len(value) && (value[i] == 'e' || value[i] == 'E') {
		i++
		if i < len(value) && (value[i] == '+' || value[i] == '-') {
			i++
		}
		digits := 0
		for i < len(value) && value[i] >= '0' && value[i] <= '9' {
			i++
			digits++
		}
		if digits == 0 {
			return false
		}
	}
	return i == len(value)
}

func dateText(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return fmt.Sprint(value)
}
