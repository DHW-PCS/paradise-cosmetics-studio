// Package php implements a restricted reader and writer for the subset of
// PHP's serialize() format used by Laravel sessions and cookies.
//
// Only null, bool, int, float, string and ordered arrays are supported.
// Objects are inert data and require an explicit class allowlist. The default
// session decoder rejects objects, references and custom-serialized values.
package php

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Limits bounds the resources a single payload may consume.
type Limits struct {
	MaxDepth    int
	MaxString   int
	MaxElements int
}

// DefaultLimits are used by Unmarshal and Marshal.
var DefaultLimits = Limits{
	MaxDepth:    64,
	MaxString:   8 << 20,
	MaxElements: 100000,
}

var (
	ErrSyntax      = errors.New("php: malformed serialized data")
	ErrUnsupported = errors.New("php: unsupported serialized type")
	ErrLimit       = errors.New("php: serialized data exceeds limit")
)

// Key is either an integer or a string array key, as PHP allows both.
type Key struct {
	IsInt bool
	Int   int64
	Str   string
}

// IntKey and StrKey build array keys.
func IntKey(v int64) Key  { return Key{IsInt: true, Int: v} }
func StrKey(v string) Key { return Key{Str: v} }

// Entry preserves PHP's insertion order.
type Entry struct {
	Key   Key
	Value Value
}

// Array is an ordered PHP array.
type Array struct {
	Entries []Entry
}

// Object is inert public-property data; decoding never constructs PHP classes.
type Object struct {
	Class      string
	Properties *Array
}

// Value is a decoded PHP scalar, *Array or explicitly allowed *Object.
type Value any

// NewArray returns an empty array.
func NewArray() *Array { return &Array{} }

// Set appends or replaces a string-keyed entry.
func (a *Array) Set(key string, v Value) *Array {
	for i := range a.Entries {
		if !a.Entries[i].Key.IsInt && a.Entries[i].Key.Str == key {
			a.Entries[i].Value = v
			return a
		}
	}
	a.Entries = append(a.Entries, Entry{Key: StrKey(key), Value: v})
	return a
}

// Get returns a string-keyed entry.
func (a *Array) Get(key string) (Value, bool) {
	if a == nil {
		return nil, false
	}
	for i := range a.Entries {
		if !a.Entries[i].Key.IsInt && a.Entries[i].Key.Str == key {
			return a.Entries[i].Value, true
		}
	}
	return nil, false
}

// Append adds a value with the next integer key, like PHP's $array[] = $value.
func (a *Array) Append(v Value) *Array {
	var next int64
	for _, entry := range a.Entries {
		if entry.Key.IsInt && entry.Key.Int >= next {
			next = entry.Key.Int + 1
		}
	}
	a.Entries = append(a.Entries, Entry{Key: IntKey(next), Value: v})
	return a
}

// Delete removes all entries with the given string key.
func (a *Array) Delete(key string) {
	kept := a.Entries[:0]
	for _, entry := range a.Entries {
		if !entry.Key.IsInt && entry.Key.Str == key {
			continue
		}
		kept = append(kept, entry)
	}
	a.Entries = kept
}

// GetString returns a string entry.
func (a *Array) GetString(key string) (string, bool) {
	v, ok := a.Get(key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// GetArray returns an array entry.
func (a *Array) GetArray(key string) (*Array, bool) {
	v, ok := a.Get(key)
	if !ok {
		return nil, false
	}
	arr, ok := v.(*Array)
	return arr, ok
}

// GetInt returns an int entry.
func (a *Array) GetInt(key string) (int64, bool) {
	v, ok := a.Get(key)
	if !ok {
		return 0, false
	}
	i, ok := v.(int64)
	return i, ok
}

// GetBool returns a bool entry.
func (a *Array) GetBool(key string) (bool, bool) {
	v, ok := a.Get(key)
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// GetPath resolves Laravel-style dot notation ("_flash.old") against nested
// arrays. Numeric segments fall back to integer keys.
func (a *Array) GetPath(path string) (Value, bool) {
	var current Value = a
	for _, segment := range strings.Split(path, ".") {
		arr, ok := current.(*Array)
		if !ok {
			return nil, false
		}
		next, ok := arr.Get(segment)
		if !ok {
			if n, err := strconv.ParseInt(segment, 10, 64); err == nil {
				for i := range arr.Entries {
					if arr.Entries[i].Key.IsInt && arr.Entries[i].Key.Int == n {
						next, ok = arr.Entries[i].Value, true
						break
					}
				}
			}
		}
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

// Unmarshal decodes one serialized value with DefaultLimits.
func Unmarshal(data []byte) (Value, error) {
	return UnmarshalLimited(data, DefaultLimits)
}

// UnmarshalLimited decodes one serialized value and rejects trailing bytes.
func UnmarshalLimited(data []byte, limits Limits) (Value, error) {
	p := &parser{data: data, limits: normalize(limits)}
	v, err := p.parse(0)
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.data) {
		return nil, p.failf("trailing data at offset %d", p.pos)
	}
	return v, nil
}

// UnmarshalObjects opts into inert objects of exactly the named classes.
// References and custom serialization remain unsupported.
func UnmarshalObjects(data []byte, classes ...string) (Value, error) {
	p := &parser{data: data, limits: normalize(DefaultLimits), classes: map[string]bool{}}
	for _, c := range classes {
		p.classes[c] = true
	}
	v, e := p.parse(0)
	if e != nil {
		return nil, e
	}
	if p.pos != len(data) {
		return nil, ErrSyntax
	}
	return v, nil
}

// Marshal encodes a value with DefaultLimits.
func Marshal(v Value) ([]byte, error) {
	var b strings.Builder
	if err := marshalValue(&b, v, 0, normalize(DefaultLimits)); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func normalize(l Limits) Limits {
	if l.MaxDepth <= 0 {
		l.MaxDepth = DefaultLimits.MaxDepth
	}
	if l.MaxString <= 0 {
		l.MaxString = DefaultLimits.MaxString
	}
	if l.MaxElements <= 0 {
		l.MaxElements = DefaultLimits.MaxElements
	}
	return l
}

type parser struct {
	data    []byte
	pos     int
	limits  Limits
	classes map[string]bool
}

func (p *parser) failf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrSyntax, fmt.Sprintf(format, args...))
}

func (p *parser) parse(depth int) (Value, error) {
	if depth > p.limits.MaxDepth {
		return nil, fmt.Errorf("%w: depth > %d", ErrLimit, p.limits.MaxDepth)
	}
	if p.pos >= len(p.data) {
		return nil, p.failf("unexpected end of data")
	}

	kind := p.data[p.pos]
	p.pos++

	switch kind {
	case 'N':
		if err := p.expect(';'); err != nil {
			return nil, err
		}
		return nil, nil
	case 'b':
		if err := p.expect(':'); err != nil {
			return nil, err
		}
		raw, err := p.readUntil(';')
		if err != nil {
			return nil, err
		}
		switch string(raw) {
		case "0":
			return false, nil
		case "1":
			return true, nil
		}
		return nil, p.failf("invalid bool %q", raw)
	case 'i':
		if err := p.expect(':'); err != nil {
			return nil, err
		}
		raw, err := p.readUntil(';')
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil {
			return nil, p.failf("invalid int %q", raw)
		}
		return n, nil
	case 'd':
		if err := p.expect(':'); err != nil {
			return nil, err
		}
		raw, err := p.readUntil(';')
		if err != nil {
			return nil, err
		}
		f, err := parseFloat(string(raw))
		if err != nil {
			return nil, p.failf("invalid float %q", raw)
		}
		return f, nil
	case 's':
		s, err := p.readString()
		if err != nil {
			return nil, err
		}
		return s, nil
	case 'a':
		return p.readArray(depth)
	case 'O':
		if err := p.expect(':'); err != nil {
			return nil, err
		}
		raw, e := p.readUntil(':')
		if e != nil {
			return nil, e
		}
		n, e := strconv.Atoi(string(raw))
		if e != nil || n < 1 || n > 256 || p.expect('"') != nil || n > len(p.data)-p.pos {
			return nil, ErrSyntax
		}
		c := string(p.data[p.pos : p.pos+n])
		p.pos += n
		if p.expect('"') != nil || !p.classes[c] {
			return nil, ErrUnsupported
		}
		v, e := p.readArray(depth)
		if e != nil {
			return nil, e
		}
		a := v.(*Array)
		seen := map[string]bool{}
		for _, item := range a.Entries {
			if item.Key.IsInt || strings.ContainsRune(item.Key.Str, 0) || seen[item.Key.Str] {
				return nil, ErrSyntax
			}
			seen[item.Key.Str] = true
		}
		return &Object{c, a}, nil
	default:
		return nil, fmt.Errorf("%w: type %q at offset %d", ErrUnsupported, kind, p.pos-1)
	}
}

func (p *parser) expect(c byte) error {
	if p.pos >= len(p.data) || p.data[p.pos] != c {
		return p.failf("expected %q at offset %d", c, p.pos)
	}
	p.pos++
	return nil
}

func (p *parser) readUntil(c byte) ([]byte, error) {
	start := p.pos
	for p.pos < len(p.data) && p.data[p.pos] != c {
		p.pos++
	}
	if p.pos >= len(p.data) {
		return nil, p.failf("unterminated value at offset %d", start)
	}
	raw := p.data[start:p.pos]
	p.pos++ // consume terminator
	return raw, nil
}

func (p *parser) readString() (string, error) {
	if err := p.expect(':'); err != nil {
		return "", err
	}
	lenRaw, err := p.readUntil(':')
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(string(lenRaw))
	if err != nil || n < 0 {
		return "", p.failf("invalid string length %q", lenRaw)
	}
	if n > p.limits.MaxString {
		return "", fmt.Errorf("%w: string length %d > %d", ErrLimit, n, p.limits.MaxString)
	}
	if err := p.expect('"'); err != nil {
		return "", err
	}
	if p.pos+n > len(p.data) {
		return "", p.failf("string length %d exceeds buffer at offset %d", n, p.pos)
	}
	s := string(p.data[p.pos : p.pos+n])
	p.pos += n
	if err := p.expect('"'); err != nil {
		return "", err
	}
	if err := p.expect(';'); err != nil {
		return "", err
	}
	return s, nil
}

func (p *parser) readArray(depth int) (Value, error) {
	if err := p.expect(':'); err != nil {
		return nil, err
	}
	countRaw, err := p.readUntil(':')
	if err != nil {
		return nil, err
	}
	count, err := strconv.Atoi(string(countRaw))
	if err != nil || count < 0 {
		return nil, p.failf("invalid array length %q", countRaw)
	}
	if count > p.limits.MaxElements {
		return nil, fmt.Errorf("%w: array elements %d > %d", ErrLimit, count, p.limits.MaxElements)
	}
	if err := p.expect('{'); err != nil {
		return nil, err
	}

	arr := &Array{Entries: make([]Entry, 0, min(count, 16))}
	for i := 0; i < count; i++ {
		key, err := p.readKey()
		if err != nil {
			return nil, err
		}
		value, err := p.parse(depth + 1)
		if err != nil {
			return nil, err
		}
		arr.Entries = append(arr.Entries, Entry{Key: key, Value: value})
	}
	if err := p.expect('}'); err != nil {
		return nil, err
	}
	return arr, nil
}

func (p *parser) readKey() (Key, error) {
	if p.pos >= len(p.data) {
		return Key{}, p.failf("unexpected end of array key")
	}
	switch p.data[p.pos] {
	case 'i':
		p.pos++
		if err := p.expect(':'); err != nil {
			return Key{}, err
		}
		raw, err := p.readUntil(';')
		if err != nil {
			return Key{}, err
		}
		n, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil {
			return Key{}, p.failf("invalid int key %q", raw)
		}
		return IntKey(n), nil
	case 's':
		p.pos++
		s, err := p.readString()
		if err != nil {
			return Key{}, err
		}
		return StrKey(s), nil
	default:
		return Key{}, p.failf("invalid array key type %q at offset %d", p.data[p.pos], p.pos)
	}
}

func parseFloat(raw string) (float64, error) {
	switch raw {
	case "INF":
		return math.Inf(1), nil
	case "-INF":
		return math.Inf(-1), nil
	case "NAN":
		return math.NaN(), nil
	}
	return strconv.ParseFloat(raw, 64)
}

func marshalValue(b *strings.Builder, v Value, depth int, limits Limits) error {
	if depth > limits.MaxDepth {
		return fmt.Errorf("%w: depth > %d", ErrLimit, limits.MaxDepth)
	}
	switch value := v.(type) {
	case nil:
		b.WriteString("N;")
	case bool:
		if value {
			b.WriteString("b:1;")
		} else {
			b.WriteString("b:0;")
		}
	case int:
		fmt.Fprintf(b, "i:%d;", value)
	case int64:
		fmt.Fprintf(b, "i:%d;", value)
	case float64:
		// Best effort: PHP's serialize_precision=-1 formatting is matched for
		// finite values that round-trip through the shortest representation.
		switch {
		case math.IsInf(value, 1):
			b.WriteString("d:INF;")
		case math.IsInf(value, -1):
			b.WriteString("d:-INF;")
		case math.IsNaN(value):
			b.WriteString("d:NAN;")
		default:
			fmt.Fprintf(b, "d:%s;", strconv.FormatFloat(value, 'g', -1, 64))
		}
	case string:
		if len(value) > limits.MaxString {
			return fmt.Errorf("%w: string length %d > %d", ErrLimit, len(value), limits.MaxString)
		}
		fmt.Fprintf(b, "s:%d:\"", len(value))
		b.WriteString(value)
		b.WriteString("\";")
	case *Object:
		if value == nil || value.Properties == nil {
			return ErrUnsupported
		}
		var props strings.Builder
		if e := marshalValue(&props, value.Properties, depth, limits); e != nil {
			return e
		}
		body := props.String()
		fmt.Fprintf(b, "O:%d:\"%s\"%s", len(value.Class), value.Class, body[1:])
	case *Array:
		if value == nil {
			b.WriteString("N;")
			return nil
		}
		if len(value.Entries) > limits.MaxElements {
			return fmt.Errorf("%w: array elements %d > %d", ErrLimit, len(value.Entries), limits.MaxElements)
		}
		fmt.Fprintf(b, "a:%d:{", len(value.Entries))
		for _, entry := range value.Entries {
			if entry.Key.IsInt {
				fmt.Fprintf(b, "i:%d;", entry.Key.Int)
			} else {
				if len(entry.Key.Str) > limits.MaxString {
					return fmt.Errorf("%w: key length %d > %d", ErrLimit, len(entry.Key.Str), limits.MaxString)
				}
				fmt.Fprintf(b, "s:%d:\"", len(entry.Key.Str))
				b.WriteString(entry.Key.Str)
				b.WriteString("\";")
			}
			if err := marshalValue(b, entry.Value, depth+1, limits); err != nil {
				return err
			}
		}
		b.WriteString("}")
	default:
		return fmt.Errorf("%w: Go type %T", ErrUnsupported, v)
	}
	return nil
}
