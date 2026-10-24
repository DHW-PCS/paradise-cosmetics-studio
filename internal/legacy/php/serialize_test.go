package php

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestUnmarshalScalars(t *testing.T) {
	cases := []struct {
		in   string
		want Value
	}{
		{"N;", nil},
		{"b:0;", false},
		{"b:1;", true},
		{"i:0;", int64(0)},
		{"i:-42;", int64(-42)},
		{"i:9223372036854775807;", int64(9223372036854775807)},
		{"d:0.1;", float64(0.1)},
		{"d:INF;", math.Inf(1)},
		{`s:5:"hello";`, "hello"},
		{`s:0:"";`, ""},
		{`s:6:"张三";`, "张三"},
	}
	for _, c := range cases {
		got, err := Unmarshal([]byte(c.in))
		if err != nil {
			t.Fatalf("Unmarshal(%q): %v", c.in, err)
		}
		if !reflect.DeepEqual(got, c.want) && !(isNaN(got) && isNaN(c.want)) {
			t.Fatalf("Unmarshal(%q) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

func isNaN(v Value) bool {
	f, ok := v.(float64)
	return ok && f != f
}

func TestUnmarshalArrayOrderAndKeys(t *testing.T) {
	in := `a:4:{i:0;s:1:"a";i:1;s:1:"b";s:3:"key";i:7;s:4:"_tok";b:1;}`
	v, err := Unmarshal([]byte(in))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	arr, ok := v.(*Array)
	if !ok {
		t.Fatalf("want *Array, got %T", v)
	}
	if len(arr.Entries) != 4 {
		t.Fatalf("entries = %d, want 4", len(arr.Entries))
	}
	if !arr.Entries[0].Key.IsInt || arr.Entries[0].Key.Int != 0 {
		t.Fatalf("first key = %#v", arr.Entries[0].Key)
	}
	if arr.Entries[2].Key.IsInt || arr.Entries[2].Key.Str != "key" {
		t.Fatalf("third key = %#v", arr.Entries[2].Key)
	}
	if got, _ := arr.GetInt("key"); got != 7 {
		t.Fatalf("key = %d, want 7", got)
	}
	if got, _ := arr.GetBool("_tok"); !got {
		t.Fatal("_tok should be true")
	}
}

func TestGetPath(t *testing.T) {
	in := `a:1:{s:6:"_flash";a:2:{s:3:"old";a:1:{i:0;s:1:"x";}s:3:"new";a:1:{i:0;s:1:"y";}}}`
	v, err := Unmarshal([]byte(in))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	arr := v.(*Array)
	old, ok := arr.GetPath("_flash.old.0")
	if !ok || old != "x" {
		t.Fatalf("_flash.old.0 = %#v, %v", old, ok)
	}
	if _, ok := arr.GetPath("_flash.missing"); ok {
		t.Fatal("missing path should not resolve")
	}
}

func TestRoundTrip(t *testing.T) {
	original := NewArray().
		Set("_token", "0123456789012345678901234567890123456789").
		Set("login_web_x", int64(1)).
		Set("nested", NewArray().Set("a", "中文").Set("b", true))
	encoded, err := Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	decoded, err := Unmarshal(encoded)
	if err != nil {
		t.Fatalf("Unmarshal(%q): %v", encoded, err)
	}
	if !reflect.DeepEqual(original, decoded) {
		t.Fatalf("round trip mismatch:\n got %#v\nwant %#v", decoded, original)
	}
}

func TestMarshalEmptyArray(t *testing.T) {
	got, err := Marshal(NewArray())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(got) != "a:0:{}" {
		t.Fatalf("empty array = %q, want a:0:{}", got)
	}
}

func TestUnmarshalRejectsUnsafeTypes(t *testing.T) {
	for _, in := range []string{
		`O:8:"stdClass":0:{}`,
		`C:11:"ArrayObject":0:{}`,
		`R:1;`,
		`r:1;`,
		`S:5:"\61bc";`,
	} {
		if _, err := Unmarshal([]byte(in)); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Unmarshal(%q) error = %v, want ErrUnsupported", in, err)
		}
	}
}

func TestUnmarshalRejectsMalformed(t *testing.T) {
	for _, in := range []string{
		"",
		"N",
		"i:abc;",
		`s:5:"abc";`,
		`s:3:"abcd";`,
		`s:1:"ab";`,
		`a:2:{i:0;s:1:"a";}`,
		`a:1:{d:1;i:1;}`,
		`a:0:{}trailing`,
		`a:1:{i:0;i:1;}x`,
	} {
		if _, err := Unmarshal([]byte(in)); err == nil {
			t.Fatalf("Unmarshal(%q) accepted malformed data", in)
		}
	}
}

func TestLimits(t *testing.T) {
	if _, err := UnmarshalLimited([]byte(`s:10:"0123456789";`), Limits{MaxString: 9}); !errors.Is(err, ErrLimit) {
		t.Fatalf("string limit error = %v", err)
	}
	if _, err := UnmarshalLimited([]byte(`a:2:{i:0;i:1;i:1;i:2;}`), Limits{MaxElements: 1}); !errors.Is(err, ErrLimit) {
		t.Fatalf("element limit error = %v", err)
	}
	deep := strings.Repeat(`a:1:{i:0;`, 80) + `N;` + strings.Repeat("}", 80)
	if _, err := Unmarshal([]byte(deep)); !errors.Is(err, ErrLimit) {
		t.Fatalf("depth limit error = %v", err)
	}
}

func FuzzUnmarshal(f *testing.F) {
	for _, seed := range []string{
		"N;", "b:1;", "i:1;", `s:0:"";`, "a:0:{}",
		`a:1:{s:1:"k";a:1:{i:0;b:0;}}`, "O:1:\"x\":0:{}",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := Unmarshal(data)
		if err != nil {
			return
		}
		encoded, err := Marshal(v)
		if err != nil {
			t.Fatalf("Marshal after successful Unmarshal: %v", err)
		}
		if _, err := Unmarshal(encoded); err != nil {
			t.Fatalf("re-Unmarshal of %q (from %q): %v", encoded, data, err)
		}
	})
}
