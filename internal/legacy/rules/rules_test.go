package rules

import (
	"strings"
	"testing"
)

func TestPlayerNameRules(t *testing.T) {
	for _, c := range []struct {
		rule, custom, value string
		want                bool
	}{
		{"official", "/[/", "Alice_1", true},
		{"official", "", "名字", false},
		{"official", "", "Alice\n", true},
		{"cjk", "", "名字§_1", true},
		{"cjk", "", "Alice!", false},
		{"utf8", "/[/", "名字\u00a0", true},
		{"utf8", "", "Alice Bob", false},
		{"utf8", "", string([]byte{255}), false},
		{"custom", "", "Any!", true},
		{"custom", "0", "Any!", true},
		{"custom", `/^(?=.{3,16}$)[\p{Han}A-Za-z]+$/u`, "名字Alice", true},
		{"custom", `/^(?=.{3,16}$)[\p{Han}A-Za-z]+$/u`, "Alice1", false},
		{"custom", `/^.$/u`, string([]byte{255}), false},
		{"custom", `/(*NO_START_OPT)(a+)+$/`, strings.Repeat("a", 200) + "!", false},
	} {
		got, err := MatchPlayer(c.rule, c.custom, c.value)
		if err != nil || got != c.want {
			t.Errorf("%q/%q: got %t, %v; want %t", c.rule, c.value, got, err, c.want)
		}
	}
}

func TestConfiguredTextureRule(t *testing.T) {
	for _, pattern := range []string{"", "0", `/^(Skin)\1$/`} {
		got, err := MatchTexture(pattern, "SkinSkin")
		if err != nil || !got {
			t.Fatalf("texture pattern %q: %t, %v", pattern, got, err)
		}
	}
	if got, err := MatchTexture(`/^(Skin)\1$/`, "SkinCape"); err != nil || got {
		t.Fatalf("non-match: %t, %v", got, err)
	}
	if _, err := MatchTexture(`/[/`, "Skin"); err == nil {
		t.Fatal("invalid configured PCRE did not report an error")
	}
}
