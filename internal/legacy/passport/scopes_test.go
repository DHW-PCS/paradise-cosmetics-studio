package passport

import "testing"

func TestScopesKeepLegacySpelling(t *testing.T) {
	if _, ok := ValidateScopes([]string{"Closet.ReadWrtie"}); !ok {
		t.Fatal("legacy Closet.ReadWrtie was rejected")
	}
	if _, ok := ValidateScopes([]string{"Closet.ReadWrite"}); ok {
		t.Fatal("unregistered Closet.ReadWrite was accepted")
	}
	if unknown, ok := ValidateScopes([]string{"User.Read", "Unknown.Scope"}); ok || unknown != "Unknown.Scope" {
		t.Fatalf("unknown = %q, ok = %v", unknown, ok)
	}
}

func TestParseScopes(t *testing.T) {
	got := ParseScopes(" User.Read  Player.Read  User.Read ")
	if len(got) != 3 || got[0] != "User.Read" || got[1] != "Player.Read" || got[2] != "User.Read" {
		t.Fatalf("ParseScopes = %#v", got)
	}
	if ParseScopes("  ") != nil {
		t.Fatal("empty scopes were not empty")
	}
	deduped := IntersectScopes([]string{"User.Read", "User.Read", "", "Player.Read"})
	if len(deduped) != 2 || deduped[0] != "User.Read" || deduped[1] != "Player.Read" {
		t.Fatalf("IntersectScopes = %#v", deduped)
	}
}
