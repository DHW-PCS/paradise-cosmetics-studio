package yggdrasil

import (
	"blessing-skin-go/internal/legacy/php"
	"strings"
	"testing"
	"time"
)

func TestNativeObjectDoesNotEnableSessionObjects(t *testing.T) {
	// This is PHP serialize()'s exact public-property representation, not its
	// log helper (which omits profileId).
	raw := []byte(`O:22:"Yggdrasil\Models\Token":5:{s:5:"owner";s:3:"a@b";s:9:"profileId";s:1:"p";s:9:"createdAt";i:123;s:11:"clientToken";s:6:"opaque";s:11:"accessToken";s:1:"a";}`)
	if _, e := php.Unmarshal(raw); e == nil {
		t.Fatal("session decoder accepted object")
	}
	v, e := DecodeNative(raw)
	if e != nil {
		t.Fatal(e)
	}
	token, e := FromNative(v, 456, 1)
	if e != nil || token.ProfileID != "p" || token.ExpiresAt != 456 {
		t.Fatalf("native: %+v %v", token, e)
	}
	again, e := php.Marshal(token.Native())
	if e != nil || string(again) != string(raw) {
		t.Fatalf("native byte format: %s %v", again, e)
	}
	for _, bad := range []string{strings.Replace(string(raw), "Yggdrasil\\Models\\Token", "Untrusted\\Other\\Object", 1), `C:22:"Yggdrasil\Models\Token":0:{}`, `R:1;`} {
		if _, e := DecodeNative([]byte(bad)); e == nil {
			t.Fatal("unsafe object accepted")
		}
	}
}
func TestJWTStateAndRefreshWindows(t *testing.T) {
	now := time.Unix(1770000000, 0)
	key := []byte("m1-key-for-signed-token")
	token, e := Mint(1, "MixedCase@example.invalid", "profile", "opaque/non-UUID", key, now, 10, 30)
	if e != nil {
		t.Fatal(e)
	}
	if e = token.Check(key, now, 10, 30, false); e != nil {
		t.Fatal(e)
	}
	if e = token.Check(key, now.Add(10*time.Second), 10, 30, false); e == nil {
		t.Fatal("expired access accepted")
	}
	if e = token.Check(key, now.Add(10*time.Second), 10, 30, true); e != nil {
		t.Fatal("access expiry killed refresh", e)
	}
	if e = token.Check(key, now.Add(30*time.Second), 10, 30, true); e == nil {
		t.Fatal("expired refresh accepted")
	}
	bad := token
	bad.ProfileID = "other"
	if bad.Check(key, now, 10, 30, true) == nil {
		t.Fatal("profile mismatch accepted")
	}
	bad = token
	bad.Owner = strings.ToLower(bad.Owner)
	if bad.Check(key, now, 10, 30, true) == nil {
		t.Fatal("historical subject changed")
	}
	if token.Check([]byte("wrong-key"), now, 10, 30, true) == nil {
		t.Fatal("wrong signature accepted")
	}
	bad = token
	bad.ExpiresAt = now.Unix()
	if bad.Check(key, now, 10, 30, true) == nil {
		t.Fatal("driver deadline extended")
	}
}
