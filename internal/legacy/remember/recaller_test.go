package remember

import (
	"errors"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/legacy/laravel"
)

const testKey = "base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
const testCookie = "remember_web_59ba36addc2b2f9401580f014c7f58ea4e30989d"

func testEncrypter(t *testing.T) *laravel.Encrypter {
	t.Helper()
	enc, err := laravel.NewEncrypter(laravel.ParseAppKey(testKey), "AES-256-CBC")
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func TestCookieRoundTrip(t *testing.T) {
	enc := testEncrypter(t)
	r := &Recaller{UID: 42, Token: "token-value", Password: "$2y$10$abcdefghijklmnopqrstuv"}
	cookie, err := CookieValue(enc, testCookie, r)
	if err != nil {
		t.Fatalf("CookieValue: %v", err)
	}
	got, err := Cookie(enc, testCookie, cookie)
	if err != nil {
		t.Fatalf("Cookie: %v", err)
	}
	if got.UID != r.UID || got.Token != r.Token || got.Password != r.Password {
		t.Fatalf("round trip = %#v", got)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for _, value := range []string{"", "1", "1|", "0|token|hash", "abc|token|hash", "1||hash", "1|token|hash|extra"} {
		if _, err := Parse(value); !errors.Is(err, ErrMalformed) {
			t.Fatalf("Parse(%q) error = %v", value, err)
		}
	}
}

func TestDurationIsMinutes(t *testing.T) {
	if got := Duration(2628000); got != 2628000*time.Minute {
		t.Fatalf("duration = %s", got)
	}
}
