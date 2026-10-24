package laravel

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Synthetic key and payloads produced by the frozen PHP 8.1 Encrypter. They
// are test-only values and cannot match any real installation.
const (
	goldenAppKey = "base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	goldenString = "eyJpdiI6IlVnTVVnSG93dkVCL0EzckxTUE9FUUE9PSIsInZhbHVlIjoiQ2o0eHU2YkRHSnhMVnhyeGJSTTBJZz09IiwibWFjIjoiMTNlODM0OWE0OTc3MWI1NzVhMWFmMmFkOTM0Y2U3MWI1OGM3MmVkYjdkOTkxM2UyNWZhNTBjZGUzZjEwNTQwZiIsInRhZyI6IiJ9"
	goldenCookie = "eyJpdiI6IkFlYUJXRGZ5aHpWeUdCbGFCNHN2MFE9PSIsInZhbHVlIjoiSUdjYmk1QTM0RHgwV0JLRXhhZGZFVnAweE5RSDRNWGZZZjV4WEI3Q2NCNDlFWVVwT25aWEI3amdxUWpXWm5IY2xVbXRkQWZZOUZqSmVORmFyZEdSRlFOL3NWQzZydU9ZZjhPNjg3OWtTZHRDT2wwN2RQQjFDUXZ1UVh2VnpMMWMiLCJtYWMiOiJlOWI0ZDE0Yzg5YTIwMWUwYzk2ODVmYWY3YTg2NzNjY2VjOWE1YzRhOTg0ZjRiMWJlYjFlZWRlYjUyZTYzODIxIiwidGFnIjoiIn0="
	goldenSID    = "0123456789abcdefghijklmnopqrstuvwxyzABCD"
)

func newGoldenEncrypter(t *testing.T) *Encrypter {
	t.Helper()
	enc, err := NewEncrypter(ParseAppKey(goldenAppKey), "AES-256-CBC")
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	return enc
}

func TestDecryptPHPGeneratedString(t *testing.T) {
	enc := newGoldenEncrypter(t)
	got, err := enc.DecryptString(goldenString)
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}
	if got != "plain value" {
		t.Fatalf("plain = %q", got)
	}
}

func TestDecryptPHPGeneratedCookie(t *testing.T) {
	enc := newGoldenEncrypter(t)
	got, err := enc.DecryptCookie("BS_SESSION", goldenCookie)
	if err != nil {
		t.Fatalf("DecryptCookie: %v", err)
	}
	if got != goldenSID {
		t.Fatalf("sid = %q, want %q", got, goldenSID)
	}
	if _, err := enc.DecryptCookie("OTHER_COOKIE", goldenCookie); !errors.Is(err, ErrCookiePrefix) {
		t.Fatalf("other cookie error = %v, want ErrCookiePrefix", err)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	enc := newGoldenEncrypter(t)
	payload, err := enc.EncryptString("round trip")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	got, err := enc.DecryptString(payload)
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}
	if got != "round trip" {
		t.Fatalf("round trip = %q", got)
	}
	if !strings.HasPrefix(payload, "eyJ") {
		t.Fatalf("payload should be base64 JSON, got %q", payload)
	}
}

func TestMACAndPayloadRejection(t *testing.T) {
	enc := newGoldenEncrypter(t)

	raw, err := base64.StdEncoding.DecodeString(goldenString)
	if err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("json: %v", err)
	}
	if p.MAC == "" {
		t.Fatal("golden payload has no mac")
	}
	p.MAC = strings.Repeat("0", len(p.MAC))
	body, _ := json.Marshal(p)
	tampered := base64.StdEncoding.EncodeToString(body)
	if _, err := enc.DecryptString(tampered); !errors.Is(err, ErrInvalidMAC) {
		t.Fatalf("tampered mac error = %v, want ErrInvalidMAC", err)
	}

	if _, err := enc.DecryptString("not-base64!"); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("non-base64 error = %v", err)
	}

	other, err := NewEncrypter([]byte("ffffffffffffffffffffffffffffffff"), "AES-256-CBC")
	if err != nil {
		t.Fatalf("second encrypter: %v", err)
	}
	if _, err := other.DecryptString(goldenString); !errors.Is(err, ErrInvalidMAC) {
		t.Fatalf("wrong key error = %v, want ErrInvalidMAC", err)
	}
}

func TestInvalidCipherOrKey(t *testing.T) {
	if _, err := NewEncrypter([]byte("short"), "AES-256-CBC"); !errors.Is(err, ErrInvalidCipher) {
		t.Fatalf("short key error = %v", err)
	}
	if _, err := NewEncrypter(make([]byte, 32), "AES-512-CBC"); !errors.Is(err, ErrInvalidCipher) {
		t.Fatalf("unknown cipher error = %v", err)
	}
}

func TestCookieValuePrefix(t *testing.T) {
	key := ParseAppKey(goldenAppKey)
	prefix := CookieValuePrefix("BS_SESSION", key)
	if len(prefix) != 41 || !strings.HasSuffix(prefix, "|") {
		t.Fatalf("prefix = %q", prefix)
	}
	if got := RemoveCookieValuePrefix(prefix + "abc"); got != "abc" {
		t.Fatalf("remove = %q", got)
	}
	if got := RemoveCookieValuePrefix("short"); got != "" {
		t.Fatalf("short remove = %q", got)
	}
}

func TestGuardKeyNames(t *testing.T) {
	if got := LoginKey("web", DefaultGuardClass); got != "login_web_59ba36addc2b2f9401580f014c7f58ea4e30989d" {
		t.Fatalf("login key = %q", got)
	}
	if got := RecallerCookieName("web", DefaultGuardClass); got != "remember_web_59ba36addc2b2f9401580f014c7f58ea4e30989d" {
		t.Fatalf("recaller = %q", got)
	}
}
