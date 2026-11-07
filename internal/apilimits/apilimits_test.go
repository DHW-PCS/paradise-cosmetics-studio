// Pure key and window-decision checks; they run without a database.
package apilimits

import (
	"crypto/sha1"
	"testing"
)

func sha1Bytes(raw string) []byte {
	sum := sha1.Sum([]byte(raw))
	return sum[:]
}

func TestKeyForUIDAndAnonymous(t *testing.T) {
	if got := keyFor(42, "ignored.example", "203.0.113.1"); string(got) != string(sha1Bytes("42")) {
		t.Fatal("positive uid must key on its decimal form")
	}
	anon := keyFor(0, "api.example", "203.0.113.9")
	if string(anon) != string(sha1Bytes("api.example|203.0.113.9")) {
		t.Fatal("anonymous key must be domain|ip")
	}
	if string(keyFor(-3, "api.example", "203.0.113.9")) != string(anon) {
		t.Fatal("non-positive uid must use the anonymous key")
	}
	if string(keyFor(0, "api.example", "203.0.113.10")) == string(anon) {
		t.Fatal("different anonymous ip must isolate")
	}
	if string(keyFor(0, "other.example", "203.0.113.9")) == string(anon) {
		t.Fatal("different domain must isolate")
	}
}

func TestDecideWindow(t *testing.T) {
	if allowed, count, expires := decide(0, 0, 1000); !allowed || count != 1 || expires != 1060 {
		t.Fatalf("first hit = %v %d %d", allowed, count, expires)
	}
	if allowed, count, expires := decide(59, 1060, 1030); !allowed || count != 60 || expires != 1060 {
		t.Fatalf("60th hit = %v %d %d", allowed, count, expires)
	}
	if allowed, count, expires := decide(60, 1060, 1030); allowed || count != 60 || expires != 1060 {
		t.Fatalf("61st hit = %v %d %d", allowed, count, expires)
	}
	if allowed, count, expires := decide(60, 1060, 1060); !allowed || count != 1 || expires != 1120 {
		t.Fatalf("reset hit = %v %d %d", allowed, count, expires)
	}
}
