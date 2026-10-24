package revocation

import (
	"bytes"
	"testing"
)

func TestFingerprintStableAndPurposeBound(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	a := Fingerprint(secret, "$2y$10$hash-one")
	b := Fingerprint(secret, "$2y$10$hash-one")
	if !bytes.Equal(a, b) {
		t.Fatal("fingerprint is not deterministic")
	}
	if bytes.Equal(a, Fingerprint(secret, "$2y$10$hash-two")) {
		t.Fatal("different hashes produced the same fingerprint")
	}
	if bytes.Equal(a, Fingerprint([]byte("ffffffffffffffffffffffffffffffff"), "$2y$10$hash-one")) {
		t.Fatal("fingerprint does not depend on the secret")
	}
	if len(a) != 32 {
		t.Fatalf("fingerprint length = %d", len(a))
	}
}

func TestSchemaIsAdditive(t *testing.T) {
	if !bytes.Contains([]byte(Schema), []byte("CREATE TABLE IF NOT EXISTS")) {
		t.Fatal("schema is not idempotent")
	}
	if bytes.Contains([]byte(Schema), []byte("ALTER TABLE")) {
		t.Fatal("schema must not alter existing tables")
	}
}
