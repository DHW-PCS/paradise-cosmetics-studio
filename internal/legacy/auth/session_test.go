package auth

import (
	"errors"
	"testing"

	"paradise-cosmetics-studio/internal/legacy/php"
	"paradise-cosmetics-studio/internal/legacy/revocation"
)

func TestPayloadCannotDowngradeToLegacy(t *testing.T) {
	if _, versioned, err := PayloadFromSession(php.NewArray()); err != nil || versioned {
		t.Fatalf("absent metadata must remain legacy: %v", err)
	}
	valid := func() *php.Array {
		return php.NewArray().Set("uid", int64(1)).Set("rev", int64(1)).Set("iat", int64(1))
	}
	cases := []php.Value{nil, false, "invalid", int64(1), php.NewArray(), (*php.Array)(nil)}
	for _, key := range []string{"uid", "rev", "iat"} {
		for _, value := range []php.Value{nil, "1", int64(0), int64(-1)} {
			cases = append(cases, valid().Set(key, value))
		}
	}
	for i, value := range cases {
		if _, _, err := PayloadFromSession(php.NewArray().Set("go_auth", value)); !errors.Is(err, revocation.ErrBadPayload) {
			t.Errorf("case %d: corrupt metadata accepted: %v", i, err)
		}
	}
	p, versioned, err := PayloadFromSession(php.NewArray().Set("go_auth", valid()))
	if err != nil || !versioned || p.UID != 1 || p.Rev != 1 || p.IAT != 1 {
		t.Fatalf("valid metadata rejected: %v", err)
	}
}
