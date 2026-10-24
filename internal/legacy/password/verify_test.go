package password

import (
	"errors"
	"testing"
)

// Golden hashes produced by the frozen PHP 8.1 build for the synthetic
// password "m0-fixture-pass" and salt "testsalt".
const (
	goldenPassword = "m0-fixture-pass"
	goldenSalt     = "testsalt"

	goldenBcrypt        = "$2y$10$W/M3StfNs72DTtTk6nFaAu/lFqvBCGMzCigsqcx6GSlmol4InPEPa"
	goldenArgon2i       = "$argon2i$v=19$m=65536,t=4,p=1$Mjd1c2loL0JQam1XakdRSg$vBFJw3I2eobkbguVxTX8LmgEkxXQONhiA1sufUv0A44"
	goldenSalted2SHA256 = "b2a562ec4034b6130075e9db86c6841f60aee40f7065446098f5f8c8de009be0"
	goldenSalted2MD5    = "8eee8e7b00a21e5b540fcabe64b173e3"
	goldenSalted2SHA512 = "7d0a7dc07510f70d00df87f38f29e40833ac109cde607a50598c7f8d475d1f3f0e22a975c6a98a8f8a0d2c6004ca009773e7394e968748488256582921f7a695"
	goldenMD5           = "95c8a12460a23fc35cd5415eac6898e4"
	goldenSHA256        = "78a2507b04f9f99b0b7b8acc1a2b88ad2464fce64929315983b000ac839fa700"
	goldenSHA512        = "40b9ba0e696cc3ac4479d5fa93874a4a139f2bf735eb7929826daab712e2300c3f963c15c007ec481e866cda9142438fa9f66c90f8028d4f5ae95ca185b88810"
)

func TestGoldenPHPHashes(t *testing.T) {
	cases := []struct {
		method Method
		hash   string
	}{
		{BCRYPT, goldenBcrypt},
		{ARGON2I, goldenArgon2i},
		{SALTED2SHA256, goldenSalted2SHA256},
		{SALTED2MD5, goldenSalted2MD5},
		{SALTED2SHA512, goldenSalted2SHA512},
		{MD5, goldenMD5},
		{SHA256, goldenSHA256},
		{SHA512, goldenSHA512},
		{PHP_PASSWORD, goldenBcrypt},
	}
	for _, c := range cases {
		h, err := New(string(c.method), goldenSalt)
		if err != nil {
			t.Fatalf("%s: %v", c.method, err)
		}
		ok, err := h.Verify(goldenPassword, c.hash)
		if err != nil {
			t.Fatalf("%s verify: %v", c.method, err)
		}
		if !ok {
			t.Fatalf("%s rejected the PHP-generated hash", c.method)
		}
		bad, err := h.Verify("wrong password", c.hash)
		if err != nil {
			t.Fatalf("%s wrong-password error: %v", c.method, err)
		}
		if bad {
			t.Fatalf("%s accepted a wrong password", c.method)
		}
		empty, err := h.Verify("", c.hash)
		if err != nil {
			t.Fatalf("%s empty-password error: %v", c.method, err)
		}
		if empty {
			t.Fatalf("%s accepted an empty password", c.method)
		}
	}
}

func TestPHP_PASSWORD_Argon2id(t *testing.T) {
	h, err := New(string(PHP_PASSWORD), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Hash("x"); err != nil {
		t.Fatalf("Hash: %v", err)
	}
	// Verify the argon2i golden through the PHP_PASSWORD dispatcher too.
	ok, err := h.Verify(goldenPassword, goldenArgon2i)
	if err != nil || !ok {
		t.Fatalf("dispatcher argon2i: ok=%v err=%v", ok, err)
	}
}

func TestUnknownMethodIsGap(t *testing.T) {
	if _, err := New("DES", ""); !errors.Is(err, ErrUnsupportedMethod) {
		t.Fatalf("unknown method error = %v", err)
	}
}

func TestHashMatchesPHPShape(t *testing.T) {
	h, err := New(string(SALTED2SHA256), "abc")
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.Hash("password")
	if err != nil {
		t.Fatal(err)
	}
	want, err := New(string(SALTED2SHA256), "abc")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := want.Verify("password", got); !ok {
		t.Fatal("self-produced hash does not verify")
	}
}

func TestLengthPolicyUsesCharacters(t *testing.T) {
	if err := ValidateLogin("123456"); err != nil {
		t.Fatalf("6-character legacy login rejected: %v", err)
	}
	if err := ValidateLogin("12345"); !errors.Is(err, ErrLength) {
		t.Fatalf("5-character login error = %v", err)
	}
	// 8 Chinese characters are 24 bytes but 8 characters.
	if err := ValidateRegistration("密码密码密码密码"); err != nil {
		t.Fatalf("8-character registration rejected: %v", err)
	}
	if err := ValidateRegistration("1234567"); !errors.Is(err, ErrLength) {
		t.Fatalf("7-character registration error = %v", err)
	}
	if err := ValidateAdminReset("12345678901234567"); !errors.Is(err, ErrLength) {
		t.Fatalf("17-character admin reset error = %v", err)
	}
	if err := ValidateLogin(""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("empty login error = %v", err)
	}
}
