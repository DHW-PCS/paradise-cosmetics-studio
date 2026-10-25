package links

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

const testKey = "base64:literal-configured-key"

// sign appends the Laravel relative-URL signature over target to a path+query
// string. target is exactly the representation the frozen signer covers.
func sign(key, target string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(target))
	sum := hex.EncodeToString(h.Sum(nil))
	if strings.Contains(target, "?") {
		return target + "&signature=" + sum
	}
	return target + "?signature=" + sum
}

func TestRelativeKeyRepresentationAndRawQuery(t *testing.T) {
	key := "base64:literal-configured-key"
	path := "/auth/reset/42?expires=1770003600&next=%2Fhello%3Fx%3D1&x=a%20b%2B%E4%B8%AD"
	raw := sign(key, path)
	now := time.Unix(1770000000, 0)
	for _, s := range []struct{ url, base string }{{raw, ""}, {"https://other.invalid" + raw, ""}, {"https://other.invalid/sub" + raw, "/sub"}} {
		if e := Verify(s.url, key, s.base, now); e != nil {
			t.Fatal(e)
		}
	}
	for _, url := range []string{raw + "&x=1", raw + "&signature=aa", raw + "#fragment"} {
		if Verify(url, key, "", now) == nil {
			t.Fatal("tampered URL accepted")
		}
	}
	if Verify(raw, "literal-configured-key", "", now) == nil {
		t.Fatal("decoded key used for URL signature")
	}
	if Verify(raw, key, "", time.Unix(1770003600, 0)) != nil {
		t.Fatal("native exact expiry is still valid")
	}
	if Verify(raw, key, "", time.Unix(1770003601, 0)) == nil {
		t.Fatal("expired URL accepted")
	}
}

// TestSharedSignedInputIsRepresentationIndependent covers R06: Verify, Observe
// and Consume must reduce every representation of one signed link to the same
// claim identity.
func TestSharedSignedInputIsRepresentationIndependent(t *testing.T) {
	targets := []string{
		"/auth/reset/42?expires=1770003600&next=%2Fhello%3Fx%3D1",
		"/auth/verify/7",
		"/auth/reset/42?expires=1770003600&x=a%20b&y=a+b&y=a%2Bb",
	}
	now := time.Unix(1770000000, 0)
	for _, target := range targets {
		raw := sign(testKey, target)
		forms := []struct{ url, base string }{
			{raw, ""},
			{"https://other.invalid" + raw, ""},
			{"https://other.invalid/sub" + raw, "/sub"},
			{"http://127.0.0.1:8080/sub" + raw, "/sub/"},
		}
		var want string
		for _, form := range forms {
			got, _, err := parseSigned(form.url, form.base)
			if err != nil {
				t.Fatalf("parseSigned(%q, %q): %v", form.url, form.base, err)
			}
			if got != target {
				t.Fatalf("signed input %q, want %q", got, target)
			}
			claim, _, err := verifySignedLink(form.url, testKey, form.base, now)
			if err != nil {
				t.Fatalf("verifySignedLink(%q, %q): %v", form.url, form.base, err)
			}
			if want == "" {
				want = claim
			} else if claim != want {
				t.Fatalf("claim key changed between representations: %q != %q", claim, want)
			}
		}
	}
}

// TestClaimKeyIsDomainSeparated keeps the new claim identity apart from the old
// raw-URL hash contract and from other representations.
func TestClaimKeyIsDomainSeparated(t *testing.T) {
	target := "/auth/reset/42?expires=1770003600&next=%2Fhello%3Fx%3D1"
	k := claimKey(target)
	if k == Fingerprint(target) {
		t.Fatal("claim key is still the raw representation hash")
	}
	if k != claimKey(target) {
		t.Fatal("claim key is not deterministic")
	}
	if k == Fingerprint("https://other.invalid"+target) {
		t.Fatal("claim key matches an absolute raw URL hash")
	}
	// Byte-different raw queries keep distinct identities: order, duplicates,
	// percent-encoding and '+' versus '%20' are not normalized away.
	for _, other := range []string{
		"/auth/reset/42?expires=1770003600&next=%2Fhello%3Fx%3D1&extra=1",
		"/auth/reset/42?next=%2Fhello%3Fx%3D1&expires=1770003600",
		"/auth/reset/42?expires=1770003600&next=%2Fhello%3Fx%3D1&next=%2Fhello%3Fx%3D1",
		"/auth/reset/42?expires=1770003600&next=%2Fhello%3fx%3d1",
	} {
		if claimKey(other) == k {
			t.Fatalf("distinct raw query %q shares the claim key", other)
		}
	}
	if claimKey("/a%2Fb") == claimKey("/a/b") {
		t.Fatal("encoded slash shares the claim key with the literal slash")
	}
}

// TestSignaturePositionAndShape keeps the native contract: the signature may
// appear anywhere in the query, but it must be unique and the MAC always covers
// the remaining raw bytes in their original order.
func TestSignaturePositionAndShape(t *testing.T) {
	now := time.Unix(1770000000, 0)
	forms := []struct{ target, raw string }{
		// signature first
		{"/auth/reset/9?expires=1770003600&x=1", "/auth/reset/9?signature=%s&expires=1770003600&x=1"},
		// signature in the middle
		{"/auth/reset/9?expires=1770003600&x=1", "/auth/reset/9?expires=1770003600&signature=%s&x=1"},
		// signature last
		{"/auth/reset/9?expires=1770003600&x=1", "/auth/reset/9?expires=1770003600&x=1&signature=%s"},
		// signature in the middle still keeps the raw order of the rest
		{"/auth/reset/9?x=1&expires=1770003600", "/auth/reset/9?x=1&signature=%s&expires=1770003600"},
	}
	for i, form := range forms {
		full := sign(testKey, form.target)
		sig := full[strings.LastIndex(full, "signature=")+len("signature="):]
		raw := strings.Replace(form.raw, "%s", sig, 1)
		if e := Verify(raw, testKey, "", now); e != nil {
			t.Fatalf("form %d rejected: %v (%s)", i, e, raw)
		}
	}
	// Absence, duplication and an empty value are denied.
	mid := sign(testKey, "/auth/reset/9?expires=1770003600&x=1")
	for _, bad := range []string{
		"/auth/reset/9?expires=1770003600&x=1",
		mid + "&signature=aa",
		"/auth/reset/9?expires=1770003600&signature=&x=1",
	} {
		if Verify(bad, testKey, "", now) == nil {
			t.Fatalf("malformed signature accepted: %s", bad)
		}
	}
}

func TestVerifyFormRejections(t *testing.T) {
	now := time.Unix(1770000000, 0)
	good := sign(testKey, "/auth/reset/42?expires=1770003600&x=a%20b")
	cases := []struct {
		name, url, key, base string
		now                  time.Time
	}{
		{"fragment", good + "#f", testKey, "", now},
		{"wrong-base-path", good, testKey, "/other", now},
		{"missing-mount-prefix", good, testKey, "/sub", now},
		{"wrong-key", good, "base64:another-configured-key", "", now},
		{"decoded-key", good, strings.TrimPrefix(testKey, "base64:"), "", now},
		{"non-numeric-expiry", sign(testKey, "/auth/reset/42?expires=soon"), testKey, "", now},
		{"expired", good, testKey, "", time.Unix(1770003601, 0)},
		{"duplicate-expiry", sign(testKey, "/auth/reset/42?expires=1770003600&expires=1770003600"), testKey, "", now},
		{"invalid-percent-query", sign(testKey, "/auth/reset/42?x=%zz"), testKey, "", now},
		{"semicolon-query", sign(testKey, "/auth/reset/42?x=a;b"), testKey, "", now},
	}
	for _, c := range cases {
		if e := Verify(c.url, c.key, c.base, c.now); e == nil {
			t.Fatalf("%s: invalid link accepted", c.name)
		}
	}
	// The mount prefix is only stripped when it is configured; otherwise it is
	// part of the signed representation and this relative signature cannot match.
	if e := Verify("https://other.invalid/sub"+sign(testKey, "/auth/reset/1?expires=1770003600"), testKey, "", now); e == nil {
		t.Fatal("unconfigured mount prefix accepted a relative signature")
	}
}

// TestRawBytesAreNotRenormalized pins the escape semantics used for identities.
func TestRawBytesAreNotRenormalized(t *testing.T) {
	for _, target := range []string{
		"/auth/reset/42?expires=1770003600&x=a%20b",
		"/auth/reset/42?expires=1770003600&x=a+b",
		"/auth/reset/42%2Fnext?expires=1770003600",
		"/auth/reset/42?expires=1770003600&a=1&a=2",
	} {
		raw := sign(testKey, target)
		got, _, err := parseSigned(raw, "")
		if err != nil {
			t.Fatal(err)
		}
		if got != target {
			t.Fatalf("raw representation changed: got %q want %q", got, target)
		}
	}
}
