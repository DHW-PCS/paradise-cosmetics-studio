package links

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestRelativeKeyRepresentationAndRawQuery(t *testing.T) {
	key := "base64:literal-configured-key"
	path := "/auth/reset/42?expires=1770003600&next=%2Fhello%3Fx%3D1&x=a%20b%2B%E4%B8%AD"
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(path))
	raw := path + "&signature=" + hex.EncodeToString(h.Sum(nil))
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
