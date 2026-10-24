package passport

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestJWTRoundTrip(t *testing.T) {
	key := testKey(t)
	now := time.Now()
	claims := Claims{
		Aud:    []string{"9001"},
		JTI:    "token-id",
		IAT:    now.Unix(),
		NBF:    now.Unix(),
		EXP:    now.Add(time.Hour).Unix(),
		Sub:    "1",
		Scopes: []string{"User.Read", "Player.Read"},
	}
	token, err := SignRS256(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAndVerifyRS256(&key.PublicKey, token, now)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.JTI != claims.JTI || parsed.Sub != claims.Sub || len(parsed.Scopes) != 2 {
		t.Fatalf("parsed = %#v", parsed)
	}
}

func TestJWTTamperingAndAlgorithm(t *testing.T) {
	key := testKey(t)
	now := time.Now()
	token, err := SignRS256(key, Claims{
		Aud: []string{"9001"}, JTI: "id", IAT: now.Unix(), NBF: now.Unix(),
		EXP: now.Add(time.Hour).Unix(), Sub: "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")

	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	payload = []byte(strings.Replace(string(payload), `"sub":"1"`, `"sub":"2"`, 1))
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + parts[2]
	if _, err := ParseAndVerifyRS256(&key.PublicKey, tampered, now); err == nil {
		t.Fatal("tampered payload accepted")
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"none"}`))
	unsigned := header + "." + parts[1] + "."
	if _, err := ParseAndVerifyRS256(&key.PublicKey, unsigned, now); err == nil {
		t.Fatal("alg=none accepted")
	}

	other := testKey(t)
	if _, err := ParseAndVerifyRS256(&other.PublicKey, token, now); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestClaimsAcceptPHPShapes(t *testing.T) {
	// Captured shape: scalar aud and microtime floats.
	payload := `{"aud":"9002","jti":"id","iat":1792772355.144721,` +
		`"nbf":1792772355.144721,"exp":1824308355.139574,"sub":"1",` +
		`"scopes":["User.Read"]}`
	var claims Claims
	if err := json.Unmarshal([]byte(payload), &claims); err != nil {
		t.Fatal(err)
	}
	if len(claims.Aud) != 1 || claims.Aud[0] != "9002" {
		t.Fatalf("aud = %#v", claims.Aud)
	}
	if claims.IAT != 1792772355 || claims.EXP != 1824308355 {
		t.Fatalf("times = %d/%d", claims.IAT, claims.EXP)
	}
	if len(claims.Scopes) != 1 || claims.Scopes[0] != "User.Read" {
		t.Fatalf("scopes = %#v", claims.Scopes)
	}
}

func TestJWTExpiryAndNotBefore(t *testing.T) {
	key := testKey(t)
	now := time.Now()
	expired, _ := SignRS256(key, Claims{
		Aud: []string{"9001"}, JTI: "id", IAT: now.Add(-2 * time.Hour).Unix(),
		NBF: now.Add(-2 * time.Hour).Unix(), EXP: now.Add(-time.Hour).Unix(), Sub: "1",
	})
	if _, err := ParseAndVerifyRS256(&key.PublicKey, expired, now); err == nil {
		t.Fatal("expired token accepted")
	}
	future, _ := SignRS256(key, Claims{
		Aud: []string{"9001"}, JTI: "id", IAT: now.Add(time.Hour).Unix(),
		NBF: now.Add(time.Hour).Unix(), EXP: now.Add(2 * time.Hour).Unix(), Sub: "1",
	})
	if _, err := ParseAndVerifyRS256(&key.PublicKey, future, now); err == nil {
		t.Fatal("future nbf accepted")
	}
}
