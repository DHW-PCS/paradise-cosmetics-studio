package yggdrasil

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// jwtKey is the HS256 signing key: the deployment AppKey (config JWT_SECRET
// equivalent). It is separate from the RSA profile-signing key.
type jwtKey struct {
	secret []byte
}

func newJWTKey(secret []byte) jwtKey { return jwtKey{secret: append([]byte(nil), secret...)} }

// claims is the frozen Yggdrasil JWT claim set. subject is the core UID in
// decimal; the protocol user.id is a different value (UUIDv5 of the email).
type claims struct {
	Issuer       string `json:"iss"`
	Subject      string `json:"sub"`
	TokenID      string `json:"yggt"`
	SelectedP_ID string `json:"spr,omitempty"`
	IssuedAt     int64  `json:"iat"`
	ExpiresAt    int64  `json:"exp"`
}

// sign mints one access token bound to uid, selected profile (empty means
// none) and the given expiry window.
func (k jwtKey) sign(uid int64, selected string, now time.Time, accessSec int64) (string, string, error) {
	tokenID, err := newTokenID()
	if err != nil {
		return "", "", err
	}
	c := claims{
		Issuer:    "Yggdrasil-Auth",
		Subject:   strconv.FormatInt(uid, 10),
		TokenID:   tokenID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Unix() + accessSec,
	}
	if selected != "" {
		c.SelectedP_ID = selected
	}
	header := `{"alg":"HS256","typ":"JWT"}`
	payload, err := json.Marshal(c)
	if err != nil {
		return "", "", err
	}
	input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, k.secret)
	mac.Write([]byte(input))
	token := input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return token, tokenID, nil
}

// parse verifies signature, issuer and subject shape without checking the
// access expiry. Refresh uses this tier; validate and join additionally
// require the access window.
func (k jwtKey) parse(raw string) (*claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errInvalidToken
	}
	input := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errInvalidToken
	}
	mac := hmac.New(sha256.New, k.secret)
	mac.Write([]byte(input))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, errInvalidToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errInvalidToken
	}
	var c claims
	if err = json.Unmarshal(payload, &c); err != nil {
		return nil, errInvalidToken
	}
	if c.Issuer != "Yggdrasil-Auth" {
		return nil, errInvalidToken
	}
	if _, err = strconv.ParseInt(c.Subject, 10, 64); err != nil {
		return nil, errInvalidToken
	}
	if c.TokenID == "" {
		return nil, errInvalidToken
	}
	return &c, nil
}

var errInvalidToken = errors.New("yggdrasil: invalid token")

// tokenDigest is the database lookup key for one access token.
func tokenDigest(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

func newTokenID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(id.String(), "-", ""), nil
}

func newClientToken() string { return uuid.NewString() }

// userUUIDv5 is the protocol user.id: UUIDv5(DNS, stored email). The
// authlib-injector spec serializes IDs as unhyphenated UUIDs (all dashes
// removed), matching the legacy getHex() output; the session profile
// document id uses the same hex form.
func userUUIDv5(email string) string {
	ns, _ := uuid.Parse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	sum := sha1.Sum(append(ns[:], []byte(email)...))
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80
	var b [16]byte
	copy(b[:], sum[:16])
	return hex.EncodeToString(b[:])
}

func hexWithDashes(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// hexToDashed converts a stored 32-char hex UUID to dashed form.
func hexToDashed(hex32 string) (string, bool) {
	raw, err := hex.DecodeString(hex32)
	if err != nil || len(raw) != 16 {
		return "", false
	}
	return hexWithDashes(raw), true
}

// dashedToHex strips dashes for binding version comparison.
func dashedToHex(dashed string) string {
	return strings.ReplaceAll(dashed, "-", "")
}
