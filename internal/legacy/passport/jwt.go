package passport

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Claims matches lcobucci/jwt's AccessTokenTrait payload. The lcobucci
// encoder writes a single audience as a string and timestamps as
// floating-point microtime, so decoding accepts both forms.
type Claims struct {
	Aud    []string `json:"aud"`
	JTI    string   `json:"jti"`
	IAT    int64    `json:"iat"`
	NBF    int64    `json:"nbf"`
	EXP    int64    `json:"exp"`
	Sub    string   `json:"sub"`
	Scopes []string `json:"scopes"`
}

// UnmarshalJSON accepts lcobucci's scalar audience and float timestamps as well
// as the array/integer form used by the Go signer.
func (c *Claims) UnmarshalJSON(data []byte) error {
	var raw struct {
		Aud    json.RawMessage `json:"aud"`
		JTI    string          `json:"jti"`
		IAT    json.RawMessage `json:"iat"`
		NBF    json.RawMessage `json:"nbf"`
		EXP    json.RawMessage `json:"exp"`
		Sub    string          `json:"sub"`
		Scopes []string        `json:"scopes"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	aud, err := decodeAudience(raw.Aud)
	if err != nil {
		return err
	}
	c.Aud = aud
	c.JTI = raw.JTI
	c.Sub = raw.Sub
	c.Scopes = raw.Scopes
	for _, item := range []struct {
		target *int64
		raw    json.RawMessage
	}{
		{&c.IAT, raw.IAT}, {&c.NBF, raw.NBF}, {&c.EXP, raw.EXP},
	} {
		if len(item.raw) == 0 {
			continue
		}
		var value float64
		if err := json.Unmarshal(item.raw, &value); err != nil {
			return err
		}
		*item.target = int64(value)
	}
	return nil
}

func decodeAudience(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err != nil {
		return nil, err
	}
	return []string{single}, nil
}

var (
	ErrJWTFormat    = errors.New("passport: malformed JWT")
	ErrJWTSignature = errors.New("passport: invalid JWT signature")
	ErrJWTAlgorithm = errors.New("passport: unsupported JWT algorithm")
	ErrJWTExpired   = errors.New("passport: JWT not yet valid or expired")
)

var base64URL = base64.RawURLEncoding

type jwtHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

// SignRS256 creates the access token string lcobucci produces.
func SignRS256(key *rsa.PrivateKey, claims Claims) (string, error) {
	header, err := json.Marshal(jwtHeader{Typ: "JWT", Alg: "RS256"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64URL.EncodeToString(header) + "." + base64URL.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64URL.EncodeToString(signature), nil
}

// ParseAndVerifyRS256 verifies the signature and the exp/nbf/iat constraints.
// The caller decides whether the jti is still present and unrevoked.
func ParseAndVerifyRS256(key *rsa.PublicKey, token string, now time.Time) (*Claims, error) {
	parts := splitToken(token)
	if len(parts) != 3 {
		return nil, ErrJWTFormat
	}
	headerBytes, err := base64URL.DecodeString(parts[0])
	if err != nil {
		return nil, ErrJWTFormat
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrJWTFormat
	}
	if header.Alg != "RS256" {
		return nil, ErrJWTAlgorithm
	}
	payloadBytes, err := base64URL.DecodeString(parts[1])
	if err != nil {
		return nil, ErrJWTFormat
	}
	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrJWTFormat
	}
	signature, err := base64URL.DecodeString(parts[2])
	if err != nil {
		return nil, ErrJWTFormat
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, ErrJWTSignature
	}
	if claims.EXP == 0 || claims.NBF == 0 || claims.IAT == 0 {
		return nil, fmt.Errorf("%w: missing time claims", ErrJWTFormat)
	}
	unix := now.Unix()
	if unix >= claims.EXP || unix < claims.NBF || unix < claims.IAT {
		return nil, ErrJWTExpired
	}
	return &claims, nil
}

func splitToken(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	return append(parts, token[start:])
}
