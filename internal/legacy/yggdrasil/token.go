// Package yggdrasil is the M1 native Yggdrasil state prototype. SQL is authoritative;
// rollback readers must use the same ledger instead of trusting cache indexes.
package yggdrasil

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var ErrDenied = errors.New("yggdrasil: invalid, expired, revoked or unauthorized state")

// Token preserves all five native public properties. ExpiresAt is the actual
// driver expiry, not a TTL measured from the time the record is imported.
type Token struct {
	Owner       string `json:"owner"`
	ProfileID   string `json:"profileId"`
	CreatedAt   int64  `json:"createdAt"`
	ClientToken string `json:"clientToken"`
	AccessToken string `json:"accessToken"`
	ExpiresAt   int64  `json:"expiresAt"`
	UID         int64  `json:"uid"`
}

type Claims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	// The JSON claim name belongs to the legacy plugin's token format.
	TokenID string  `json:"yggt"`
	SPR     string  `json:"spr,omitempty"`
	IAT     float64 `json:"iat"`
	EXP     float64 `json:"exp"`
}

func UUID5(name string) string {
	ns, _ := hex.DecodeString("6ba7b8109dad11d180b400c04fd430c8")
	h := sha1.New()
	h.Write(ns)
	h.Write([]byte(name))
	b := h.Sum(nil)[:16]
	b[6] = (b[6] & 15) | 80
	b[8] = (b[8] & 63) | 128
	return hex.EncodeToString(b)
}
func randomID() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return hex.EncodeToString(b), nil
}
func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func encode(v any) string  { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }

func (t Token) Check(key []byte, now time.Time, validTTL, refreshTTL int64, refresh bool) error {
	n := now.Unix()
	if t.UID <= 0 || t.Owner == "" || t.AccessToken == "" || t.CreatedAt > n || t.CreatedAt <= 0 || t.ExpiresAt <= n || n-t.CreatedAt >= refreshTTL {
		return ErrDenied
	}
	if strings.Contains(t.AccessToken, ".") {
		p := strings.Split(t.AccessToken, ".")
		if len(p) != 3 || len(key) < 1 {
			return ErrDenied
		}
		header, e := base64.RawURLEncoding.DecodeString(p[0])
		if e != nil {
			return ErrDenied
		}
		var hdr struct {
			Alg string `json:"alg"`
			Typ string `json:"typ"`
		}
		if json.Unmarshal(header, &hdr) != nil || hdr.Alg != "HS256" || hdr.Typ != "JWT" {
			return ErrDenied
		}
		sig, e := base64.RawURLEncoding.DecodeString(p[2])
		if e != nil {
			return ErrDenied
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(p[0] + "." + p[1]))
		if !hmac.Equal(sig, mac.Sum(nil)) {
			return ErrDenied
		}
		body, e := base64.RawURLEncoding.DecodeString(p[1])
		if e != nil {
			return ErrDenied
		}
		var c Claims
		if json.Unmarshal(body, &c) != nil || c.Iss != "Yggdrasil-Auth" || c.Sub != UUID5(t.Owner) || c.TokenID == "" || c.SPR != t.ProfileID || int64(c.IAT) != t.CreatedAt || c.EXP <= c.IAT || c.IAT > float64(now.UnixMilli())/1000 || c.EXP-c.IAT > float64(validTTL)+1 {
			return ErrDenied
		}
		if !refresh && float64(now.UnixMilli())/1000 >= c.EXP {
			return ErrDenied
		}
	} else {
		raw := strings.ReplaceAll(t.AccessToken, "-", "")
		b, e := hex.DecodeString(raw)
		if e != nil || len(b) != 16 {
			return ErrDenied
		}
	}
	if !refresh && n-t.CreatedAt >= validTTL {
		return ErrDenied
	}
	return nil
}

func Mint(uid int64, owner, profile, client string, key []byte, now time.Time, validTTL, refreshTTL int64) (Token, error) {
	if uid <= 0 || owner == "" || len(key) == 0 || validTTL <= 0 || refreshTTL < validTTL {
		return Token{}, ErrDenied
	}
	id, e := randomID()
	if e != nil {
		return Token{}, e
	}
	c := Claims{Iss: "Yggdrasil-Auth", Sub: UUID5(owner), TokenID: id, SPR: profile, IAT: float64(now.Unix()), EXP: float64(now.Unix() + validTTL)}
	raw := encode(map[string]string{"typ": "JWT", "alg": "HS256"}) + "." + encode(c)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(raw))
	raw += "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return Token{owner, profile, now.Unix(), client, raw, now.Unix() + refreshTTL, uid}, nil
}
