package yggdrasil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// ParsePrivateKey parses a PEM RSA private key without any size check. The
// enable precondition uses exactly this tier: parseable is enough.
func ParsePrivateKey(pemText string) (*rsa.PrivateKey, *APIError) {
	trimmed := trimSpace(pemText)
	if trimmed == "" {
		return nil, ErrRSAInvalid
	}
	block, _ := pem.Decode([]byte(trimmed))
	if block == nil {
		return nil, ErrRSAInvalid
	}
	if block.Type == "RSA PRIVATE KEY" {
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrRSAInvalid
		}
		if key.Validate() != nil {
			return nil, ErrRSAInvalid
		}
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// PKCS#1 without the RSA header is also accepted by legacy
		// OpenSSL; try it before failing.
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		return nil, ErrRSAInvalid
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrRSAInvalid
	}
	if key.Validate() != nil {
		return nil, ErrRSAInvalid
	}
	return key, nil
}

// LoadForExport parses and exports at the 4096-bit tier shared by hello,
// publickeys and signed profiles (legacy getPrivateKey). Any failure is a
// 400 IllegalArgumentException, never a silent empty success.
func LoadForExport(pemText string) (*rsa.PrivateKey, *APIError) {
	key, apiErr := ParsePrivateKey(pemText)
	if apiErr != nil {
		return nil, apiErr
	}
	if key.N.BitLen() < 4096 {
		return nil, ErrRSALength
	}
	return key, nil
}

// PublicKeyPEM returns the PEM public key text for the parsed key.
func PublicKeyPEM(key *rsa.PrivateKey) string {
	der := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	// Export PKIX so metadata and verify-by-clients read the standard PEM.
	if pkix, err := x509.MarshalPKIXPublicKey(&key.PublicKey); err == nil {
		_ = der
		der = pkix
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

// PublicKeyBase64 returns the headerless Base64 public key used by the
// publickeys endpoint.
func PublicKeyBase64(key *rsa.PrivateKey) string {
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	body := string(pem.EncodeToMemory(block))
	// Strip headers and newlines exactly like the legacy getPublicKeys
	// text replacement.
	lines := splitLines(body)
	var b64 []byte
	for _, line := range lines {
		if line == "-----BEGIN PUBLIC KEY-----" || line == "-----END PUBLIC KEY-----" || line == "" {
			continue
		}
		b64 = append(b64, line...)
	}
	return string(b64)
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, cur)
			cur = ""
		} else if s[i] != '\r' {
			cur += string(s[i])
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// GeneratePrivateKeyPEM creates a fresh 4096-bit candidate private key for
// the explicit admin generate action. It is never called automatically.
func GeneratePrivateKeyPEM() (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", err
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}
