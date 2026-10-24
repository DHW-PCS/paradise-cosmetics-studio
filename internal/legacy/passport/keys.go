package passport

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

var ErrKeyFormat = errors.New("passport: unsupported RSA key format")

// LoadPrivateKey reads the PEM private key Passport stores at
// storage/oauth-private.key (PKCS#1 or PKCS#8).
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrKeyFormat
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyFormat, err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: not an RSA key", ErrKeyFormat)
	}
	return key, nil
}

// LoadPublicKey reads the PEM public key Passport stores at
// storage/oauth-public.key (PKIX or PKCS#1).
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrKeyFormat
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("%w: not an RSA key", ErrKeyFormat)
	}
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyFormat, err)
	}
	return key, nil
}

// PublicKeyFingerprint returns a stable, non-secret identifier for evidence.
func PublicKeyFingerprint(key *rsa.PublicKey) string {
	if key == nil {
		return ""
	}
	sum := sha256.Sum256(x509.MarshalPKCS1PublicKey(key))
	return hex.EncodeToString(sum[:])
}
