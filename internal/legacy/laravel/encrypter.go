// Package laravel reproduces the parts of Laravel 8's encryption and cookie
// layer that the legacy Blessing Skin state depends on.
package laravel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidPayload = errors.New("laravel: invalid encryption payload")
	ErrInvalidMAC     = errors.New("laravel: invalid encryption MAC")
	ErrInvalidCipher  = errors.New("laravel: unsupported cipher or key length")
	ErrDecrypt        = errors.New("laravel: could not decrypt data")
)

// cipherSpec mirrors Encrypter::$supportedCiphers.
type cipherSpec struct {
	keySize int
	ivSize  int
	aead    bool
}

var supportedCiphers = map[string]cipherSpec{
	"aes-128-cbc": {keySize: 16, ivSize: 16},
	"aes-256-cbc": {keySize: 32, ivSize: 16},
	"aes-128-gcm": {keySize: 16, ivSize: 12, aead: true},
	"aes-256-gcm": {keySize: 32, ivSize: 12, aead: true},
}

// ParseAppKey mirrors EncryptionServiceProvider::parseKey: a "base64:" prefix
// is decoded, anything else is used verbatim as raw key bytes.
func ParseAppKey(raw string) []byte {
	const prefix = "base64:"
	if strings.HasPrefix(raw, prefix) {
		if decoded, err := base64.StdEncoding.DecodeString(raw[len(prefix):]); err == nil {
			return decoded
		}
		// Laravel would hand the undecoded value to the Encrypter, which then
		// rejects it because of the length; keeping the raw bytes preserves
		// that failure mode instead of masking it.
	}
	return []byte(raw)
}

// Encrypter is the subset of Illuminate\Encryption\Encrypter used by sessions
// and cookies.
type Encrypter struct {
	key    []byte
	cipher string
	spec   cipherSpec
	block  cipher.Block
}

// NewEncrypter validates the key/cipher combination exactly like Laravel.
func NewEncrypter(key []byte, cipherName string) (*Encrypter, error) {
	name := strings.ToLower(cipherName)
	spec, ok := supportedCiphers[name]
	if !ok || len(key) != spec.keySize {
		return nil, fmt.Errorf("%w: cipher %q, key length %d", ErrInvalidCipher, cipherName, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCipher, err)
	}
	return &Encrypter{key: append([]byte(nil), key...), cipher: name, spec: spec, block: block}, nil
}

// Key returns a copy of the raw key bytes.
func (e *Encrypter) Key() []byte { return append([]byte(nil), e.key...) }

// Cipher returns the normalized cipher name.
func (e *Encrypter) Cipher() string { return e.cipher }

type payload struct {
	IV    string `json:"iv"`
	Value string `json:"value"`
	MAC   string `json:"mac"`
	Tag   string `json:"tag"`
}

func (e *Encrypter) mac(iv, value string) string {
	h := hmac.New(sha256.New, e.key)
	h.Write([]byte(iv))
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}

// EncryptString mirrors encrypt($value, false): the result is base64 JSON.
func (e *Encrypter) EncryptString(plain string) (string, error) {
	if e.spec.aead {
		return "", fmt.Errorf("%w: AEAD cipher %q", ErrInvalidCipher, e.cipher)
	}
	iv := make([]byte, e.spec.ivSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	padded := pkcs7Pad([]byte(plain), e.block.BlockSize())
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(e.block, iv).CryptBlocks(out, padded)

	ivB64 := base64.StdEncoding.EncodeToString(iv)
	valueB64 := base64.StdEncoding.EncodeToString(out)
	body, err := json.Marshal(payload{IV: ivB64, Value: valueB64, MAC: e.mac(ivB64, valueB64), Tag: ""})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(body), nil
}

// DecryptString mirrors decrypt($payload, false).
func (e *Encrypter) DecryptString(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", ErrInvalidPayload
	}
	var p payload
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&p); err != nil {
		return "", ErrInvalidPayload
	}
	if p.IV == "" || p.MAC == "" {
		return "", ErrInvalidPayload
	}
	iv, err := base64.StdEncoding.DecodeString(p.IV)
	if err != nil || len(iv) != e.spec.ivSize {
		return "", ErrInvalidPayload
	}
	if subtle.ConstantTimeCompare([]byte(e.mac(p.IV, p.Value)), []byte(p.MAC)) != 1 {
		return "", ErrInvalidMAC
	}
	ciphertext, err := base64.StdEncoding.DecodeString(p.Value)
	if err != nil || len(ciphertext) == 0 || len(ciphertext)%e.block.BlockSize() != 0 {
		return "", ErrDecrypt
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(e.block, iv).CryptBlocks(out, ciphertext)
	plain, err := pkcs7Unpad(out, e.block.BlockSize())
	if err != nil {
		return "", ErrDecrypt
	}
	return string(plain), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, ErrDecrypt
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize || pad > len(data) {
		return nil, ErrDecrypt
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, ErrDecrypt
		}
	}
	return data[:len(data)-pad], nil
}
