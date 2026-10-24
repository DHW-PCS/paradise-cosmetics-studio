package passport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

// Defuse\Crypto v2 password mode, as used by league/oauth2-server for
// authorization codes and refresh tokens.
//
// Format: VERSION(4) || SALT(32) || IV(16) || CIPHERTEXT || HMAC(32), hex
// encoded. The password is the raw application key bytes
// (app('encrypter')->getKey()), not the "base64:" form.

const (
	defuseSaltSize     = 32
	defuseIVSize       = 16
	defuseMACSize      = 32
	defuseKeySize      = 32
	defuseIterations   = 100000
	defuseMinCipher    = 4 + 32 + 16 + 32
	encryptionInfo     = "DefusePHP|V2|KeyForEncryption"
	authenticationInfo = "DefusePHP|V2|KeyForAuthentication"
)

var (
	defuseHeader    = []byte{0xDE, 0xF5, 0x02, 0x00}
	ErrDefuseFormat = errors.New("passport: invalid defuse ciphertext")
	ErrDefuseMAC    = errors.New("passport: defuse integrity check failed")
)

// EncryptWithPassword produces the hex ciphertext Defuse v2 produces.
func EncryptWithPassword(plaintext string, password []byte) (string, error) {
	salt := make([]byte, defuseSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	iv := make([]byte, defuseIVSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	encKey, authKey := deriveDefuseKeys(password, salt)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, []byte(plaintext))

	body := make([]byte, 0, len(defuseHeader)+len(salt)+len(iv)+len(ciphertext))
	body = append(body, defuseHeader...)
	body = append(body, salt...)
	body = append(body, iv...)
	body = append(body, ciphertext...)

	mac := hmac.New(sha256.New, authKey)
	mac.Write(body)
	body = append(body, mac.Sum(nil)...)
	return hex.EncodeToString(body), nil
}

// DecryptWithPassword verifies and decrypts a Defuse v2 password ciphertext.
func DecryptWithPassword(ciphertext string, password []byte) (string, error) {
	raw, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", ErrDefuseFormat
	}
	if len(raw) < defuseMinCipher {
		return "", ErrDefuseFormat
	}
	if subtle.ConstantTimeCompare(raw[:4], defuseHeader) != 1 {
		return "", ErrDefuseFormat
	}
	salt := raw[4 : 4+defuseSaltSize]
	iv := raw[4+defuseSaltSize : 4+defuseSaltSize+defuseIVSize]
	encrypted := raw[4+defuseSaltSize+defuseIVSize : len(raw)-defuseMACSize]
	mac := raw[len(raw)-defuseMACSize:]

	encKey, authKey := deriveDefuseKeys(password, salt)
	check := hmac.New(sha256.New, authKey)
	check.Write(raw[:len(raw)-defuseMACSize])
	if subtle.ConstantTimeCompare(check.Sum(nil), mac) != 1 {
		return "", ErrDefuseMAC
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	plaintext := make([]byte, len(encrypted))
	cipher.NewCTR(block, iv).XORKeyStream(plaintext, encrypted)
	return string(plaintext), nil
}

func deriveDefuseKeys(password, salt []byte) (encKey, authKey []byte) {
	prehash := sha256.Sum256(password)
	prekey := pbkdf2.Key(prehash[:], salt, defuseIterations, defuseKeySize, sha256.New)
	encKey = hkdfSHA256(prekey, salt, []byte(encryptionInfo))
	authKey = hkdfSHA256(prekey, salt, []byte(authenticationInfo))
	return encKey, authKey
}

// hkdfSHA256 implements HKDF-Extract/Expand for a single 32-byte block,
// matching PHP's hash_hkdf($hash, $ikm, 32, $info, $salt).
func hkdfSHA256(ikm, salt, info []byte) []byte {
	extract := hmac.New(sha256.New, salt)
	extract.Write(ikm)
	prk := extract.Sum(nil)

	expand := hmac.New(sha256.New, prk)
	expand.Write(info)
	expand.Write([]byte{0x01})
	return expand.Sum(nil)
}
