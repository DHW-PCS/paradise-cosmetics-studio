// Package password verifies legacy Blessing Skin password hashes.
//
// The method set and the exact concatenation rules come from the frozen
// 6.0.2 sources (app/Services/Cipher/*, config/secure.php). SALTED2* hashes
// the hexadecimal inner digest, not the raw bytes.
package password

import (
	"crypto/md5"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Method is the value of PWD_METHOD in the legacy configuration.
type Method string

const (
	BCRYPT        Method = "BCRYPT"
	ARGON2I       Method = "ARGON2I"
	PHP_PASSWORD  Method = "PHP_PASSWORD_HASH"
	MD5           Method = "MD5"
	SHA256        Method = "SHA256"
	SHA512        Method = "SHA512"
	SALTED2MD5    Method = "SALTED2MD5"
	SALTED2SHA256 Method = "SALTED2SHA256"
	SALTED2SHA512 Method = "SALTED2SHA512"
)

// ErrUnsupportedMethod means the configured method has no verifier here. It is
// reported as a gap instead of silently falling back to bcrypt.
var ErrUnsupportedMethod = errors.New("password: unsupported PWD_METHOD")

// ErrEmptyPassword means the login attempt used an empty password, which the
// legacy UI never allows to authenticate.
var ErrEmptyPassword = errors.New("password: empty password")

// Hasher verifies (and, for fixtures, produces) legacy hashes.
type Hasher struct {
	method Method
	salt   string
}

// New builds a Hasher. Unknown methods return ErrUnsupportedMethod.
func New(method, salt string) (*Hasher, error) {
	m := Method(strings.ToUpper(strings.TrimSpace(method)))
	switch m {
	case BCRYPT, ARGON2I, PHP_PASSWORD, MD5, SHA256, SHA512,
		SALTED2MD5, SALTED2SHA256, SALTED2SHA512:
		return &Hasher{method: m, salt: salt}, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedMethod, method)
	}
}

// Method returns the normalized method name.
func (h *Hasher) Method() Method { return h.method }

// Verify checks a password against a stored hash. Empty passwords never match.
func (h *Hasher) Verify(raw, hash string) (bool, error) {
	if raw == "" || hash == "" {
		return false, nil
	}
	switch h.method {
	case BCRYPT:
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(raw))
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return err == nil, err
	case ARGON2I:
		return verifyArgon2(raw, hash, argon2i)
	case PHP_PASSWORD:
		return verifyPHP(raw, hash)
	case MD5, SHA256, SHA512, SALTED2MD5, SALTED2SHA256, SALTED2SHA512:
		computed, err := h.compute(raw)
		if err != nil {
			return false, err
		}
		return subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) == 1, nil
	default:
		return false, fmt.Errorf("%w: %q", ErrUnsupportedMethod, h.method)
	}
}

// Hash produces the configured legacy format for new passwords. Existing
// account hashes are preserved until an authorized password change.
func (h *Hasher) Hash(raw string) (string, error) {
	switch h.method {
	case BCRYPT, PHP_PASSWORD:
		out, err := bcrypt.GenerateFromPassword(bcryptInput(raw), bcrypt.DefaultCost)
		return string(out), err
	case ARGON2I:
		return hashArgon2(raw, argon2i)
	case MD5, SHA256, SHA512, SALTED2MD5, SALTED2SHA256, SALTED2SHA512:
		return h.compute(raw)
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedMethod, h.method)
	}
}

func (h *Hasher) compute(raw string) (string, error) {
	switch h.method {
	case MD5:
		sum := md5.Sum([]byte(raw))
		return hex.EncodeToString(sum[:]), nil
	case SHA256:
		sum := sha256.Sum256([]byte(raw))
		return hex.EncodeToString(sum[:]), nil
	case SHA512:
		sum := sha512.Sum512([]byte(raw))
		return hex.EncodeToString(sum[:]), nil
	case SALTED2MD5:
		inner := md5.Sum([]byte(raw))
		outer := md5.Sum([]byte(hex.EncodeToString(inner[:]) + h.salt))
		return hex.EncodeToString(outer[:]), nil
	case SALTED2SHA256:
		inner := sha256.Sum256([]byte(raw))
		outer := sha256.Sum256([]byte(hex.EncodeToString(inner[:]) + h.salt))
		return hex.EncodeToString(outer[:]), nil
	case SALTED2SHA512:
		inner := sha512.Sum512([]byte(raw))
		outer := sha512.Sum512([]byte(hex.EncodeToString(inner[:]) + h.salt))
		return hex.EncodeToString(outer[:]), nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedMethod, h.method)
	}
}

type argonVariant int

const (
	argon2i argonVariant = iota
	argon2id
)

// argonParams is the PHC string layout produced by PHP's password_hash.
type argonParams struct {
	variant argonVariant
	version int
	memory  uint32
	time    uint32
	threads uint8
	salt    []byte
	hash    []byte
}

func parseArgon2(hash string) (*argonParams, error) {
	var variant argonVariant
	switch {
	case strings.HasPrefix(hash, "$argon2i$"):
		variant = argon2i
	case strings.HasPrefix(hash, "$argon2id$"):
		variant = argon2id
	default:
		return nil, errors.New("password: not an argon2 hash")
	}
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] == "" {
		return nil, errors.New("password: malformed argon2 hash")
	}
	p := &argonParams{variant: variant, version: 19}
	for _, field := range strings.Split(parts[3], ",") {
		kv := strings.SplitN(field, "=", 2)
		if len(kv) != 2 {
			return nil, errors.New("password: malformed argon2 parameters")
		}
		switch kv[0] {
		case "v":
			if _, err := fmt.Sscanf(kv[1], "%d", &p.version); err != nil {
				return nil, err
			}
		case "m":
			if _, err := fmt.Sscanf(kv[1], "%d", &p.memory); err != nil {
				return nil, err
			}
		case "t":
			if _, err := fmt.Sscanf(kv[1], "%d", &p.time); err != nil {
				return nil, err
			}
		case "p":
			var threads int
			if _, err := fmt.Sscanf(kv[1], "%d", &threads); err != nil {
				return nil, err
			}
			if threads < 1 || threads > 255 {
				return nil, errors.New("password: invalid argon2 parallelism")
			}
			p.threads = uint8(threads)
		}
	}
	var err error
	p.salt, err = decodeB64(parts[4])
	if err != nil {
		return nil, err
	}
	p.hash, err = decodeB64(parts[5])
	if err != nil {
		return nil, err
	}
	if p.memory == 0 || p.time == 0 || len(p.salt) == 0 || len(p.hash) == 0 {
		return nil, errors.New("password: incomplete argon2 hash")
	}
	return p, nil
}

// decodeB64 decodes the unpadded standard base64 used by PHC strings.
func decodeB64(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	case 1:
		return nil, errors.New("password: invalid base64 length")
	}
	return base64.StdEncoding.DecodeString(s)
}

func verifyArgon2(raw, hash string, want argonVariant) (bool, error) {
	p, err := parseArgon2(hash)
	if err != nil {
		return false, err
	}
	if p.variant != want {
		return false, fmt.Errorf("password: argon2 variant mismatch")
	}
	return compareArgon(raw, p), nil
}

func verifyPHP(raw, hash string) (bool, error) {
	switch {
	case strings.HasPrefix(hash, "$2y$"), strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"):
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(raw))
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return err == nil, err
	case strings.HasPrefix(hash, "$argon2i$"), strings.HasPrefix(hash, "$argon2id$"):
		p, err := parseArgon2(hash)
		if err != nil {
			return false, err
		}
		return compareArgon(raw, p), nil
	default:
		return false, fmt.Errorf("%w: unrecognized PHP hash prefix", ErrUnsupportedMethod)
	}
}

func compareArgon(raw string, p *argonParams) bool {
	var computed []byte
	if p.variant == argon2id {
		computed = argon2.IDKey([]byte(raw), p.salt, p.time, p.memory, p.threads, uint32(len(p.hash)))
	} else {
		computed = argon2.Key([]byte(raw), p.salt, p.time, p.memory, p.threads, uint32(len(p.hash)))
	}
	return subtle.ConstantTimeCompare(computed, p.hash) == 1
}

func hashArgon2(raw string, variant argonVariant) (string, error) {
	salt := make([]byte, 16)
	if _, err := crand.Read(salt); err != nil {
		return "", err
	}
	const memory, time, threads = 64 * 1024, 4, 1
	var out []byte
	name := "argon2i"
	if variant == argon2id {
		name = "argon2id"
		out = argon2.IDKey([]byte(raw), salt, time, memory, threads, 32)
	} else {
		out = argon2.Key([]byte(raw), salt, time, memory, threads, 32)
	}
	enc := func(b []byte) string {
		return strings.TrimRight(base64.StdEncoding.EncodeToString(b), "=")
	}
	return fmt.Sprintf("$%s$v=19$m=%d,t=%d,p=%d$%s$%s", name, memory, time, threads, enc(salt), enc(out)), nil
}

// PHP's bcrypt hashes the first 72 bytes, including when the accepted
// character count produces a longer UTF-8 byte sequence.
func bcryptInput(raw string) []byte {
	if len(raw) > 72 {
		raw = raw[:72]
	}
	return []byte(raw)
}
