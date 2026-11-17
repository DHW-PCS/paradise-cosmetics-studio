// Package session reads and writes the legacy file-backed Laravel session
// store and the payload attributes Blessing Skin relies on.
package session

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"paradise-cosmetics-studio/internal/legacy/laravel"
	"paradise-cosmetics-studio/internal/legacy/php"
)

var (
	// ErrNotFound covers both a missing session file and an expired one; the
	// native handler returns an empty string for both.
	ErrNotFound  = errors.New("session: not found or expired")
	ErrInvalidID = errors.New("session: invalid session id")
	ErrCorrupt   = errors.New("session: corrupt session payload")
)

const idCharset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const idLength = 40

// Store is a file session handler equivalent to Illuminate FileSessionHandler.
type Store struct {
	Dir      string
	Lifetime time.Duration
	Now      func() time.Time
}

// NewStore validates the directory and returns a store.
func NewStore(dir string, lifetime time.Duration) (*Store, error) {
	if dir == "" {
		return nil, errors.New("session: empty storage directory")
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("session: storage directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("session: %s is not a directory", dir)
	}
	if lifetime <= 0 {
		return nil, fmt.Errorf("session: invalid lifetime %s", lifetime)
	}
	return &Store{Dir: dir, Lifetime: lifetime, Now: time.Now}, nil
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// ValidID reports whether id has the shape Str::random(40) produces. Laravel
// itself does not validate this, but a decrypted cookie is the only source of
// the id, so rejecting anything else removes path traversal risk.
func ValidID(id string) bool {
	if len(id) != idLength {
		return false
	}
	for i := 0; i < len(id); i++ {
		if !strings.ContainsRune(idCharset, rune(id[i])) {
			return false
		}
	}
	return true
}

// NewID returns a 40-character alphanumeric id.
func NewID() (string, error) {
	buf := make([]byte, idLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = idCharset[int(buf[i])%len(idCharset)]
	}
	return string(buf), nil
}

func (s *Store) path(id string) (string, error) {
	if !ValidID(id) {
		return "", ErrInvalidID
	}
	return filepath.Join(s.Dir, id), nil
}

// Read mirrors FileSessionHandler::read: a file older than the lifetime is
// treated as absent. The payload is restricted-PHP-serialized.
func (s *Store) Read(id string) (*php.Array, error) {
	path, err := s.path(id)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, ErrNotFound
	}
	if info.ModTime().Before(s.now().Add(-s.Lifetime)) {
		return nil, ErrNotFound
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrNotFound
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_SH); err != nil {
		return nil, err
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, ErrNotFound
	}
	value, err := php.Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	attrs, ok := value.(*php.Array)
	if !ok {
		return nil, fmt.Errorf("%w: payload is %T, want array", ErrCorrupt, value)
	}
	return attrs, nil
}

// Write mirrors FileSessionHandler::write (file_put_contents with LOCK_EX).
func (s *Store) Write(id string, attrs *php.Array) error {
	path, err := s.path(id)
	if err != nil {
		return err
	}
	data, err := php.Marshal(attrs)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	// Truncate only while holding the lock, as PHP LOCK_EX does. Opening
	// with O_TRUNC would corrupt a reader or writer that already holds it.
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

// Destroy mirrors FileSessionHandler::destroy.
func (s *Store) Destroy(id string) error {
	path, err := s.path(id)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Rotate mirrors Store::migrate(true): the old id is destroyed and a new id is
// returned. The caller must write the payload under the new id before the
// response is sent; until then the old cookie resolves to nothing, exactly like
// the native implementation.
func (s *Store) Rotate(oldID string) (string, error) {
	if oldID != "" {
		if err := s.Destroy(oldID); err != nil {
			return "", err
		}
	}
	return NewID()
}

// NewPayload builds a fresh session payload in the same shape Store::save
// persists after a login.
func NewPayload(loginKey string, uid int64, token string, previousURL string) *php.Array {
	return php.NewArray().
		Set("_token", token).
		Set(loginKey, uid).
		Set("_previous", php.NewArray().Set("url", previousURL)).
		Set("_flash", php.NewArray().
			Set("old", php.NewArray()).
			Set("new", php.NewArray()))
}

// AgeFlashData mirrors Store::ageFlashData: entries listed in _flash.old are
// forgotten, _flash.new becomes the new _flash.old, and _flash.new is cleared.
func AgeFlashData(attrs *php.Array) *php.Array {
	if old, ok := attrs.GetPath("_flash.old"); ok {
		if list, ok := old.(*php.Array); ok {
			for _, entry := range list.Entries {
				if key, ok := entry.Value.(string); ok {
					attrs.Delete(key)
				}
			}
		}
	}
	if current, ok := attrs.Get("_flash"); ok {
		if flash, ok := current.(*php.Array); ok {
			newValues, _ := flash.Get("new")
			switch v := newValues.(type) {
			case *php.Array:
				flash.Set("old", v)
			default:
				flash.Set("old", php.NewArray())
			}
			flash.Set("new", php.NewArray())
		}
	}
	return attrs
}

// LoginUID reads the legacy session guard key (login_web_<sha1>).
func LoginUID(attrs *php.Array, loginKey string) (int64, bool) {
	if attrs == nil {
		return 0, false
	}
	return attrs.GetInt(loginKey)
}

// CSRF returns the session's _token value.
func CSRF(attrs *php.Array) (string, bool) {
	if attrs == nil {
		return "", false
	}
	return attrs.GetString("_token")
}

// SessionCookieValue encrypts a session id the way StartSession plus
// EncryptCookies do.
func SessionCookieValue(e *laravel.Encrypter, name, id string) (string, error) {
	if !ValidID(id) {
		return "", ErrInvalidID
	}
	return e.EncryptCookie(name, id)
}

// SessionIDFromCookie decrypts a BS_SESSION cookie and validates the id shape.
func SessionIDFromCookie(e *laravel.Encrypter, name, value string) (string, error) {
	id, err := e.DecryptCookie(name, value)
	if err != nil {
		return "", err
	}
	if !ValidID(id) {
		return "", ErrInvalidID
	}
	return id, nil
}
