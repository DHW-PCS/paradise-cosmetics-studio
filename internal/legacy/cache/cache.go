// Package cache reads and writes the legacy Laravel file cache store.
//
// Only the subset Blessing Skin needs for authentication is implemented:
// string keys with the application cache prefix, a ten-digit expiry header and
// restricted PHP serialization. This is deliberately not a general cache.
package cache

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"blessing-skin-go/internal/legacy/php"
)

const forever = 9999999999

var ErrInvalidKey = errors.New("cache: empty key")

// Store is the file store equivalent to Illuminate FileStore. Prefix mirrors
// the Repository prefix (config/cache.php), which Laravel applies before the
// store hashes the key.
type Store struct {
	Dir    string
	Prefix string
	Now    func() time.Time
	// Decode may opt into a domain-specific inert class allowlist.
	Decode func([]byte) (php.Value, error)
	// ReadOnly keeps malformed and expired source artifacts for import audits.
	ReadOnly bool
}

// NewStore returns a store rooted at dir. Directories are created lazily on
// the first write, like Laravel's file store.
func NewStore(dir, prefix string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("cache: empty storage directory")
	}
	return &Store{Dir: dir, Prefix: prefix, Now: time.Now}, nil
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Path returns the file Laravel would use for key, including the prefix.
func (s *Store) Path(key string) (string, error) {
	if key == "" {
		return "", ErrInvalidKey
	}
	sum := sha1.Sum([]byte(s.Prefix + key))
	hash := hex.EncodeToString(sum[:])
	return filepath.Join(s.Dir, hash[0:2], hash[2:4], hash), nil
}

func (s *Store) expiration(ttl time.Duration) int64 {
	if ttl == 0 {
		return forever
	}
	expire := s.now().Add(ttl).Unix()
	if expire > forever {
		return forever
	}
	return expire
}

// Get mirrors FileStore::getPayload. Expired, short or corrupt payloads are
// deleted and reported as a miss, matching the native error handling.
func (s *Store) Get(key string) (php.Value, bool, error) {
	value, _, ok, err := s.getPayload(key)
	return value, ok, err
}

func (s *Store) getPayload(key string) (php.Value, int64, bool, error) {
	v, expiry, ok, e := s.readPayload(key)
	if !ok {
		return v, 0, ok, e
	}
	return v, expiry - s.now().Unix(), ok, e
}

func (s *Store) readPayload(key string) (php.Value, int64, bool, error) {
	path, err := s.Path(key)
	if err != nil {
		return nil, 0, false, err
	}
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, false, nil
		}
		return nil, 0, false, err
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_SH); err != nil {
		return nil, 0, false, err
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, 0, false, err
	}
	if len(data) < 10 {
		return nil, 0, false, s.discard(path)
	}
	expire, err := strconv.ParseInt(string(data[:10]), 10, 64)
	if err != nil {
		return nil, 0, false, s.discard(path)
	}
	if s.now().Unix() >= expire {
		return nil, 0, false, s.discard(path)
	}
	decode := s.Decode
	if decode == nil {
		decode = php.Unmarshal
	}
	value, err := decode(data[10:])
	if err != nil {
		return nil, 0, false, s.discard(path)
	}
	return value, expire, true, nil
}

func (s *Store) discard(path string) error {
	if s.ReadOnly {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Put mirrors FileStore::put: an expiry header followed by serialize(value).
func (s *Store) Put(key string, value php.Value, ttl time.Duration) error {
	path, err := s.Path(key)
	if err != nil {
		return err
	}
	encoded, err := php.Marshal(value)
	if err != nil {
		return err
	}
	payload := append([]byte(fmt.Sprintf("%010d", s.expiration(ttl))), encoded...)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
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
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		return err
	}
	return file.Sync()
}

// Forget mirrors FileStore::forget.
func (s *Store) Forget(key string) error {
	path, err := s.Path(key)
	if err != nil {
		return err
	}
	return s.discard(path)
}

// Increment mirrors FileStore::increment: read, add and write back with the
// remaining lifetime. A missing key becomes permanent, as in the native store.
func (s *Store) Increment(key string, delta int64) (int64, error) {
	value, remaining, ok, err := s.getPayload(key)
	if err != nil {
		return 0, err
	}
	current := int64(0)
	if ok {
		if n, ok := value.(int64); ok {
			current = n
		}
	}
	next := current + delta
	ttl := time.Duration(remaining) * time.Second
	if !ok {
		ttl = 0
	}
	if err := s.Put(key, next, ttl); err != nil {
		return 0, err
	}
	return next, nil
}

// GetWithExpiry returns the absolute driver expiry without restarting its TTL.
func (s *Store) GetWithExpiry(key string) (php.Value, int64, bool, error) {
	return s.readPayload(key)
}
