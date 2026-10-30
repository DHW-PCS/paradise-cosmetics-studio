package textures

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrPath = errors.New("textures: unsafe file path")
	ErrFile = errors.New("textures: texture file unavailable")
)

// SafePath resolves a stored texture hash inside the texture root.
func (s *Service) SafePath(hash string) (string, error) {
	if hash == "" || strings.ContainsAny(hash, "/\\") || hash == "." || hash == ".." {
		return "", ErrPath
	}
	root, err := filepath.Abs(s.Dir)
	if err != nil {
		return "", ErrPath
	}
	target := filepath.Join(root, hash)
	clean := filepath.Clean(target)
	if clean != target || !strings.HasPrefix(clean, root+string(filepath.Separator)) {
		return "", ErrPath
	}
	return clean, nil
}

// HashFile returns the lowercase sha256 of the original bytes.
func HashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err = io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// lockHash takes the frozen comparison-semantics coordination row for a hash.
func (s *Service) lockHash(ctx context.Context, tx *sql.Tx, hash string) (int64, error) {
	// INSERT IGNORE first so concurrent first publishers conflict on the
	// duplicate-key path instead of racing gap locks; then lock the row.
	if _, err := tx.ExecContext(ctx, "INSERT IGNORE INTO "+s.Store.Table("go_file_hashes")+" (hash,generation,updated_at) VALUES (?,0,?)", hash, s.Now().Unix()); err != nil {
		return 0, err
	}
	var generation int64
	if err := tx.QueryRowContext(ctx, "SELECT generation FROM "+s.Store.Table("go_file_hashes")+" WHERE hash=? FOR UPDATE", hash).Scan(&generation); err != nil {
		return 0, err
	}
	return generation, nil
}

func (s *Service) bumpGeneration(ctx context.Context, tx *sql.Tx, hash string) error {
	_, err := tx.ExecContext(ctx, "UPDATE "+s.Store.Table("go_file_hashes")+" SET generation=generation+1,updated_at=? WHERE hash=?", s.Now().Unix(), hash)
	return err
}

// publishLocked makes the already validated original file readable at the hash
// path. The caller holds the hash coordination lock.
func (s *Service) publishLocked(hash, source string) error {
	target, err := s.SafePath(hash)
	if err != nil {
		return err
	}
	if info, statErr := os.Lstat(target); statErr == nil {
		if !info.Mode().IsRegular() || info.Size() == 0 {
			return ErrFile
		}
		actual, err := HashFile(target)
		if err != nil || actual != hash {
			return ErrFile
		}
		return nil
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	if err = os.Rename(source, target); err != nil {
		return err
	}
	info, err := os.Stat(target)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return ErrFile
	}
	actual, err := HashFile(target)
	if err != nil || actual != hash {
		return ErrFile
	}
	dir, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	err = dir.Sync()
	if closeErr := dir.Close(); err == nil {
		err = closeErr
	}
	return err
}

// EnsureTempDir prepares the same-filesystem staging directory.
func (s *Service) EnsureTempDir() (string, error) {
	root, err := filepath.Abs(s.Dir)
	if err != nil {
		return "", err
	}
	if err = os.MkdirAll(root, 0o750); err != nil {
		return "", err
	}
	temp := filepath.Join(root, ".tmp")
	if err = os.MkdirAll(temp, 0o700); err != nil {
		return "", err
	}
	return temp, nil
}

func (s *Service) newTempFile() (*os.File, error) {
	temp, err := s.EnsureTempDir()
	if err != nil {
		return nil, err
	}
	return os.CreateTemp(temp, "upload-*")
}

// Collect removes an unreferenced original inside the caller's transaction.
// Zero references and an unchanged generation are required.
func (s *Service) Collect(ctx context.Context, tx *sql.Tx, hash string, generation int64) (bool, error) {
	current, err := s.lockHash(ctx, tx, hash)
	if err != nil {
		return false, err
	}
	if current != generation {
		return false, nil
	}
	var refs int64
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("textures")+" WHERE hash=?", hash).Scan(&refs); err != nil {
		return false, err
	}
	if refs > 0 {
		return false, nil
	}
	target, err := s.SafePath(hash)
	if err != nil {
		return false, err
	}
	if info, statErr := os.Lstat(target); statErr == nil && !info.Mode().IsRegular() {
		return false, ErrFile
	}
	if err = os.Remove(target); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err = s.bumpGeneration(ctx, tx, hash); err != nil {
		return false, err
	}
	return true, nil
}

// LockHash exposes the shared hash coordination row to M3-04 mutations.
func (s *Service) LockHash(ctx context.Context, tx *sql.Tx, hash string) (int64, error) {
	return s.lockHash(ctx, tx, hash)
}

// BumpGeneration exposes the hash generation update to M3-04 mutations.
func (s *Service) BumpGeneration(ctx context.Context, tx *sql.Tx, hash string) error {
	return s.bumpGeneration(ctx, tx, hash)
}

// PublishLocked exposes the publication step to the M3-05 game intent, which
// must run under the same hash coordination row.
func (s *Service) PublishLocked(hash, source string) error { return s.publishLocked(hash, source) }

// ProbePNG reads only the PNG header for dimension/ratio validation.
func (s *Service) ProbePNG(path string) (int, int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, ErrNotPNG
	}
	defer file.Close()
	config, err := png.DecodeConfig(file)
	if err != nil {
		return 0, 0, ErrNotPNG
	}
	return config.Width, config.Height, nil
}
