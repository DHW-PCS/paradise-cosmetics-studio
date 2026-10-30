// Package textures owns PNG uploads, original-file publication and the skin
// library read models shared with M3-04/05/06.
package textures

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"image/png"
	"io"
	"os"
	"strings"
	"time"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/legacy/rules"
	"blessing-skin-go/internal/site"
)

var (
	ErrNotFound    = errors.New("textures: texture not found")
	ErrLackScore   = errors.New("textures: not enough score")
	ErrInvalidType = errors.New("textures: invalid texture type")
	ErrInvalidName = errors.New("textures: invalid texture name")
	ErrNotPNG      = errors.New("textures: not a decodable PNG")
	ErrTooLarge    = errors.New("textures: upload exceeds configured size")
	ErrForbidden   = errors.New("textures: no permission")
)

// DuplicateError reports the frozen duplicate-upload outcome (code 2 + TID).
type DuplicateError struct{ TID int64 }

func (e *DuplicateError) Error() string { return "textures: duplicate upload" }

type Service struct {
	Store    *database.Store
	Identity *identity.Service
	Site     *site.Service
	Dir      string
	Now      func() time.Time
}

func New(store *database.Store, id *identity.Service, view *site.Service, dir string, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{Store: store, Identity: id, Site: view, Dir: dir, Now: now}
}

type UploadInput struct {
	Browser *identity.BrowserSession
	Name    string
	Type    string
	Public  bool
	Source  string // validated original file inside the staging directory
	Bytes   int64
}

type imageInfo struct{ Width, Height int }

type DimensionError struct{ Width, Height int }

func (e *DimensionError) Error() string { return "textures: invalid dimensions" }

// maxDecodedPixels bounds decoded memory and accepts every legal upload the
// production corpus contains.
//
// Evidence (2026-10-30): the read-only production inventory
// (evidence/2026-10-30-m3-production-dimensions) recorded 355 textures with a
// 64x32/64x64 core, 9 files at or above 256 px, and a single 4608x2304 steve
// texture = 10,616,832 px. Measured on the target platform, decoding that file
// allocates ~41 MiB and takes ~64 ms; 4096x4096 costs ~64 MiB and ~106 ms.
//
// The budget is the production maximum rounded up to the next 64x32 multiple
// with 2x headroom: 4608x4608 = 21,233,664 px. That still rejects
// decompression bombs well before a full decode while leaving room for HD
// skins larger than anything observed.
const maxDecodedPixels = 4608 * 4608

func validatePNG(path string) (imageInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return imageInfo{}, ErrNotPNG
	}
	defer file.Close()
	config, err := png.DecodeConfig(file)
	if err != nil {
		return imageInfo{}, ErrNotPNG
	}
	if config.Width <= 0 || config.Height <= 0 {
		return imageInfo{}, ErrNotPNG
	}
	if config.Width*config.Height > maxDecodedPixels {
		return imageInfo{}, ErrTooLarge
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return imageInfo{}, err
	}
	decoded, err := png.Decode(file)
	if err != nil {
		return imageInfo{}, ErrNotPNG
	}
	bounds := decoded.Bounds()
	if bounds.Dx() != config.Width || bounds.Dy() != config.Height {
		return imageInfo{}, ErrNotPNG
	}
	return imageInfo{Width: config.Width, Height: config.Height}, nil
}

func validDimensions(kind string, info imageInfo) bool {
	if info.Width%64 != 0 || info.Height%32 != 0 {
		return false
	}
	ratio := float64(info.Width) / float64(info.Height)
	switch kind {
	case "steve":
		return ratio == 2 || ratio == 1
	case "alex":
		return ratio == 1
	case "cape":
		return ratio == 2
	}
	return false
}

// Upload commits the texture row, score, default closet item and original file
// in one transaction, preserving the uploaded bytes.
func (s *Service) Upload(ctx context.Context, in UploadInput) (int64, error) {
	options, err := s.Site.Options(ctx)
	if err != nil {
		return 0, err
	}
	if in.Type != "steve" && in.Type != "alex" && in.Type != "cape" {
		return 0, ErrInvalidType
	}
	if strings.TrimSpace(in.Name) == "" {
		return 0, ErrInvalidName
	}
	maxBytes := site.Number(options["max_upload_file_size"]) * 1024
	if in.Bytes > maxBytes {
		return 0, ErrTooLarge
	}
	pattern, _ := options["texture_name_regexp"].(string)
	if matched, err := rules.MatchTexture(pattern, in.Name); err != nil {
		return 0, err
	} else if !matched {
		return 0, ErrInvalidName
	}
	info, err := validatePNG(in.Source)
	if err != nil {
		return 0, err
	}
	if !validDimensions(in.Type, info) {
		return 0, &DimensionError{Width: info.Width, Height: info.Height}
	}
	hash, err := HashFile(in.Source)
	if err != nil {
		return 0, err
	}
	size := (in.Bytes + 1023) / 1024
	publicRate := site.Number(options["score_per_storage"])
	privateRate := site.Number(options["private_score_per_storage"])
	closetCost := site.Number(options["score_per_closet_item"])
	award := site.Number(options["score_award_per_texture"])
	rate := publicRate
	if !in.Public {
		rate = privateRate
	}
	cost := size*rate + closetCost - award
	var tid int64
	err = s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err = s.lockHash(ctx, tx, hash); err != nil {
			return err
		}
		actor, err := s.Identity.CheckBrowserTx(ctx, tx, in.Browser)
		if err != nil {
			return err
		}
		var duplicate int64
		err = tx.QueryRowContext(ctx, "SELECT tid FROM "+s.Store.Table("textures")+" WHERE hash=? AND (public=1 OR uploader=?) ORDER BY tid LIMIT 1", hash, actor.UID).Scan(&duplicate)
		if err == nil {
			return &DuplicateError{TID: duplicate}
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var score int64
		if err = tx.QueryRowContext(ctx, "SELECT score FROM "+s.Store.Table("users")+" WHERE uid=? FOR UPDATE", actor.UID).Scan(&score); err != nil {
			return err
		}
		if score < cost {
			return ErrLackScore
		}
		now := s.Now().In(s.Site.Location)
		result, err := tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("textures")+" (name,type,hash,size,uploader,public,likes,upload_at) VALUES (?,?,?,?,?,?,1,?)",
			in.Name, in.Type, hash, size, actor.UID, in.Public, now)
		if err != nil {
			return err
		}
		if tid, err = result.LastInsertId(); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("user_closet")+" (user_uid,texture_tid,item_name) VALUES (?,?,?)", actor.UID, tid, in.Name); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=score-? WHERE uid=?", cost, actor.UID); err != nil {
			return err
		}
		if err = s.publishLocked(hash, in.Source); err != nil {
			return fmt.Errorf("%w: %w", ErrFile, err)
		}
		return s.bumpGeneration(ctx, tx, hash)
	})
	return tid, err
}

// Texture is the frozen texture row shape returned by info endpoints.
type Texture struct {
	TID      int64  `json:"tid"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Hash     string `json:"hash"`
	Size     int64  `json:"size"`
	Uploader int64  `json:"uploader"`
	Public   bool   `json:"public"`
	UploadAt string `json:"upload_at"`
	Likes    int64  `json:"likes"`
}

func scanTexture(location *time.Location, scan func(...any) error) (*Texture, error) {
	var row Texture
	var uploadAt time.Time
	if err := scan(&row.TID, &row.Name, &row.Type, &row.Hash, &row.Size, &row.Uploader, &row.Public, &uploadAt, &row.Likes); err != nil {
		return nil, err
	}
	row.UploadAt = uploadAt.In(location).Format("2006-01-02 15:04:05")
	return &row, nil
}

// Get reads the current texture row (business row is never deleted on read).
func (s *Service) Get(ctx context.Context, tid int64) (*Texture, error) {
	row, err := scanTexture(s.Site.Location, func(dest ...any) error {
		return s.Store.DB.QueryRowContext(ctx, "SELECT tid,name,type,hash,size,uploader,public,upload_at,likes FROM "+s.Store.Table("textures")+" WHERE tid=?", tid).Scan(dest...)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return row, nil
}

// CanView applies the frozen private-texture rule: public, owner or admin.
func (s *Service) CanView(row *Texture, viewer *identity.User) bool {
	if row.Public {
		return true
	}
	if viewer == nil {
		return false
	}
	return viewer.UID == row.Uploader || viewer.Permission >= 1
}

// FileAvailable reports whether a regular original file exists.
func (s *Service) FileAvailable(hash string) (bool, error) {
	target, err := s.SafePath(hash)
	if err != nil {
		return false, err
	}
	info, err := os.Stat(target)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return info.Mode().IsRegular(), nil
}

// Owner reads the uploader display fields without fabricating an owner.
func (s *Service) Owner(ctx context.Context, uid int64) (nickname string, admin bool, exists bool, err error) {
	var permission int
	err = s.Store.DB.QueryRowContext(ctx, "SELECT nickname,permission FROM "+s.Store.Table("users")+" WHERE uid=?", uid).Scan(&nickname, &permission)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, false, nil
	}
	if err != nil {
		return "", false, false, err
	}
	return nickname, permission >= 1, true, nil
}

// StageUpload copies a bounded multipart payload into the same-filesystem
// staging directory and returns its path and byte length. Validation happens
// before any database work.
func (s *Service) StageUpload(source io.Reader, maxBytes int64) (string, int64, error) {
	file, err := s.newTempFile()
	if err != nil {
		return "", 0, err
	}
	path := file.Name()
	written, err := io.Copy(file, io.LimitReader(source, maxBytes+1))
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
		return "", 0, err
	}
	if written > maxBytes {
		os.Remove(path)
		return "", 0, ErrTooLarge
	}
	return path, written, nil
}
