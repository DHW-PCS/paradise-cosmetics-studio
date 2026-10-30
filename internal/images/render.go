package images

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"time"

	"blessing-skin-go/internal/renderer"
)

type textureFile struct {
	TID      int64
	Hash     string
	Kind     string
	Uploader int64
}

func (s *Service) textureByTID(ctx context.Context, tid int64) (*textureFile, error) {
	var out textureFile
	err := s.Store.DB.QueryRowContext(ctx, "SELECT tid,hash,type,uploader FROM "+s.Store.Table("textures")+" WHERE tid=?", tid).Scan(&out.TID, &out.Hash, &out.Kind, &out.Uploader)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &out, err
}

func (s *Service) textureByHash(ctx context.Context, hash string) (*textureFile, error) {
	var out textureFile
	err := s.Store.DB.QueryRowContext(ctx, "SELECT tid,hash,type,uploader FROM "+s.Store.Table("textures")+" WHERE hash=? ORDER BY tid LIMIT 1", hash).Scan(&out.TID, &out.Hash, &out.Kind, &out.Uploader)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &out, err
}

func (s *Service) readOriginal(hash string) ([]byte, time.Time, error) {
	path, err := s.Textures.SafePath(hash)
	if err != nil {
		return nil, time.Time{}, ErrNotFound
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, time.Time{}, ErrNotFound
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	if !info.Mode().IsRegular() {
		return nil, time.Time{}, ErrNotFound
	}
	payload, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, time.Time{}, ErrNotFound
	}
	return payload, info.ModTime(), err
}

// Player renders the frozen CustomSkinAPI JSON with Last-Modified.
func (s *Service) Player(ctx context.Context, name string) ([]byte, time.Time, error) {
	var pid, uid int64
	var model, skinHash, capeHash sql.NullString
	var modified time.Time
	err := s.Store.DB.QueryRowContext(ctx, "SELECT p.pid,p.uid,p.last_modified,t.type,t.hash,c.hash FROM "+s.Store.Table("players")+" p LEFT JOIN "+s.Store.Table("textures")+" t ON t.tid=p.tid_skin LEFT JOIN "+s.Store.Table("textures")+" c ON c.tid=p.tid_cape WHERE p.name=?", name).
		Scan(&pid, &uid, &modified, &model, &skinHash, &capeHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, ErrNotFound
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	var permission int
	if err = s.Store.DB.QueryRowContext(ctx, "SELECT permission FROM "+s.Store.Table("users")+" WHERE uid=?", uid).Scan(&permission); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, err
	}
	if permission < 0 {
		return nil, time.Time{}, ErrForbidden
	}
	modelKey := "default"
	if model.Valid && model.String == "alex" {
		modelKey = "slim"
	}
	payload := map[string]any{
		"username": name,
		"skins":    map[string]any{modelKey: nullableString(skinHash)},
		"cape":     nullableString(capeHash),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, time.Time{}, err
	}
	return encoded, modified, nil
}

func nullableString(value sql.NullString) any {
	if !value.Valid || value.String == "" {
		return nil
	}
	return value.String
}

// Avatar resolves the frozen avatar semantics: player without profile 404,
// user/tid/hash fallback to the default avatar, cape 422.
func (s *Service) Avatar(ctx context.Context, kind, value string, size int, threeD, pngFormat bool) ([]byte, string, time.Time, error) {
	if size <= 0 {
		size = 100
	}
	mode := "2d"
	if threeD {
		mode = "3d"
	}
	format := "webp"
	contentType := "image/webp"
	if pngFormat {
		format = "png"
		contentType = "image/png"
	}
	var texture *textureFile
	var err error
	switch kind {
	case "player":
		var uid, skinTID int64
		if err := s.Store.DB.QueryRowContext(ctx, "SELECT uid,tid_skin FROM "+s.Store.Table("players")+" WHERE name=?", value).Scan(&uid, &skinTID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, "", time.Time{}, ErrNotFound
			}
			return nil, "", time.Time{}, err
		}
		if skinTID > 0 {
			texture, err = s.textureByTID(ctx, skinTID)
		}
	case "user":
		uid, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil {
			payload, contentType, err := s.defaultAvatar(ctx, mode, size, format)
			return payload, contentType, time.Time{}, err
		}
		var avatarTID int64
		if err := s.Store.DB.QueryRowContext(ctx, "SELECT avatar FROM "+s.Store.Table("users")+" WHERE uid=?", uid).Scan(&avatarTID); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, "", time.Time{}, err
		}
		if avatarTID > 0 {
			texture, err = s.textureByTID(ctx, avatarTID)
		}
	case "tid":
		tid, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr == nil {
			texture, err = s.textureByTID(ctx, tid)
		}
	case "hash":
		texture, err = s.textureByHash(ctx, value)
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, "", time.Time{}, err
	}
	if texture != nil && texture.Kind == "cape" {
		return nil, "", time.Time{}, ErrAvatarType
	}
	if texture == nil {
		payload, contentType, err := s.defaultAvatar(ctx, mode, size, format)
		return payload, contentType, time.Time{}, err
	}
	payload, modified, err := s.readOriginal(texture.Hash)
	if errors.Is(err, ErrNotFound) {
		defaults, contentType, defaultErr := s.defaultAvatar(ctx, mode, size, format)
		return defaults, contentType, time.Time{}, defaultErr
	}
	if err != nil {
		return nil, "", time.Time{}, err
	}
	key := cacheKey{Name: texture.Hash, Mode: mode, Type: texture.Kind, Size: size, Format: format, Version: rendererVersion}
	rendered, err := s.cached(ctx, key, "enable_avatar_cache", func() ([]byte, error) {
		source, decodeErr := decodePNG(payload)
		if decodeErr != nil {
			return nil, decodeErr
		}
		var derived = renderer.Avatar2D(source, 25)
		if mode == "3d" {
			derived = renderer.Avatar3D(source, 25)
		}
		derived = resize(derived, size, size)
		if format == "png" {
			return encodePNG(derived)
		}
		return encodeWebP(derived)
	})
	if err != nil {
		return nil, "", time.Time{}, err
	}
	return rendered, contentType, modified, nil
}

func (s *Service) defaultAvatar(ctx context.Context, mode string, size int, format string) ([]byte, string, error) {
	contentType, encodedFormat := "image/webp", "webp"
	if format == "png" {
		contentType, encodedFormat = "image/png", "png"
	}
	key := cacheKey{Name: "default", Mode: mode, Size: size, Format: encodedFormat, Version: rendererVersion}
	payload, err := s.cached(ctx, key, "enable_avatar_cache", func() ([]byte, error) {
		name := "avatar2d.png"
		if mode == "3d" {
			name = "avatar3d.png"
		}
		data, readErr := embeddedAssets.ReadFile("assets/" + name)
		if readErr != nil {
			return nil, readErr
		}
		source, decodeErr := decodePNG(data)
		if decodeErr != nil {
			return nil, decodeErr
		}
		derived := resize(source, size, size)
		if encodedFormat == "png" {
			return encodePNG(derived)
		}
		return encodeWebP(derived)
	})
	return payload, contentType, err
}

// Preview renders skin previews (ratio 12) or capes (height) with PNG/WebP.
func (s *Service) Preview(ctx context.Context, kind, value string, height int, pngFormat bool) ([]byte, string, time.Time, error) {
	var texture *textureFile
	var err error
	if kind == "hash" {
		texture, err = s.textureByHash(ctx, value)
	} else {
		tid, convErr := strconv.ParseInt(value, 10, 64)
		if convErr != nil {
			return nil, "", time.Time{}, ErrNotFound
		}
		texture, err = s.textureByTID(ctx, tid)
	}
	if err != nil {
		return nil, "", time.Time{}, err
	}
	payload, modified, err := s.readOriginal(texture.Hash)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	format := "webp"
	contentType := "image/webp"
	if pngFormat {
		format = "png"
		contentType = "image/png"
	}
	key := cacheKey{Name: texture.Hash, Mode: "preview", Type: texture.Kind, Height: height, Format: format, Version: rendererVersion}
	rendered, err := s.cached(ctx, key, "enable_preview_cache", func() ([]byte, error) {
		source, decodeErr := decodePNG(payload)
		if decodeErr != nil {
			return nil, decodeErr
		}
		var derived = renderer.Skin(source, 12, texture.Kind == "alex")
		if texture.Kind == "cape" {
			if height <= 0 {
				height = 200
			}
			derived = renderer.Cape(source, height)
		}
		if format == "png" {
			return encodePNG(derived)
		}
		return encodeWebP(derived)
	})
	if err != nil {
		return nil, "", time.Time{}, err
	}
	return rendered, contentType, modified, nil
}
