// Package images renders avatars/previews and serves the original texture and
// profile endpoints with conditional caching.
package images

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"image"
	"image/png"
	"net/http"
	"strconv"
	"sync"
	"time"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/textures"
	"github.com/HugoSmits86/nativewebp"
	xdraw "golang.org/x/image/draw"
)

var (
	ErrNotFound   = errors.New("images: not found")
	ErrForbidden  = errors.New("images: forbidden")
	ErrAvatarType = errors.New("images: cape cannot be used as avatar")
)

type Service struct {
	Store    *database.Store
	Site     *site.Service
	Textures *textures.Service
	Now      func() time.Time

	mu    sync.Mutex
	cache map[cacheKey]cacheEntry
}

type cacheEntry struct {
	Payload []byte
	Expires time.Time
}

type cacheKey struct {
	Name    string
	Mode    string
	Type    string
	Size    int
	Height  int
	Format  string
	Version string
}

const (
	rendererVersion = "go-renderer-1"
	cacheEntries    = 256
)

func New(store *database.Store, view *site.Service, tex *textures.Service, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{Store: store, Site: view, Textures: tex, Now: now, cache: map[cacheKey]cacheEntry{}}
}

func (s *Service) cached(ctx context.Context, key cacheKey, option string, render func() ([]byte, error)) ([]byte, error) {
	options, err := s.Site.Options(ctx)
	if err != nil {
		return nil, err
	}
	now := s.Now()
	s.mu.Lock()
	if value, ok := s.cache[key]; ok && now.Before(value.Expires) {
		s.mu.Unlock()
		return value.Payload, nil
	}
	s.mu.Unlock()
	value, err := render()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if len(s.cache) >= cacheEntries {
		for existing := range s.cache {
			delete(s.cache, existing)
			break
		}
	}
	expires := now.Add(time.Minute)
	if site.Truth(options[option]) {
		expires = now.AddDate(1, 0, 0)
	}
	s.cache[key] = cacheEntry{Payload: value, Expires: expires}
	s.mu.Unlock()
	return value, nil
}

func decodePNG(data []byte) (image.Image, error) {
	return png.Decode(bytes.NewReader(data))
}

func encodePNG(img image.Image) ([]byte, error) {
	var buffer bytes.Buffer
	if err := png.Encode(&buffer, img); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func encodeWebP(img image.Image) ([]byte, error) {
	var buffer bytes.Buffer
	if err := nativewebp.Encode(&buffer, img, &nativewebp.Options{UseExtendedFormat: false, CompressionLevel: nativewebp.DefaultCompression}); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func resize(img image.Image, width, height int) image.Image {
	if width <= 0 || height <= 0 {
		return img
	}
	target := image.NewNRGBA(image.Rect(0, 0, width, height))
	xdraw.CatmullRom.Scale(target, target.Bounds(), img, img.Bounds(), xdraw.Over, nil)
	return target
}

func etag(payload []byte) string {
	sum := sha256.Sum256(payload)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// ServeBytes writes a cache-validated response with ETag/Last-Modified.
func (s *Service) ServeBytes(w http.ResponseWriter, r *http.Request, payload []byte, contentType string, modified time.Time) error {
	options, err := s.Site.Options(r.Context())
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("ETag", etag(payload))
	w.Header().Set("Cache-Control", "public, max-age="+strconv.FormatInt(site.Number(options["cache_expire_time"]), 10))
	http.ServeContent(w, r, "", modified, bytes.NewReader(payload))
	return nil
}

// Raw serves the original uploaded bytes without re-encoding.
func (s *Service) Raw(ctx context.Context, hash string, w http.ResponseWriter, r *http.Request) (bool, error) {
	payload, modified, err := s.readOriginal(hash)
	if err != nil {
		return false, err
	}
	if err := s.ServeBytes(w, r, payload, "image/png", modified); err != nil {
		return false, err
	}
	return true, nil
}
