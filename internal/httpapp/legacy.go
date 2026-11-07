package httpapp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"blessing-skin-go/internal/images"
)

// legacyAPIModule is the fixed module name for the Legacy API 1.1.3 routes.
const legacyAPIModule = "legacy-api"

func (a *App) legacySkin(w http.ResponseWriter, r *http.Request) { a.legacyPNG(w, r, "skin") }
func (a *App) legacyCape(w http.ResponseWriter, r *http.Request) { a.legacyPNG(w, r, "cape") }

// legacyPNG serves the original bytes of the player's currently equipped
// skin or cape. It is a public asset route: no browser or login wrapper,
// no session cookie, and no private/download option gates. State and file
// bytes are read live on every request; conditional responses derive only
// from the current payload's SHA-256 ETag.
func (a *App) legacyPNG(w http.ResponseWriter, r *http.Request, slot string) {
	served, err := a.servedModule(r.Context(), legacyAPIModule)
	if err != nil {
		a.serverError(w, r, nil)
		return
	}
	if !served {
		a.notFound(w, r)
		return
	}
	name, ok := strings.CutSuffix(r.PathValue("player"), ".png")
	if !ok || name == "" {
		a.notFound(w, r)
		return
	}
	hash, err := a.images.PlayerTexture(r.Context(), name, slot)
	switch {
	case errors.Is(err, images.ErrForbidden):
		a.abortFor(w, r, nil, http.StatusForbidden, "general.player-banned")
		return
	case errors.Is(err, images.ErrNotFound):
		a.notFound(w, r)
		return
	case err != nil:
		a.serverError(w, r, nil)
		return
	}
	payload, err := a.images.Original(hash)
	switch {
	case errors.Is(err, images.ErrNotFound):
		a.notFound(w, r)
		return
	case err != nil:
		a.serverError(w, r, nil)
		return
	}
	sum := sha256.Sum256(payload)
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(payload))
}
