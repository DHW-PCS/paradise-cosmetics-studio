package httpapp

import (
	"errors"
	"net/http"
	"strconv"

	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/images"
	"paradise-cosmetics-studio/internal/site"
	"paradise-cosmetics-studio/internal/textures"
)

func (a *App) playerProfileJSON(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	payload, modified, err := a.images.Player(r.Context(), r.PathValue("player"))
	switch {
	case errors.Is(err, images.ErrNotFound):
		a.notFound(w, r)
		return
	case errors.Is(err, images.ErrForbidden):
		a.abortFor(w, r, b, http.StatusForbidden, "general.player-banned")
		return
	case err != nil:
		a.serverError(w, r, b)
		return
	}
	if err := a.images.ServeBytes(w, r, payload, "application/json", modified); err != nil {
		a.serverError(w, r, b)
	}
}

func (a *App) rawTexture(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	options, err := a.site.Options(r.Context())
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !site.Truth(options["allow_downloading_texture"]) {
		jsonResponse(w, http.StatusForbidden, map[string]any{"message": a.message(r, b, "errors.http.msg-403")})
		return
	}
	tid, convErr := strconv.ParseInt(r.PathValue("texture"), 10, 64)
	if convErr != nil {
		a.notFound(w, r)
		return
	}
	row, err := a.textures.Get(r.Context(), tid)
	if errors.Is(err, textures.ErrNotFound) {
		a.notFound(w, r)
		return
	}
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if _, err = a.images.Raw(r.Context(), row.Hash, w, r); err != nil {
		if errors.Is(err, images.ErrNotFound) {
			a.notFound(w, r)
		} else {
			a.serverError(w, r, b)
		}
	}
}

func (a *App) hashTexture(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if _, err := a.images.Raw(r.Context(), r.PathValue("hash"), w, r); err != nil {
		if errors.Is(err, images.ErrNotFound) {
			a.notFound(w, r)
		} else {
			a.serverError(w, r, b)
		}
	}
}

func (a *App) playerAvatar(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.serveAvatar(w, r, b, "player", r.PathValue("name"))
}

func (a *App) userAvatar(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.serveAvatar(w, r, b, "user", r.PathValue("user"))
}

func (a *App) textureAvatar(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.serveAvatar(w, r, b, "tid", r.PathValue("texture"))
}

func (a *App) hashAvatar(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.serveAvatar(w, r, b, "hash", r.PathValue("hash"))
}

// Derived-image limits. Evidence (2026-10-30): the frozen UI requests at most
// avatar size 45 and preview height 150; the next power of two above that with
// 2x headroom is 512. Measured cost on the target platform: a 512 px PNG
// derivation allocates ~4.2 MiB and takes ~6 ms from a 64x64 source, against
// ~13.5 MiB / ~26 ms at 1024. Over-limit requests are clamped, not rejected
// (user decision 4B).
const (
	maxAvatarSize    = 512
	maxPreviewHeight = 512
)

func (a *App) serveAvatar(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, kind, value string) {
	size := 100
	if raw := r.URL.Query().Get("size"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			size = parsed
		}
	}
	if size < 1 {
		size = 1
	}
	if size > maxAvatarSize {
		size = maxAvatarSize
	}
	_, threeD := r.URL.Query()["3d"]
	_, pngFormat := r.URL.Query()["png"]
	payload, contentType, modified, err := a.images.Avatar(r.Context(), kind, value, size, threeD, pngFormat)
	switch {
	case errors.Is(err, images.ErrNotFound):
		a.notFound(w, r)
		return
	case errors.Is(err, images.ErrAvatarType):
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	case err != nil:
		a.serverError(w, r, b)
		return
	}
	if err := a.images.ServeBytes(w, r, payload, contentType, modified); err != nil {
		a.serverError(w, r, b)
	}
}

func (a *App) texturePreview(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.servePreview(w, r, b, "tid", r.PathValue("texture"))
}

func (a *App) hashPreview(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.servePreview(w, r, b, "hash", r.PathValue("hash"))
}

func (a *App) servePreview(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, kind, value string) {
	height := 200
	if raw := r.URL.Query().Get("height"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			height = parsed
		}
	}
	if height < 1 {
		height = 1
	}
	if height > maxPreviewHeight {
		height = maxPreviewHeight
	}
	_, pngFormat := r.URL.Query()["png"]
	payload, contentType, modified, err := a.images.Preview(r.Context(), kind, value, height, pngFormat)
	switch {
	case errors.Is(err, images.ErrNotFound):
		a.notFound(w, r)
		return
	case err != nil:
		a.serverError(w, r, b)
		return
	}
	if err := a.images.ServeBytes(w, r, payload, contentType, modified); err != nil {
		a.serverError(w, r, b)
	}
}
