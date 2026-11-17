package httpapp

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/players"
)

func (a *App) playerSetTexture(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	pid, err := strconv.ParseInt(r.PathValue("player"), 10, 64)
	if err != nil {
		a.notFound(w, r)
		return
	}
	if err = a.players.Authorize(r.Context(), b, pid, players.Normal); err != nil {
		if a.authorizationFailure(w, r, b, err) {
			return
		}
	}
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	readSlot := func(key string) (*int64, bool) {
		raw, present := v[key]
		if !present || raw == nil {
			return nil, false
		}
		tid, convErr := integerValue(v, key)
		if convErr != nil {
			return nil, true
		}
		if tid == 0 {
			return nil, false
		}
		return &tid, false
	}
	skin, skinInvalid := readSlot("skin")
	cape, capeInvalid := readSlot("cape")
	if skinInvalid || capeInvalid {
		validation(w, map[string][]string{"textures": {a.fieldMessage(r, b, "textures", "integer")}})
		return
	}
	player, err := a.players.SetTextures(r.Context(), b, pid, skin, cape)
	switch {
	case errors.Is(err, players.ErrNotFound):
		a.business(w, r, b, 1, "skinlib.non-existent")
		return
	case errors.Is(err, players.ErrNotInCloset):
		a.business(w, r, b, 1, "user.closet.remove.non-existent")
		return
	case errors.Is(err, players.ErrTypeMismatch):
		a.business(w, r, b, 1, "general.illegal-parameters")
		return
	case errors.Is(err, players.ErrNoPermission), errors.Is(err, players.ErrConflict):
		a.authorizationFailure(w, r, b, err)
		return
	case err != nil:
		a.serverError(w, r, b)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"code": 0, "message": a.message(r, b, "user.player.set.success", ":name", player.Name), "data": player})
}

func (a *App) playerClearTexture(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	pid, err := strconv.ParseInt(r.PathValue("player"), 10, 64)
	if err != nil {
		a.notFound(w, r)
		return
	}
	if err = a.players.Authorize(r.Context(), b, pid, players.Normal); err != nil {
		if a.authorizationFailure(w, r, b, err) {
			return
		}
	}
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	var types []string
	if raw, present := v["type"]; present {
		switch value := raw.(type) {
		case string:
			types = append(types, value)
		case []any:
			for _, item := range value {
				if text, ok := item.(string); ok {
					types = append(types, text)
				}
			}
		}
	}
	_, hasSkin := v["skin"]
	_, hasCape := v["cape"]
	if _, present := r.URL.Query()["skin"]; present {
		hasSkin = true
	}
	if _, present := r.URL.Query()["cape"]; present {
		hasCape = true
	}
	skinSelected := hasSkin || contains(types, "skin")
	capeSelected := hasCape || contains(types, "cape")
	player, err := a.players.ClearTextures(r.Context(), b, pid, skinSelected, capeSelected)
	switch {
	case errors.Is(err, players.ErrNotFound):
		a.notFound(w, r)
		return
	case errors.Is(err, players.ErrNoPermission), errors.Is(err, players.ErrConflict):
		a.authorizationFailure(w, r, b, err)
		return
	case err != nil:
		a.serverError(w, r, b)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"code": 0, "message": a.message(r, b, "user.player.clear.success", ":name", player.Name), "data": player})
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (a *App) adminPlayerTexture(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	pid, err := strconv.ParseInt(r.PathValue("player"), 10, 64)
	if err != nil {
		a.notFound(w, r)
		return
	}
	if err = a.players.Authorize(r.Context(), b, pid, players.Admin); err != nil {
		if a.authorizationFailure(w, r, b, err) {
			return
		}
	}
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	fields := map[string][]string{}
	tid, tidErr := integerValue(v, "tid")
	if tidErr != nil {
		fields["tid"] = []string{a.fieldMessage(r, b, "tid", "integer")}
	}
	slot := v.text("type")
	if slot != "skin" && slot != "cape" {
		fields["type"] = []string{a.fieldMessage(r, b, "type", "in")}
	}
	if len(fields) > 0 {
		validation(w, fields)
		return
	}
	if err = a.players.AdminSetTexture(r.Context(), b, pid, tid, slot); err != nil {
		switch {
		case errors.Is(err, players.ErrNotFound):
			a.business(w, r, b, 1, "admin.players.textures.non-existent", ":tid", strconv.FormatInt(tid, 10))
			return
		case errors.Is(err, players.ErrTypeMismatch):
			a.business(w, r, b, 1, "general.illegal-parameters")
			return
		case errors.Is(err, players.ErrNoPermission), errors.Is(err, players.ErrConflict):
			a.authorizationFailure(w, r, b, err)
			return
		default:
			a.serverError(w, r, b)
			return
		}
	}
	name := a.message(r, b, "admin.players.textures.success", ":player", a.playerName(r.Context(), pid))
	jsonResponse(w, http.StatusOK, map[string]any{"code": 0, "message": name})
}

func (a *App) playerName(ctx context.Context, pid int64) string {
	var name string
	_ = a.site.Store.DB.QueryRowContext(ctx, "SELECT name FROM "+a.site.Store.Table("players")+" WHERE pid=?", pid).Scan(&name)
	return name
}
