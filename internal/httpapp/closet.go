package httpapp

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"blessing-skin-go/internal/closet"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/textures"
)

// verifiedTexture keeps the frozen `authorize+verified` group for the texture
// mutation endpoints.
func (a *App) verifiedTexture(next func(http.ResponseWriter, *http.Request, *identity.BrowserSession)) func(http.ResponseWriter, *http.Request, *identity.BrowserSession) {
	return func(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
		options, err := a.site.Options(r.Context())
		if err != nil {
			a.serverError(w, r, b)
			return
		}
		if !a.requireVerified(w, r, b, options) {
			return
		}
		next(w, r, b)
	}
}

func (a *App) closetPage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.render(w, r, b, "user/closet", "general.my-closet", false)
}

func (a *App) closetList(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	page := 1
	if parsed, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil {
		page = parsed
	}
	perPage := 6
	if parsed, err := strconv.Atoi(r.URL.Query().Get("perPage")); err == nil {
		perPage = parsed
	}
	path := a.cfg.BaseURL + strings.TrimPrefix(r.URL.Path, a.basePath)
	value, err := a.closet.List(r.Context(), b, r.URL.Query().Get("category"), r.URL.Query().Get("q"), page, perPage, path)
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	jsonResponse(w, http.StatusOK, value)
}

func (a *App) closetIDs(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	ids, err := a.closet.IDs(r.Context(), b)
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	jsonResponse(w, http.StatusOK, ids)
}

func (a *App) closetAdd(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	fields := map[string][]string{}
	tid, err := integerValue(v, "tid")
	if err != nil || tid <= 0 {
		fields["tid"] = []string{a.fieldMessage(r, b, "tid", "integer")}
	}
	name := v.text("name")
	if name == "" {
		fields["name"] = []string{a.fieldMessage(r, b, "name", "required")}
	}
	if len(fields) > 0 {
		validation(w, fields)
		return
	}
	err = a.closet.Add(r.Context(), b, tid, name)
	switch {
	case errors.Is(err, closet.ErrNotFound):
		a.business(w, r, b, 1, "user.closet.add.not-found")
		return
	case errors.Is(err, closet.ErrPrivate):
		a.business(w, r, b, 1, "skinlib.show.private")
		return
	case errors.Is(err, closet.ErrRepeated):
		a.business(w, r, b, 1, "user.closet.add.repeated")
		return
	case errors.Is(err, closet.ErrLackScore):
		a.business(w, r, b, 1, "user.closet.add.lack-score")
		return
	case err != nil:
		a.serverError(w, r, b)
		return
	}
	a.business(w, r, b, 0, "user.closet.add.success", ":name", name)
}

func (a *App) closetRename(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	tid, err := strconv.ParseInt(r.PathValue("tid"), 10, 64)
	if err != nil {
		a.notFound(w, r)
		return
	}
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	name := v.text("name")
	if name == "" {
		validation(w, map[string][]string{"name": {a.fieldMessage(r, b, "name", "required")}})
		return
	}
	if err = a.closet.Rename(r.Context(), b, tid, name); err != nil {
		if errors.Is(err, closet.ErrNotFound) {
			a.business(w, r, b, 1, "user.closet.remove.non-existent")
			return
		}
		a.serverError(w, r, b)
		return
	}
	a.business(w, r, b, 0, "user.closet.rename.success", ":name", name)
}

func (a *App) closetRemove(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	tid, err := strconv.ParseInt(r.PathValue("tid"), 10, 64)
	if err != nil {
		a.notFound(w, r)
		return
	}
	if _, ok := a.body(w, r, b); !ok {
		return
	}
	if err = a.closet.Remove(r.Context(), b, tid); err != nil {
		if errors.Is(err, closet.ErrNotFound) {
			a.business(w, r, b, 1, "user.closet.remove.non-existent")
			return
		}
		a.serverError(w, r, b)
		return
	}
	a.business(w, r, b, 0, "user.closet.remove.success")
}

func (a *App) textureRename(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	tid, err := strconv.ParseInt(r.PathValue("texture"), 10, 64)
	if err != nil {
		a.notFound(w, r)
		return
	}
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	name := v.text("name")
	if name == "" {
		validation(w, map[string][]string{"name": {a.fieldMessage(r, b, "name", "required")}})
		return
	}
	if err = a.closet.RenameTexture(r.Context(), b, tid, name); err != nil {
		if errors.Is(err, closet.ErrInvalidName) {
			validation(w, map[string][]string{"name": {a.fieldMessage(r, b, "name", "regex")}})
			return
		}
		a.textureMutationError(w, r, b, err)
		return
	}
	a.business(w, r, b, 0, "skinlib.rename.success", ":name", name)
}

func (a *App) textureType(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	tid, err := strconv.ParseInt(r.PathValue("texture"), 10, 64)
	if err != nil {
		a.notFound(w, r)
		return
	}
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	kind := v.text("type")
	if kind != "steve" && kind != "alex" && kind != "cape" {
		validation(w, map[string][]string{"type": {a.fieldMessage(r, b, "type", "in")}})
		return
	}
	if err = a.closet.SetTextureType(r.Context(), b, tid, kind); err != nil {
		a.textureMutationError(w, r, b, err)
		return
	}
	a.business(w, r, b, 0, "skinlib.model.success", ":model", kind)
}

func (a *App) texturePrivacy(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	tid, err := strconv.ParseInt(r.PathValue("texture"), 10, 64)
	if err != nil {
		a.notFound(w, r)
		return
	}
	if _, ok := a.body(w, r, b); !ok {
		return
	}
	public, err := a.closet.SetPrivacy(r.Context(), b, tid)
	var duplicate *closet.DuplicateTexture
	switch {
	case errors.As(err, &duplicate):
		jsonResponse(w, http.StatusOK, map[string]any{"code": 2, "message": a.message(r, b, "skinlib.upload.repeated"), "data": map[string]int64{"tid": duplicate.TID}})
		return
	case errors.Is(err, closet.ErrLackScore):
		a.business(w, r, b, 1, "skinlib.upload.lack-score")
		return
	case err != nil:
		a.textureMutationError(w, r, b, err)
		return
	}
	privacy := "private"
	if public {
		privacy = "public"
	}
	a.business(w, r, b, 0, "skinlib.privacy.success", ":privacy", a.message(r, b, "general."+privacy))
}

func (a *App) textureDelete(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	tid, err := strconv.ParseInt(r.PathValue("texture"), 10, 64)
	if err != nil {
		a.notFound(w, r)
		return
	}
	if _, ok := a.body(w, r, b); !ok {
		return
	}
	if err = a.closet.DeleteTexture(r.Context(), b, tid); err != nil {
		a.textureMutationError(w, r, b, err)
		return
	}
	a.business(w, r, b, 0, "skinlib.delete.success")
}

func (a *App) textureMutationError(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, err error) {
	switch {
	case errors.Is(err, closet.ErrNotFound), errors.Is(err, textures.ErrNotFound):
		a.abortFor(w, r, b, http.StatusNotFound, "skinlib.show.deleted")
	case errors.Is(err, closet.ErrNoPermission):
		jsonResponse(w, http.StatusForbidden, map[string]any{"code": 1, "message": a.message(r, b, "skinlib.no-permission")})
	case errors.Is(err, closet.ErrConflict):
		a.serverError(w, r, b)
	default:
		a.serverError(w, r, b)
	}
}

func (a *App) adminClosetAdd(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	uid, err := strconv.ParseInt(r.PathValue("user"), 10, 64)
	if err != nil {
		a.notFound(w, r)
		return
	}
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	tid, err := integerValue(v, "tid")
	if err != nil {
		validation(w, map[string][]string{"tid": {a.fieldMessage(r, b, "tid", "integer")}})
		return
	}
	data, err := a.closet.AdminAdd(r.Context(), b, uid, tid)
	if err != nil {
		if errors.Is(err, closet.ErrNoPermission) {
			jsonResponse(w, http.StatusForbidden, map[string]any{"code": 1, "message": a.message(r, b, "admin.users.operations.no-permission")})
			return
		}
		if errors.Is(err, closet.ErrTargetNotFound) {
			a.notFound(w, r)
			return
		}
		a.textureMutationError(w, r, b, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"code": 0, "message": "", "data": data})
}

func (a *App) adminClosetRemove(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	uid, err := strconv.ParseInt(r.PathValue("user"), 10, 64)
	if err != nil {
		a.notFound(w, r)
		return
	}
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	tid, err := integerValue(v, "tid")
	if err != nil {
		validation(w, map[string][]string{"tid": {a.fieldMessage(r, b, "tid", "integer")}})
		return
	}
	data, err := a.closet.AdminRemove(r.Context(), b, uid, tid)
	if err != nil {
		if errors.Is(err, closet.ErrNoPermission) {
			jsonResponse(w, http.StatusForbidden, map[string]any{"code": 1, "message": a.message(r, b, "admin.users.operations.no-permission")})
			return
		}
		if errors.Is(err, closet.ErrTargetNotFound) {
			a.notFound(w, r)
			return
		}
		a.textureMutationError(w, r, b, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"code": 0, "message": "", "data": data})
}
