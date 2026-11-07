package httpapp

import (
	"errors"
	"net/http"
	"strconv"

	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/oauthserver"
)

// The four maintenance entries respond like the reviewed contract: 201/200
// rows, 204 delete, 404 missing, 422 invalid input, 409 collisions, 403
// refusal, and SQL faults keep the service error. No consent UI covers
// these responses; the technical copy stays plain.
func (a *App) oauthScopesList(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	rows, err := a.oauth.CustomScopes(r.Context())
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	jsonResponse(w, 200, rows)
}

func (a *App) oauthScopesCreate(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	v, err := decode(r)
	if err != nil {
		validation(w, map[string][]string{"request": {a.fieldMessage(r, b, "request", "json")}})
		return
	}
	if !a.csrf(w, r, b, v) {
		return
	}
	row, err := a.oauth.CreateScope(r.Context(), b, v.text("name"), v.text("description"))
	a.oauthScopeResponse(w, r, b, http.StatusCreated, row, err)
}

func (a *App) oauthScopesUpdate(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	v, err := decode(r)
	if err != nil {
		validation(w, map[string][]string{"request": {a.fieldMessage(r, b, "request", "json")}})
		return
	}
	if !a.csrf(w, r, b, v) {
		return
	}
	id, parseErr := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if parseErr != nil {
		failure(w, 404, oauthserver.ErrMissingRow.Error())
		return
	}
	row, err := a.oauth.UpdateScope(r.Context(), b, id, v.text("name"), v.text("description"))
	a.oauthScopeResponse(w, r, b, http.StatusOK, row, err)
}

func (a *App) oauthScopesDelete(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	v, err := decode(r)
	if err != nil {
		validation(w, map[string][]string{"request": {a.fieldMessage(r, b, "request", "json")}})
		return
	}
	if !a.csrf(w, r, b, v) {
		return
	}
	id, parseErr := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if parseErr != nil {
		failure(w, 404, oauthserver.ErrMissingRow.Error())
		return
	}
	if err := a.oauth.DeleteScope(r.Context(), b, id); err != nil {
		a.oauthScopeResponse(w, r, b, http.StatusNoContent, nil, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) oauthScopeResponse(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, created int, row any, err error) {
	switch {
	case err == nil:
		jsonResponse(w, created, row)
	case errors.Is(err, oauthserver.ErrInvalidInput), errors.Is(err, oauthserver.ErrScopeName), errors.Is(err, oauthserver.ErrScopeLength):
		// No scope-management UI exists, so the 422 body carries the
		// technical rule instead of a translated frozen copy.
		validation(w, map[string][]string{"name": {err.Error()}})
	case errors.Is(err, oauthserver.ErrConflict):
		failure(w, 409, oauthserver.ErrConflict.Error())
	case errors.Is(err, oauthserver.ErrMissingRow):
		failure(w, 404, oauthserver.ErrMissingRow.Error())
	case errors.Is(err, oauthserver.ErrAdmin):
		failure(w, 403, a.message(r, b, "auth.check.admin"))
	case errors.Is(err, identity.ErrSession):
		failure(w, 401, a.message(r, b, "auth.check.anonymous"))
	default:
		a.serverError(w, r, b)
	}
}
