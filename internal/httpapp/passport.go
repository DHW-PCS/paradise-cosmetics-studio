package httpapp

import (
	"errors"
	"net/http"
	"strconv"

	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/oauthserver"
)

// The eleven frozen Passport management handlers. Registration stays with
// the composition root: every route is browser(true, false) — an
// authenticated session, never administrator — writes carry the CSRF check,
// lists answer bare JSON arrays (creation 201, update 200, deletion 204),
// and SQL faults keep the service error. Ownership follows the service
// contract: unknown and foreign ids both answer 404 so they cannot be
// enumerated. The frozen dynamic registration applies `verified` only to
// the clients and tokens endpoints below (plus manage and authorize in
// consent.go); scopes, personal-access-tokens, token issuance/refresh and
// the non-frozen client detail keep their existing conditions.
// passportVerified applies the frozen `verified` middleware condition
// inside the handler, following the requireVerified pattern used by the
// player/texture handlers. Route registration in app.go stays untouched.
// The production composition root always sets the site service; the
// minimal slice harness (sliceApp) leaves it nil and carries the default
// require_verification=false, so there is nothing to enforce there.
func (a *App) passportVerified(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) bool {
	if a.site == nil {
		return true
	}
	options, err := a.site.Options(r.Context())
	if err != nil {
		a.serverError(w, r, b)
		return false
	}
	return a.requireVerified(w, r, b, options)
}

func (a *App) oauthClientsList(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if !a.passportVerified(w, r, b) {
		return
	}
	rows, err := a.oauth.ListClients(r.Context(), b)
	a.passportResponse(w, r, b, http.StatusOK, rows, err)
}

func (a *App) oauthClientCreate(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if !a.passportVerified(w, r, b) {
		return
	}
	v, ok := a.passportInput(w, r, b)
	if !ok {
		return
	}
	if !a.csrf(w, r, b, v) {
		return
	}
	grants, valid := v.list("grant_types")
	if !valid {
		a.passportValidation(w, r, b, "grant_types")
		return
	}
	scopes, valid := v.list("scopes")
	if !valid {
		a.passportValidation(w, r, b, "scopes")
		return
	}
	row, err := a.oauth.CreateClient(r.Context(), b, v.text("name"), v.text("redirect"), grants, scopes)
	a.passportResponse(w, r, b, http.StatusCreated, row, err)
}

func (a *App) oauthClientUpdate(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if !a.passportVerified(w, r, b) {
		return
	}
	id, ok := a.passportID(w, r, b, "client_id")
	if !ok {
		return
	}
	v, decoded := a.passportInput(w, r, b)
	if !decoded {
		return
	}
	if !a.csrf(w, r, b, v) {
		return
	}
	grants, valid := v.list("grant_types")
	if !valid {
		a.passportValidation(w, r, b, "grant_types")
		return
	}
	scopes, valid := v.list("scopes")
	if !valid {
		a.passportValidation(w, r, b, "scopes")
		return
	}
	row, err := a.oauth.UpdateClient(r.Context(), b, id, v.text("name"), v.text("redirect"), grants, scopes)
	a.passportResponse(w, r, b, http.StatusOK, row, err)
}

func (a *App) oauthClientDelete(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if !a.passportVerified(w, r, b) {
		return
	}
	id, ok := a.passportID(w, r, b, "client_id")
	if !ok {
		return
	}
	if !a.passportWrite(w, r, b) {
		return
	}
	if err := a.oauth.DeleteClient(r.Context(), b, id); err != nil {
		a.passportResponse(w, r, b, http.StatusNoContent, nil, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// oauthClientDetail serves the manage page's single-client data point; it
// has no frozen upstream route, so the composition root registers it only
// if the page needs it.
func (a *App) oauthClientDetail(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	id, ok := a.passportID(w, r, b, "client_id")
	if !ok {
		return
	}
	row, err := a.oauth.GetClientDetail(r.Context(), b, id)
	a.passportResponse(w, r, b, http.StatusOK, row, err)
}

func (a *App) oauthPassportScopesList(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	rows, err := a.oauth.ScopesList(r.Context(), b)
	a.passportResponse(w, r, b, http.StatusOK, rows, err)
}

func (a *App) oauthPersonalTokensList(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	rows, err := a.oauth.ListPersonalTokens(r.Context(), b)
	a.passportResponse(w, r, b, http.StatusOK, rows, err)
}

func (a *App) oauthPersonalTokenCreate(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	v, ok := a.passportInput(w, r, b)
	if !ok {
		return
	}
	if !a.csrf(w, r, b, v) {
		return
	}
	scopes, valid := v.list("scopes")
	if !valid {
		a.passportValidation(w, r, b, "scopes")
		return
	}
	row, err := a.oauth.CreatePersonalToken(r.Context(), b, v.text("name"), scopes)
	a.passportResponse(w, r, b, http.StatusCreated, row, err)
}

func (a *App) oauthPersonalTokenDelete(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	id, ok := a.passportTokenID(w, r, "token_id")
	if !ok {
		return
	}
	if !a.passportWrite(w, r, b) {
		return
	}
	if err := a.oauth.RevokePersonalToken(r.Context(), b, id); err != nil {
		a.passportResponse(w, r, b, http.StatusNoContent, nil, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) oauthTokensList(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if !a.passportVerified(w, r, b) {
		return
	}
	rows, err := a.oauth.ListTokens(r.Context(), b)
	a.passportResponse(w, r, b, http.StatusOK, rows, err)
}

func (a *App) oauthTokenDelete(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if !a.passportVerified(w, r, b) {
		return
	}
	id, ok := a.passportTokenID(w, r, "token_id")
	if !ok {
		return
	}
	if !a.passportWrite(w, r, b) {
		return
	}
	if err := a.oauth.RevokeToken(r.Context(), b, id); err != nil {
		a.passportResponse(w, r, b, http.StatusNoContent, nil, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// passportInput decodes the JSON body, reporting a malformed body as a
// 422 request error like the frozen endpoints.
func (a *App) passportInput(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) (input, bool) {
	v, err := decode(r)
	if err != nil {
		validation(w, map[string][]string{"request": {a.fieldMessage(r, b, "request", "json")}})
		return nil, false
	}
	return v, true
}

// passportWrite carries the write check for bodyless deletions: the body is
// only a CSRF carrier, in the same shape as the frozen DELETE handlers.
func (a *App) passportWrite(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) bool {
	v, ok := a.passportInput(w, r, b)
	return ok && a.csrf(w, r, b, v)
}

func (a *App) passportID(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, field string) (int64, bool) {
	id, parseErr := strconv.ParseInt(r.PathValue(field), 10, 64)
	if parseErr != nil || id < 1 {
		failure(w, 404, oauthserver.ErrPassportNotFound.Error())
		return 0, false
	}
	return id, true
}

func (a *App) passportTokenID(w http.ResponseWriter, r *http.Request, field string) (string, bool) {
	id := r.PathValue(field)
	if id == "" {
		failure(w, 404, oauthserver.ErrPassportNotFound.Error())
		return "", false
	}
	return id, true
}

func (a *App) passportValidation(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, field string) {
	validation(w, map[string][]string{field: {a.fieldMessage(r, b, field, "array")}})
}

// passportResponse maps the service contract: invalid input and scope
// failures are 422, conflicts 409, unknown or foreign ids 404, expired
// sessions 401 and everything else (including SQL faults) the service error.
func (a *App) passportResponse(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, status int, row any, err error) {
	switch {
	case err == nil:
		jsonResponse(w, status, row)
	case errors.Is(err, oauthserver.ErrInvalidInput), errors.Is(err, oauthserver.ErrScope):
		validation(w, map[string][]string{"request": {err.Error()}})
	case errors.Is(err, oauthserver.ErrPassportConflict):
		failure(w, 409, oauthserver.ErrPassportConflict.Error())
	case errors.Is(err, oauthserver.ErrPassportNotFound):
		failure(w, 404, oauthserver.ErrPassportNotFound.Error())
	case errors.Is(err, identity.ErrSession):
		failure(w, 401, a.message(r, b, "auth.check.anonymous"))
	default:
		a.serverError(w, r, b)
	}
}

// list reads a JSON array field, or a single string (a form-encoded body
// carries one value per field). Anything else is invalid input.
func (v input) list(key string) ([]string, bool) {
	raw, present := v[key]
	if !present || raw == nil {
		return nil, true
	}
	switch value := raw.(type) {
	case string:
		return []string{value}, true
	case []any:
		out := []string{}
		for _, item := range value {
			text, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, text)
		}
		return out, true
	default:
		return nil, false
	}
}
