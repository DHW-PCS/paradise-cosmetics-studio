package httpapp

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/legacy/rules"
	"blessing-skin-go/internal/players"
	"blessing-skin-go/internal/site"
)

func (a *App) authorizationFailure(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, err error) bool {
	switch {
	case errors.Is(err, players.ErrNotFound):
		a.notFound(w, r)
		return true
	case errors.Is(err, players.ErrNoPermission):
		jsonResponse(w, http.StatusForbidden, map[string]any{"code": 1, "message": a.message(r, b, "admin.players.no-permission")})
		return true
	default:
		a.serverError(w, r, b)
		return true
	}
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

// requireVerified mirrors the frozen `verified` route middleware: when email
// verification is required, both pages and AJAX endpoints are rejected with 403.
func (a *App) requireVerified(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, options map[string]any) bool {
	if !site.Truth(options["require_verification"]) || b.User.Verified {
		return true
	}
	if wantsJSON(r) {
		failure(w, http.StatusForbidden, a.message(r, b, "auth.check.verified"))
	} else {
		a.errorPage(w, r, http.StatusForbidden, "auth.check.verified")
	}
	return false
}

func stringField(value any) string {
	text, _ := value.(string)
	return text
}

// playerNameField performs the frozen name validation for both endpoints.
func (a *App) playerNameField(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, v input, field string, fields map[string][]string, options map[string]any) bool {
	min := int(site.Number(options["player_name_length_min"]))
	max := int(site.Number(options["player_name_length_max"]))
	a.requiredText(r, b, v, fields, field, min, max)
	if fields[field] != nil {
		return false
	}
	name := v.text(field)
	if name == "" {
		return false
	}
	valid, err := rules.MatchPlayer(stringField(options["player_name_rule"]), stringField(options["custom_player_name_regexp"]), name)
	if err != nil {
		a.serverError(w, r, b)
		return false
	}
	if !valid {
		fields[field] = []string{a.message(r, b, "user.player.player-name-rule."+stringField(options["player_name_rule"]))}
	}
	return len(fields) == 0
}

func (a *App) playerPage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	options, err := a.site.Options(r.Context())
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !a.requireVerified(w, r, b, options) {
		return
	}
	a.render(w, r, b, "user/player", "general.player-manage", false)
}

func (a *App) playerList(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	options, err := a.site.Options(r.Context())
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !a.requireVerified(w, r, b, options) {
		return
	}
	list, err := a.players.List(r.Context(), b)
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	jsonResponse(w, http.StatusOK, list)
}

func (a *App) playerAdd(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	options, err := a.site.Options(r.Context())
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !a.requireVerified(w, r, b, options) {
		return
	}
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	fields := map[string][]string{}
	if !a.playerNameField(w, r, b, v, "name", fields, options) {
		if len(fields) > 0 {
			validation(w, fields)
		}
		return
	}
	player, err := a.players.Add(r.Context(), b, v.text("name"))
	switch {
	case errors.Is(err, players.ErrPlayerUsed):
		validation(w, map[string][]string{"name": {a.fieldMessage(r, b, "name", "unique")}})
		return
	case errors.Is(err, players.ErrLackScore):
		a.business(w, r, b, 7, "user.player.add.lack-score")
		return
	case errors.Is(err, players.ErrInvalidName):
		validation(w, map[string][]string{"name": {a.message(r, b, "user.player.player-name-rule."+stringField(options["player_name_rule"]))}})
		return
	case errors.Is(err, players.ErrConflict):
		a.serverError(w, r, b)
		return
	case err != nil:
		a.serverError(w, r, b)
		return
	}
	message := a.message(r, b, "user.player.add.success", ":name", player.Name)
	jsonResponse(w, http.StatusOK, map[string]any{"code": 0, "message": message, "data": player})
}

func (a *App) playerRename(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	options, err := a.site.Options(r.Context())
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !a.requireVerified(w, r, b, options) {
		return
	}
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
	fields := map[string][]string{}
	if !a.playerNameField(w, r, b, v, "name", fields, options) {
		if len(fields) > 0 {
			validation(w, fields)
		}
		return
	}
	player, oldName, err := a.players.Rename(r.Context(), b, pid, v.text("name"), players.Normal)
	switch {
	case errors.Is(err, players.ErrNotFound):
		a.notFound(w, r)
		return
	case errors.Is(err, players.ErrPlayerUsed):
		validation(w, map[string][]string{"name": {a.fieldMessage(r, b, "name", "unique")}})
		return
	case errors.Is(err, players.ErrInvalidName):
		validation(w, map[string][]string{"name": {a.message(r, b, "user.player.player-name-rule."+stringField(options["player_name_rule"]))}})
		return
	case errors.Is(err, players.ErrNoPermission):
		jsonResponse(w, http.StatusForbidden, map[string]any{"code": 1, "message": a.message(r, b, "admin.players.no-permission")})
		return
	case errors.Is(err, players.ErrUUIDUnavailable), errors.Is(err, players.ErrUUIDAmbiguous),
		errors.Is(err, players.ErrUUIDConflict), errors.Is(err, players.ErrUUIDMalformed), errors.Is(err, players.ErrConflict):
		a.serverError(w, r, b)
		return
	case err != nil:
		a.serverError(w, r, b)
		return
	}
	message := a.message(r, b, "user.player.rename.success", ":old", oldName, ":new", player.Name)
	jsonResponse(w, http.StatusOK, map[string]any{"code": 0, "message": message, "data": player})
}

func (a *App) playerDelete(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	options, err := a.site.Options(r.Context())
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !a.requireVerified(w, r, b, options) {
		return
	}
	if _, ok := a.body(w, r, b); !ok {
		return
	}
	pid, err := strconv.ParseInt(r.PathValue("player"), 10, 64)
	if err != nil {
		a.notFound(w, r)
		return
	}
	name, err := a.players.Delete(r.Context(), b, pid, players.Normal)
	if err != nil {
		switch {
		case errors.Is(err, players.ErrNotFound):
			a.notFound(w, r)
			return
		case errors.Is(err, players.ErrNoPermission):
			jsonResponse(w, http.StatusForbidden, map[string]any{"code": 1, "message": a.message(r, b, "admin.players.no-permission")})
			return
		default:
			a.serverError(w, r, b)
			return
		}
	}
	a.business(w, r, b, 0, "user.player.delete.success", ":name", name)
}

func (a *App) adminPlayersPage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.render(w, r, b, "admin/players", "general.player-manage", false)
}

func (a *App) adminPlayersList(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	page := 1
	if raw := r.URL.Query().Get("page"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			page = parsed
		}
	}
	query := r.URL.Query().Get("q")
	// The frozen controllers never call withQueryString(), so paginator URLs
	// carry only page= even when q= is present.
	path := a.cfg.BaseURL + strings.TrimPrefix(r.URL.Path, a.basePath)
	value, err := a.players.AdminList(r.Context(), page, query, path)
	if err != nil {
		a.searchError(w, r, b, err)
		return
	}
	jsonResponse(w, http.StatusOK, value)
}

func (a *App) adminPlayerRename(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	options, err := a.site.Options(r.Context())
	if err != nil {
		a.serverError(w, r, b)
		return
	}
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
	if !a.playerNameField(w, r, b, v, "player_name", fields, options) {
		if len(fields) > 0 {
			validation(w, fields)
		}
		return
	}
	player, _, err := a.players.Rename(r.Context(), b, pid, v.text("player_name"), players.Admin)
	switch {
	case errors.Is(err, players.ErrNotFound):
		a.notFound(w, r)
		return
	case errors.Is(err, players.ErrPlayerUsed):
		validation(w, map[string][]string{"player_name": {a.fieldMessage(r, b, "player_name", "unique")}})
		return
	case errors.Is(err, players.ErrNoPermission):
		jsonResponse(w, http.StatusForbidden, map[string]any{"code": 1, "message": a.message(r, b, "admin.players.no-permission")})
		return
	case errors.Is(err, players.ErrInvalidName):
		validation(w, map[string][]string{"player_name": {a.message(r, b, "user.player.player-name-rule."+stringField(options["player_name_rule"]))}})
		return
	case err != nil:
		a.serverError(w, r, b)
		return
	}
	a.business(w, r, b, 0, "admin.players.name.success", ":player", player.Name)
}

func (a *App) adminPlayerOwner(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
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
	if raw, present := v["uid"]; !present || raw == nil {
		validation(w, map[string][]string{"uid": {a.fieldMessage(r, b, "uid", "required")}})
		return
	}
	uid, err := integerValue(v, "uid")
	if err != nil {
		validation(w, map[string][]string{"uid": {a.fieldMessage(r, b, "uid", "integer")}})
		return
	}
	result, err := a.players.Transfer(r.Context(), b, pid, uid)
	switch {
	case errors.Is(err, players.ErrTargetMissing):
		a.business(w, r, b, 1, "admin.users.operations.non-existent")
		return
	case errors.Is(err, players.ErrNotFound):
		a.notFound(w, r)
		return
	case errors.Is(err, players.ErrNoPermission):
		jsonResponse(w, http.StatusForbidden, map[string]any{"code": 1, "message": a.message(r, b, "admin.players.no-permission")})
		return
	case errors.Is(err, players.ErrConflict):
		a.serverError(w, r, b)
		return
	case err != nil:
		a.serverError(w, r, b)
		return
	}
	a.business(w, r, b, 0, "admin.players.owner.success", ":player", result.PlayerName, ":user", result.OwnerNickname)
}

func (a *App) adminPlayerDelete(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
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
	if _, ok := a.body(w, r, b); !ok {
		return
	}
	if _, err = a.players.Delete(r.Context(), b, pid, players.Admin); err != nil {
		switch {
		case errors.Is(err, players.ErrNotFound):
			a.notFound(w, r)
			return
		case errors.Is(err, players.ErrNoPermission):
			jsonResponse(w, http.StatusForbidden, map[string]any{"code": 1, "message": a.message(r, b, "admin.players.no-permission")})
			return
		default:
			a.serverError(w, r, b)
			return
		}
	}
	a.business(w, r, b, 0, "admin.players.delete.success")
}
