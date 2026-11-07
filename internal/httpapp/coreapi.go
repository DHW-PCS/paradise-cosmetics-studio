// Yggdrasil core API handlers (M4-03 slice C2): 33 frozen /api entries.
// Auth: explicit Bearer wins (no fallback); otherwise API cookie with
// CSRF on every method. UID 0 is rejected. Scope and admin checks run
// inside the business *Actor transaction, never as a pre-check.
package httpapp

import (
	"errors"
	"net/http"
	"net/mail"

	"strconv"
	"strings"

	"blessing-skin-go/internal/account"
	"blessing-skin-go/internal/apilimits"
	"blessing-skin-go/internal/closet"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/notifications"
	"blessing-skin-go/internal/oauthserver"
	"blessing-skin-go/internal/players"
	"blessing-skin-go/internal/reports"
	"blessing-skin-go/internal/users"
)

// domainName keeps the frozen route.getDomain() semantics: API, root and
// token share no domain binding, so the anonymous key uses "".
const apiDomain = ""

func (a *App) apiLimiter() *apilimits.Service {
	return a.apiLimits
}

// apiWantJSON reports whether the client wants JSON. API defaults to JSON
// unless the client explicitly asks for HTML.
func apiWantJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		return true
	}
	if strings.Contains(accept, "text/html") {
		return false
	}
	return true
}

func (a *App) apiFailure(w http.ResponseWriter, r *http.Request, status int, messageKey string) {
	if !apiWantJSON(r) {
		a.errorPage(w, r, status, messageKey)
		return
	}
	failure(w, status, a.message(r, nil, messageKey))
}

// apiAuth authenticates and returns the Actor; on failure it writes the
// mapped response and returns nil,false. Bearer failure never falls back.
func (a *App) apiAuth(w http.ResponseWriter, r *http.Request) (identity.Actor, bool) {
	if HasBearer(r) {
		actor, err := a.oauth.AuthenticateActor(r.Context(), bearerValue(r))
		if err != nil {
			a.apiAuthFailure(w, r, err)
			return nil, false
		}
		if actor == nil || actor.UID() == 0 {
			a.apiAuthFailure(w, r, oauthserver.ErrToken)
			return nil, false
		}
		return actor, true
	}
	session, err := a.ResolveAPICookie(r)
	if err != nil {
		a.apiAuthFailure(w, r, err)
		return nil, false
	}
	actor, err := a.identity.NewAPICookieActor(session)
	if err != nil {
		a.apiAuthFailure(w, r, err)
		return nil, false
	}
	if actor == nil || actor.UID() == 0 {
		a.apiAuthFailure(w, r, oauthserver.ErrToken)
		return nil, false
	}
	return actor, true
}

func (a *App) apiAuthFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, oauthserver.ErrToken):
		a.apiFailure(w, r, http.StatusUnauthorized, "auth.check.anonymous")
	case errors.Is(err, oauthserver.ErrScope):
		a.apiFailure(w, r, http.StatusForbidden, "auth.check.admin")
	case errors.Is(err, oauthserver.ErrUnavailable):
		a.apiFailure(w, r, http.StatusServiceUnavailable, "errors.http.msg-500")
	case errors.Is(err, identity.ErrSession):
		a.apiFailure(w, r, http.StatusUnauthorized, "auth.check.anonymous")
	default:
		// SQL faults and other service errors: never map to 401/403.
		a.apiFailure(w, r, http.StatusInternalServerError, "errors.http.msg-500")
	}
}

// apiLimit consumes one limiter unit. Returns false if the response was
// already written (429 or service error). Caller must set headers before
// writing the body; apiLimit sets them.
func (a *App) apiLimit(w http.ResponseWriter, r *http.Request, uid int64) bool {
	svc := a.apiLimiter()
	if svc == nil {
		a.apiFailure(w, r, http.StatusServiceUnavailable, "errors.http.msg-500")
		return false
	}
	decision, err := svc.Take(r.Context(), uid, apiDomain, clientIP(r))
	if err != nil {
		a.apiFailure(w, r, http.StatusInternalServerError, "errors.http.msg-500")
		return false
	}
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(decision.Limit))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(decision.Remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(decision.ResetAt.Unix(), 10))
	if !decision.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(decision.RetryAfter))
		if !apiWantJSON(r) {
			a.errorPage(w, r, http.StatusTooManyRequests, "errors.http.msg-500")
			return false
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"message":"Too Many Attempts.","exception":true,"trace":[]}` + "\n"))
		return false
	}
	return true
}

// api wraps a handler with Bearer/cookie auth + post-auth limiter.
func (a *App) api(next func(http.ResponseWriter, *http.Request, identity.Actor)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := a.apiAuth(w, r)
		if !ok {
			return
		}
		if !a.apiLimit(w, r, actor.UID()) {
			return
		}
		next(w, r, actor)
	}
}

// apiRoot is the public ANY entry; only anonymous limiter applies.
func (a *App) apiRoot(w http.ResponseWriter, r *http.Request) {
	if !a.apiLimit(w, r, 0) {
		return
	}
	options, err := a.site.Options(r.Context())
	if err != nil {
		a.apiFailure(w, r, http.StatusServiceUnavailable, "errors.http.msg-500")
		return
	}
	copyright := ""
	// Preserve frozen copyright choice list semantics via existing helper.
	copyright = copyrightChoice(options)
	siteName, _ := options["site_name"].(string)
	jsonResponse(w, http.StatusOK, map[string]any{
		"blessing_skin": "6.0.2",
		"spec":          0,
		"copyright":     copyright,
		"site_name":     siteName,
	})
}

func copyrightChoice(options map[string]any) string {
	choices := []string{
		"Powered with ❤ by Blessing Skin Server.",
		"Powered by Blessing Skin Server.",
		"Proudly powered by Blessing Skin Server.",
		"由 Blessing Skin Server 强力驱动。",
		"采用 Blessing Skin Server 搭建。",
		"使用 Blessing Skin Server 稳定运行。",
		"自豪地采用 Blessing Skin Server。",
	}
	idx := 0
	switch v := options["copyright_prefer"].(type) {
	case int:
		idx = v
	case int64:
		idx = int(v)
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			idx = n
		}
	}
	if idx < 0 || idx >= len(choices) {
		idx = 0
	}
	return choices[idx]
}

// apiToken wraps POST /oauth/token with the anonymous shared limiter.
func (a *App) apiToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.apiLimit(w, r, 0) {
			return
		}
		next(w, r)
	}
}

// mapAPIError maps business errors to HTTP status; returns true if written.
func (a *App) mapAPIError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	// Auth/scope from recheck inside the business transaction.
	if errors.Is(err, oauthserver.ErrToken) {
		a.apiAuthFailure(w, r, err)
		return true
	}
	if errors.Is(err, oauthserver.ErrScope) {
		a.apiAuthFailure(w, r, err)
		return true
	}
	if errors.Is(err, oauthserver.ErrUnavailable) {
		a.apiAuthFailure(w, r, err)
		return true
	}
	// Deterministic missing admin target -> 404 (route-model binding).
	if errors.Is(err, closet.ErrTargetNotFound) {
		a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
		return true
	}
	// Business authorization -> 403. The frozen key is per resource:
	// players middleware returns admin.players.no-permission; the other
	// resources return admin.users.operations.no-permission.
	if errors.Is(err, players.ErrNoPermission) {
		a.apiFailure(w, r, http.StatusForbidden, "admin.players.no-permission")
		return true
	}
	if errors.Is(err, closet.ErrNoPermission) || errors.Is(err, reports.ErrNoPermission) ||
		errors.Is(err, users.ErrNoPermission) || errors.Is(err, notifications.ErrNoPermission) ||
		errors.Is(err, account.ErrForbidden) {
		a.apiFailure(w, r, http.StatusForbidden, "admin.users.operations.no-permission")
		return true
	}
	// Object missing -> 404.
	if errors.Is(err, players.ErrNotFound) || errors.Is(err, closet.ErrNotFound) ||
		errors.Is(err, reports.ErrNotFound) || errors.Is(err, account.ErrNotFound) ||
		errors.Is(err, notifications.ErrNotFound) {
		a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
		return true
	}
	// Concurrency conflicts are never identity-token failures.
	if errors.Is(err, players.ErrConflict) || errors.Is(err, closet.ErrConflict) {
		a.apiFailure(w, r, http.StatusConflict, "errors.http.msg-500")
		return true
	}
	// Browser session errors surfacing from services.
	if errors.Is(err, identity.ErrSession) {
		a.apiFailure(w, r, http.StatusUnauthorized, "auth.check.anonymous")
		return true
	}
	// Service fault.
	a.apiFailure(w, r, http.StatusServiceUnavailable, "errors.http.msg-500")
	return true
}

// helpers

func (a *App) apiPage(r *http.Request) int {
	page := 1
	if raw := r.URL.Query().Get("page"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 1 {
			page = parsed
		}
	}
	return page
}

func (a *App) apiPath(r *http.Request) string {
	return a.cfg.BaseURL + strings.TrimPrefix(r.URL.Path, a.basePath)
}

func (a *App) decodeAPI(w http.ResponseWriter, r *http.Request) (input, bool) {
	v, err := decode(r)
	if err != nil {
		validation(w, map[string][]string{"request": {a.fieldMessage(r, nil, "request", "json")}})
		return nil, false
	}
	return v, true
}

func parseID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

// --- 33 handlers ---

func (a *App) apiUser(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	user, err := a.accounts.CurrentActor(r.Context(), actor)
	if a.mapAPIError(w, r, err) {
		return
	}
	jsonResponse(w, http.StatusOK, user)
}

func (a *App) apiNotificationsUnread(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	list, err := a.notifications.UnreadActor(r.Context(), actor)
	if a.mapAPIError(w, r, err) {
		return
	}
	if list == nil {
		list = []notifications.Unread{}
	}
	jsonResponse(w, http.StatusOK, list)
}

func (a *App) apiNotificationRead(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	id := r.PathValue("id")
	if id == "" {
		a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
		return
	}
	result, err := a.notifications.ReadActor(r.Context(), actor, id)
	if errors.Is(err, notifications.ErrNotFound) {
		a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
		return
	}
	if a.mapAPIError(w, r, err) {
		return
	}
	jsonResponse(w, http.StatusOK, result)
}

func (a *App) apiPlayersList(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	list, err := a.players.ListActor(r.Context(), actor)
	if a.mapAPIError(w, r, err) {
		return
	}
	if list == nil {
		list = []players.Player{}
	}
	jsonResponse(w, http.StatusOK, list)
}

func (a *App) apiPlayersAdd(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	v, ok := a.decodeAPI(w, r)
	if !ok {
		return
	}
	name := v.text("name")
	if name == "" {
		validation(w, map[string][]string{"name": {a.fieldMessage(r, nil, "name", "required")}})
		return
	}
	player, err := a.players.AddActor(r.Context(), actor, name)
	if errors.Is(err, players.ErrPlayerUsed) {
		validation(w, map[string][]string{"name": {a.fieldMessage(r, nil, "name", "unique")}})
		return
	}
	if errors.Is(err, players.ErrLackScore) {
		a.apiBusiness(w, r, 7, "user.player.add.lack-score")
		return
	}
	if errors.Is(err, players.ErrInvalidName) {
		validation(w, map[string][]string{"name": {a.fieldMessage(r, nil, "name", "required")}})
		return
	}
	if a.mapAPIError(w, r, err) {
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"code": 0, "message": a.message(r, nil, "user.player.add.success", ":name", player.Name), "data": player})
}

func (a *App) apiPlayersDelete(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	pid, ok := parseID(w, r, "player")
	if !ok {
		a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
		return
	}
	name, err := a.players.DeleteActor(r.Context(), actor, pid, players.Normal)
	if a.mapAPIError(w, r, err) {
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"code": 0, "message": a.message(r, nil, "user.player.delete.success", ":name", name)})
}

func (a *App) apiPlayersRename(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	pid, ok := parseID(w, r, "player")
	if !ok {
		a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
		return
	}
	v, ok := a.decodeAPI(w, r)
	if !ok {
		return
	}
	name := v.text("name")
	if name == "" {
		validation(w, map[string][]string{"name": {a.fieldMessage(r, nil, "name", "required")}})
		return
	}
	player, oldName, err := a.players.RenameActor(r.Context(), actor, pid, name, players.Normal)
	if errors.Is(err, players.ErrPlayerUsed) {
		validation(w, map[string][]string{"name": {a.fieldMessage(r, nil, "name", "unique")}})
		return
	}
	if errors.Is(err, players.ErrInvalidName) {
		validation(w, map[string][]string{"name": {a.fieldMessage(r, nil, "name", "required")}})
		return
	}
	if a.mapAPIError(w, r, err) {
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"code": 0, "message": a.message(r, nil, "user.player.rename.success", ":old", oldName, ":new", player.Name), "data": player})
}

func (a *App) apiPlayersSetTextures(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	pid, ok := parseID(w, r, "player")
	if !ok {
		a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
		return
	}
	v, ok := a.decodeAPI(w, r)
	if !ok {
		return
	}
	readSlot := func(key string) (*int64, bool) {
		raw, present := v[key]
		if !present || raw == nil {
			return nil, false
		}
		tid, err := integerValue(v, key)
		if err != nil {
			return nil, true
		}
		if tid == 0 {
			return nil, false
		}
		return &tid, false
	}
	skin, skinBad := readSlot("skin")
	cape, capeBad := readSlot("cape")
	if skinBad || capeBad {
		validation(w, map[string][]string{"textures": {a.fieldMessage(r, nil, "textures", "integer")}})
		return
	}
	player, err := a.players.SetTexturesActor(r.Context(), actor, pid, skin, cape)
	if errors.Is(err, players.ErrNotFound) {
		a.apiBusiness(w, r, 1, "skinlib.non-existent")
		return
	}
	if errors.Is(err, players.ErrNotInCloset) {
		a.apiBusiness(w, r, 1, "user.closet.remove.non-existent")
		return
	}
	if errors.Is(err, players.ErrTypeMismatch) {
		a.apiBusiness(w, r, 1, "general.illegal-parameters")
		return
	}
	if a.mapAPIError(w, r, err) {
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"code": 0, "message": a.message(r, nil, "user.player.set.success", ":name", player.Name), "data": player})
}

func (a *App) apiPlayersClearTextures(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	pid, ok := parseID(w, r, "player")
	if !ok {
		a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
		return
	}
	v, ok := a.decodeAPI(w, r)
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
	player, err := a.players.ClearTexturesActor(r.Context(), actor, pid, skinSelected, capeSelected)
	if a.mapAPIError(w, r, err) {
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"code": 0, "message": a.message(r, nil, "user.player.clear.success", ":name", player.Name), "data": player})
}

func (a *App) apiClosetList(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	perPage := 6
	if raw := r.URL.Query().Get("perPage"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 1 {
			perPage = parsed
		}
	}
	value, err := a.closet.ListActor(r.Context(), actor, r.URL.Query().Get("category"), r.URL.Query().Get("q"), a.apiPage(r), perPage, a.apiPath(r))
	if a.mapAPIError(w, r, err) {
		return
	}
	jsonResponse(w, http.StatusOK, value)
}

func (a *App) apiClosetAdd(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	v, ok := a.decodeAPI(w, r)
	if !ok {
		return
	}
	fields := map[string][]string{}
	tid, err := integerValue(v, "tid")
	if err != nil {
		fields["tid"] = []string{a.fieldMessage(r, nil, "tid", "integer")}
	}
	name := v.text("name")
	if name == "" {
		fields["name"] = []string{a.fieldMessage(r, nil, "name", "required")}
	}
	if len(fields) > 0 {
		validation(w, fields)
		return
	}
	err = a.closet.AddActor(r.Context(), actor, tid, name)
	switch {
	case errors.Is(err, closet.ErrNotFound):
		a.apiBusiness(w, r, 1, "user.closet.add.not-found")
		return
	case errors.Is(err, closet.ErrPrivate):
		a.apiBusiness(w, r, 1, "skinlib.show.private")
		return
	case errors.Is(err, closet.ErrRepeated):
		a.apiBusiness(w, r, 1, "user.closet.add.repeated")
		return
	case errors.Is(err, closet.ErrLackScore):
		a.apiBusiness(w, r, 1, "user.closet.add.lack-score")
		return
	case errors.Is(err, closet.ErrInvalidName):
		validation(w, map[string][]string{"name": {a.fieldMessage(r, nil, "name", "required")}})
		return
	}
	if a.mapAPIError(w, r, err) {
		return
	}
	a.apiBusiness(w, r, 0, "user.closet.add.success", ":name", name)
}

func (a *App) apiClosetRename(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	tid, ok := parseID(w, r, "tid")
	if !ok {
		a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
		return
	}
	v, ok := a.decodeAPI(w, r)
	if !ok {
		return
	}
	name := v.text("name")
	if name == "" {
		validation(w, map[string][]string{"name": {a.fieldMessage(r, nil, "name", "required")}})
		return
	}
	err := a.closet.RenameActor(r.Context(), actor, tid, name)
	if errors.Is(err, closet.ErrNotFound) {
		a.apiBusiness(w, r, 1, "user.closet.remove.non-existent")
		return
	}
	if errors.Is(err, closet.ErrInvalidName) {
		validation(w, map[string][]string{"name": {a.fieldMessage(r, nil, "name", "required")}})
		return
	}
	if a.mapAPIError(w, r, err) {
		return
	}
	a.apiBusiness(w, r, 0, "user.closet.rename.success", ":name", name)
}

func (a *App) apiClosetRemove(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	tid, ok := parseID(w, r, "tid")
	if !ok {
		a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
		return
	}
	if _, ok := a.decodeAPI(w, r); !ok {
		// DELETE without body is allowed; decode returns empty on EOF.
	}
	err := a.closet.RemoveActor(r.Context(), actor, tid)
	if errors.Is(err, closet.ErrNotFound) {
		a.apiBusiness(w, r, 1, "user.closet.remove.non-existent")
		return
	}
	if a.mapAPIError(w, r, err) {
		return
	}
	a.apiBusiness(w, r, 0, "user.closet.remove.success")
}

func (a *App) apiBusiness(w http.ResponseWriter, r *http.Request, code int, key string, params ...string) {
	message := ""
	if key != "" {
		message = a.message(r, nil, key, params...)
	}
	jsonResponse(w, http.StatusOK, map[string]any{"code": code, "message": message})
}

func (a *App) apiAdminUsersList(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	value, err := a.usersAdmin.ListActor(r.Context(), actor, a.apiPage(r), r.URL.Query().Get("q"), a.apiPath(r))
	if a.mapAPIError(w, r, err) {
		return
	}
	jsonResponse(w, http.StatusOK, value)
}

func (a *App) apiAdminUserAction(action string) func(http.ResponseWriter, *http.Request, identity.Actor) {
	return func(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
		uid, ok := parseID(w, r, "user")
		if !ok {
			a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
			return
		}
		v, ok := a.decodeAPI(w, r)
		if !ok {
			// delete/verification may have no body
			if action != "delete" && action != "verification" {
				return
			}
			v = input{}
			ok = true
		}
		value := v.text(action)
		fields := map[string][]string{}
		switch action {
		case "email":
			a.emailField(r, nil, v, fields)
		case "nickname":
			a.requiredText(r, nil, v, fields, "nickname", 1, 0)
		case "password":
			a.requiredText(r, nil, v, fields, "password", 8, 16)
		case "score":
			if raw, present := v["score"]; !present || raw == nil {
				fields["score"] = []string{a.fieldMessage(r, nil, "score", "required")}
			} else if score, err := integerValue(v, "score"); err != nil {
				fields["score"] = []string{a.fieldMessage(r, nil, "score", "integer")}
			} else {
				value = strconv.FormatInt(score, 10)
			}
		case "permission":
			p, err := integerValue(v, "permission")
			if err != nil || (p != -1 && p != 0 && p != 1) {
				fields["permission"] = []string{a.fieldMessage(r, nil, "permission", "in")}
			}
			value = strconv.FormatInt(p, 10)
		}
		if len(fields) > 0 {
			validation(w, fields)
			return
		}
		err := a.accounts.AdminChangeActor(r.Context(), actor, uid, action, value)
		if errors.Is(err, account.ErrEmailUsed) {
			validation(w, map[string][]string{"email": {a.fieldMessage(r, nil, "email", "unique")}})
			return
		}
		if a.mapAPIError(w, r, err) {
			return
		}
		key := "admin.users.operations." + action + ".success"
		if action == "permission" {
			key = "admin.users.operations.permission"
		}
		a.apiBusiness(w, r, 0, key, ":new", value)
	}
}

func (a *App) apiAdminPlayersList(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	value, err := a.players.AdminListActor(r.Context(), actor, a.apiPage(r), r.URL.Query().Get("q"), a.apiPath(r))
	if a.mapAPIError(w, r, err) {
		return
	}
	jsonResponse(w, http.StatusOK, value)
}

func (a *App) apiAdminPlayerRename(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	pid, ok := parseID(w, r, "player")
	if !ok {
		a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
		return
	}
	v, ok := a.decodeAPI(w, r)
	if !ok {
		return
	}
	name := v.text("player_name")
	if name == "" {
		validation(w, map[string][]string{"player_name": {a.fieldMessage(r, nil, "player_name", "required")}})
		return
	}
	player, _, err := a.players.RenameActor(r.Context(), actor, pid, name, players.Admin)
	if errors.Is(err, players.ErrPlayerUsed) {
		validation(w, map[string][]string{"player_name": {a.fieldMessage(r, nil, "player_name", "unique")}})
		return
	}
	if errors.Is(err, players.ErrInvalidName) {
		validation(w, map[string][]string{"player_name": {a.fieldMessage(r, nil, "player_name", "required")}})
		return
	}
	if a.mapAPIError(w, r, err) {
		return
	}
	a.apiBusiness(w, r, 0, "admin.players.name.success", ":player", player.Name)
}

func (a *App) apiAdminPlayerOwner(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	pid, ok := parseID(w, r, "player")
	if !ok {
		a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
		return
	}
	v, ok := a.decodeAPI(w, r)
	if !ok {
		return
	}
	if raw, present := v["uid"]; !present || raw == nil {
		validation(w, map[string][]string{"uid": {a.fieldMessage(r, nil, "uid", "required")}})
		return
	}
	uid, err := integerValue(v, "uid")
	if err != nil {
		validation(w, map[string][]string{"uid": {a.fieldMessage(r, nil, "uid", "integer")}})
		return
	}
	result, err := a.players.TransferActor(r.Context(), actor, pid, uid)
	if errors.Is(err, players.ErrTargetMissing) {
		a.apiBusiness(w, r, 1, "admin.users.operations.non-existent")
		return
	}
	if a.mapAPIError(w, r, err) {
		return
	}
	a.apiBusiness(w, r, 0, "admin.players.owner.success", ":player", result.PlayerName, ":user", result.OwnerNickname)
}

func (a *App) apiAdminPlayerTextures(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	pid, ok := parseID(w, r, "player")
	if !ok {
		a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
		return
	}
	v, ok := a.decodeAPI(w, r)
	if !ok {
		return
	}
	tid, err := integerValue(v, "tid")
	if err != nil {
		validation(w, map[string][]string{"tid": {a.fieldMessage(r, nil, "tid", "integer")}})
		return
	}
	slot := v.text("type")
	if slot != "skin" && slot != "cape" {
		validation(w, map[string][]string{"type": {a.fieldMessage(r, nil, "type", "in")}})
		return
	}
	err = a.players.AdminSetTextureActor(r.Context(), actor, pid, tid, slot)
	if errors.Is(err, players.ErrNotFound) && tid != 0 {
		a.apiBusiness(w, r, 1, "admin.players.textures.non-existent", ":tid", strconv.FormatInt(tid, 10))
		return
	}
	if errors.Is(err, players.ErrTypeMismatch) {
		a.apiBusiness(w, r, 1, "general.illegal-parameters")
		return
	}
	if a.mapAPIError(w, r, err) {
		return
	}
	a.apiBusiness(w, r, 0, "admin.players.textures.success", ":player", a.playerName(r.Context(), pid))
}

func (a *App) apiAdminPlayersDelete(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	pid, ok := parseID(w, r, "player")
	if !ok {
		a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
		return
	}
	if _, err := a.players.DeleteActor(r.Context(), actor, pid, players.Admin); a.mapAPIError(w, r, err) {
		return
	}
	a.apiBusiness(w, r, 0, "admin.players.delete.success")
}

func (a *App) apiAdminClosetList(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	uid, ok := parseID(w, r, "user")
	if !ok {
		a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
		return
	}
	value, err := a.closet.AdminListActor(r.Context(), actor, uid)
	if a.mapAPIError(w, r, err) {
		return
	}
	jsonResponse(w, http.StatusOK, value)
}

func (a *App) apiAdminClosetAdd(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	uid, ok := parseID(w, r, "user")
	if !ok {
		a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
		return
	}
	v, ok := a.decodeAPI(w, r)
	if !ok {
		return
	}
	tid, err := integerValue(v, "tid")
	if err != nil {
		validation(w, map[string][]string{"tid": {a.fieldMessage(r, nil, "tid", "integer")}})
		return
	}
	data, err := a.closet.AdminAddActor(r.Context(), actor, uid, tid)
	if a.mapAPIError(w, r, err) {
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"code": 0, "message": "", "data": data})
}

func (a *App) apiAdminClosetRemove(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	uid, ok := parseID(w, r, "user")
	if !ok {
		a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
		return
	}
	v, ok := a.decodeAPI(w, r)
	if !ok {
		return
	}
	tid, err := integerValue(v, "tid")
	if err != nil {
		validation(w, map[string][]string{"tid": {a.fieldMessage(r, nil, "tid", "integer")}})
		return
	}
	data, err := a.closet.AdminRemoveActor(r.Context(), actor, uid, tid)
	if a.mapAPIError(w, r, err) {
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"code": 0, "message": "", "data": data})
}

func (a *App) apiAdminReportsManage(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	value, err := a.reports.ManageActor(r.Context(), actor, a.apiPage(r), r.URL.Query().Get("q"), a.apiPath(r))
	if a.mapAPIError(w, r, err) {
		return
	}
	jsonResponse(w, http.StatusOK, value)
}

func (a *App) apiAdminReportsReview(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	id, ok := parseID(w, r, "report")
	if !ok {
		a.apiFailure(w, r, http.StatusNotFound, "errors.http.msg-404")
		return
	}
	v, ok := a.decodeAPI(w, r)
	if !ok {
		return
	}
	action := v.text("action")
	if action != "delete" && action != "ban" && action != "reject" {
		validation(w, map[string][]string{"action": {a.fieldMessage(r, nil, "action", "in")}})
		return
	}
	result, err := a.reports.ReviewActor(r.Context(), actor, id, action)
	// Frozen ReportController::review answers the ban-outranking case as a
	// business rejection (HTTP 200, code 1, admin.users.operations.no-permission);
	// every other authorization failure keeps its 403 mapping below.
	if errors.Is(err, reports.ErrBanOutranking) {
		a.apiBusiness(w, r, 1, "admin.users.operations.no-permission")
		return
	}
	if a.mapAPIError(w, r, err) {
		return
	}
	message := a.message(r, nil, "general.op-success")
	if result.TextureAlreadyDeleted {
		message = a.message(r, nil, "general.texture-deleted")
	}
	jsonResponse(w, http.StatusOK, map[string]any{"code": 0, "message": message, "data": map[string]int64{"status": result.Status}})
}

func (a *App) apiAdminNotificationSend(w http.ResponseWriter, r *http.Request, actor identity.Actor) {
	v, ok := a.decodeAPI(w, r)
	if !ok {
		return
	}
	receiver := v.text("receiver")
	if receiver != "all" && receiver != "normal" && receiver != "uid" && receiver != "email" {
		validation(w, map[string][]string{"receiver": {a.fieldMessage(r, nil, "receiver", "in")}})
		return
	}
	// Frozen NotificationsController::send validation.
	if receiver == "uid" && v.text("uid") == "" {
		validation(w, map[string][]string{"uid": {a.fieldMessage(r, nil, "uid", "required")}})
		return
	}
	if receiver == "email" && v.text("email") == "" {
		validation(w, map[string][]string{"email": {a.fieldMessage(r, nil, "email", "required")}})
		return
	}
	if receiver == "uid" {
		if _, err := integerValue(v, "uid"); err != nil {
			validation(w, map[string][]string{"uid": {a.fieldMessage(r, nil, "uid", "integer")}})
			return
		}
	}
	if receiver == "email" && v.text("email") != "" {
		if addr, err := mail.ParseAddress(v.text("email")); err != nil || addr.Address != v.text("email") {
			validation(w, map[string][]string{"email": {a.fieldMessage(r, nil, "email", "email")}})
			return
		}
	}
	if raw, present := v["content"]; present && raw != nil {
		if _, ok := raw.(string); !ok {
			validation(w, map[string][]string{"content": {a.fieldMessage(r, nil, "content", "string")}})
			return
		}
	}
	in := notifications.SendInput{
		Receiver: receiver,
		UID:      v.text("uid"),
		Email:    v.text("email"),
		Title:    v.text("title"),
		Content:  v.text("content"),
	}
	if in.Title == "" || len([]rune(in.Title)) > 20 {
		validation(w, map[string][]string{"title": {a.fieldMessage(r, nil, "title", "required")}})
		return
	}
	err := a.notifications.SendActor(r.Context(), actor, in)
	if errors.Is(err, notifications.ErrNoTarget) {
		if receiver == "uid" {
			validation(w, map[string][]string{"uid": {a.fieldMessage(r, nil, "uid", "exists")}})
		} else if receiver == "email" {
			validation(w, map[string][]string{"email": {a.fieldMessage(r, nil, "email", "exists")}})
		} else {
			validation(w, map[string][]string{"receiver": {a.fieldMessage(r, nil, "receiver", "exists")}})
		}
		return
	}
	if a.mapAPIError(w, r, err) {
		return
	}
	http.Redirect(w, r, a.cfg.BaseURL+"/admin", http.StatusFound)
}
