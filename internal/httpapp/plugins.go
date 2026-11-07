package httpapp

import (
	"errors"
	"net/http"
	"strings"

	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/modules"
)

// The plugin routes live in the frozen admin group: GET /data lists the
// installed modules with their true enable facts, POST /manage runs the
// enable/disable/delete module-state transaction, and config/readme are the
// core dispatch contacts that each module owner fills with its own handler.
func (a *App) adminPluginsPage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.render(w, r, b, "admin/plugins/manage", "general.plugin-manage", false)
}

func (a *App) pluginsData(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	data, err := a.pluginList(r, b)
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	jsonResponse(w, 200, data)
}

// pluginList resolves the installed module facts of one consistent statement
// and centers the request locale for the frozen manifest translations.
func (a *App) pluginList(r *http.Request, b *identity.BrowserSession) ([]modules.PluginData, error) {
	state, err := a.modules.RequestState(r.Context())
	if err != nil {
		return nil, err
	}
	return a.modules.Installed(r.Context(), a.locale(r, b), state), nil
}

// pluginsManage keeps the original code/message shapes. Unknown and uninstalled
// module names stay plugin not-found exactly like the original manage dispatch.
func (a *App) pluginsManage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	v, err := decode(r)
	if err != nil {
		validation(w, map[string][]string{"request": {a.fieldMessage(r, b, "request", "json")}})
		return
	}
	if !a.csrf(w, r, b, v) {
		return
	}
	name := v.text("name")
	title, known, err := a.moduleTitle(r, b, name)
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !known {
		// The original controller looks the plugin up before any action.
		jsonResponse(w, 200, map[string]any{"code": 1, "message": a.message(r, b, "admin.plugins.operations.not-found")})
		return
	}
	switch v.text("action") {
	case "enable":
		err := a.modules.Enable(r.Context(), b, name)
		switch {
		case err == nil:
			jsonResponse(w, 200, map[string]any{"code": 0, "message": strings.ReplaceAll(a.message(r, b, "admin.plugins.operations.enabled"), ":plugin", title)})
		case isModuleRefused(err):
			// The original json(message,1,compact('reason')) carries the
			// translated reasons as an array; the frozen modal maps the list.
			jsonResponse(w, 200, map[string]any{"code": 1, "message": a.message(r, b, "admin.plugins.operations.unsatisfied.notice"), "data": map[string]any{"reason": modules.Reasons(err)}})
		case isModuleMissing(err):
			jsonResponse(w, 200, map[string]any{"code": 1, "message": a.message(r, b, "admin.plugins.operations.not-found")})
		case isModuleAccess(err):
			failure(w, 401, a.message(r, b, "auth.check.anonymous"))
		case errors.Is(err, modules.ErrForbidden):
			failure(w, 403, a.message(r, b, "auth.check.admin"))
		default:
			a.serverError(w, r, b)
		}
	case "disable":
		err := a.modules.Disable(r.Context(), b, name)
		switch {
		case err == nil:
			jsonResponse(w, 200, map[string]any{"code": 0, "message": strings.ReplaceAll(a.message(r, b, "admin.plugins.operations.disabled"), ":plugin", title)})
		case isModuleMissing(err):
			jsonResponse(w, 200, map[string]any{"code": 1, "message": a.message(r, b, "admin.plugins.operations.not-found")})
		case isModuleAccess(err):
			failure(w, 401, a.message(r, b, "auth.check.anonymous"))
		case errors.Is(err, modules.ErrForbidden):
			failure(w, 403, a.message(r, b, "auth.check.admin"))
		default:
			a.serverError(w, r, b)
		}
	case "delete":
		err := a.modules.Uninstall(r.Context(), b, name)
		switch {
		case err == nil:
			jsonResponse(w, 200, map[string]any{"code": 0, "message": a.message(r, b, "admin.plugins.operations.deleted")})
		case isModuleMissing(err):
			jsonResponse(w, 200, map[string]any{"code": 1, "message": a.message(r, b, "admin.plugins.operations.not-found")})
		case isModuleAccess(err):
			failure(w, 401, a.message(r, b, "auth.check.anonymous"))
		case errors.Is(err, modules.ErrForbidden):
			failure(w, 403, a.message(r, b, "auth.check.admin"))
		default:
			a.serverError(w, r, b)
		}
	default:
		jsonResponse(w, 200, map[string]any{"code": 1, "message": a.message(r, b, "admin.invalid-action")})
	}
}

// isModuleMissing covers unknown and unregistered module names: both behave
// exactly like the original lookup miss.
func isModuleMissing(err error) bool {
	return errors.Is(err, modules.ErrNotFound) || errors.Is(err, modules.ErrUnknownModule)
}

func isModuleAccess(err error) bool {
	return errors.Is(err, identity.ErrSession) || errors.Is(err, identity.ErrStale)
}

func isModuleRefused(err error) bool {
	_, ok := modules.AsNotReady(err)
	return ok
}

// moduleTitle resolves the frozen translated title for the action messages.
func (a *App) moduleTitle(r *http.Request, b *identity.BrowserSession, name string) (string, bool, error) {
	state, err := a.modules.RequestState(r.Context())
	if err != nil {
		return "", false, err
	}
	for _, meta := range a.modules.Installed(r.Context(), a.locale(r, b), state) {
		if meta.Name == name {
			return meta.Title, true, nil
		}
	}
	return "", false, nil
}

// The config dispatch keeps the original abort message for modules
// without a config surface; the Yggdrasil module owner serves its own
// config page and save roundtrip.
func (a *App) pluginConfig(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if r.PathValue("name") == yggdrasilModule {
		a.yggConfig(w, r, b)
		return
	}
	a.errorPage(w, r, http.StatusNotFound, "admin.plugins.operations.no-config-notice")
}

func (a *App) pluginReadme(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if r.PathValue("name") == yggdrasilModule {
		a.yggReadme(w, r, b)
		return
	}
	a.errorPage(w, r, http.StatusNotFound, "admin.plugins.operations.no-readme-notice")
}
