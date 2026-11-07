package httpapp

import (
	"net/http"

	"blessing-skin-go/internal/identity"
)

// oauthLogin serves the external-login entries. The provider set is empty:
// no provider is configured, so every driver is unknown. The module state
// is checked first; an absent module behaves like an absent route, a
// logged-in user on an enabled module follows the guest redirect, and
// everyone else gets the HTML 404. Nothing here creates a user, consumes
// an invitation code, issues a login credential, or reads
// oauth_clients.provider to infer an external identity.
func (a *App) oauthLogin(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	served, err := a.servedModule(r.Context(), "oauth")
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !served {
		a.notFound(w, r)
		return
	}
	if b.User != nil {
		http.Redirect(w, r, a.cfg.BaseURL+"/user", http.StatusFound)
		return
	}
	a.notFound(w, r)
}
