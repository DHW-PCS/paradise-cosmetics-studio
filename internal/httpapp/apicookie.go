// M4-03 slice B: first-party API cookie (POST /oauth/token/refresh) and
// the Bearer-vs-cookie precedence helpers. The cookie secret is an
// independent random value bound to one browser session row; it is never
// an OAuth bearer token.
package httpapp

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"paradise-cosmetics-studio/internal/identity"
)

// apiCookieName is the Go first-party API cookie. Legacy PHP cookies
// (including laravel_token) are never read here: their values fail the
// Go session lookup and stay invalidated.
const apiCookieName = "pcs_api"

// oauthTokenRefresh implements POST /oauth/token/refresh: rotate the API
// cookie secret bound to the current browser session. The rotation is an
// atomic digest replace under the users/version/session locks, so the old
// secret stops working the moment this response commits.
func (a *App) oauthTokenRefresh(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	v, err := decode(r)
	if err != nil {
		validation(w, map[string][]string{"request": {a.fieldMessage(r, b, "request", "json")}})
		return
	}
	if !a.csrf(w, r, b, v) {
		return
	}
	secret, err := a.identity.IssueAPI(r.Context(), b.Token)
	if err != nil {
		if errors.Is(err, identity.ErrSession) {
			failure(w, 401, a.message(r, b, "auth.check.anonymous"))
			return
		}
		a.serverError(w, r, b)
		return
	}
	a.cookie(w, apiCookieName, secret, b.Expires)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("Refreshed."))
}

// ResolveAPICookie validates the first-party API cookie against its bound
// session and CSRF (including on GET). Callers must apply the explicit
// Bearer precedence: when an Authorization header is present, the bearer
// path owns the request and this helper is never consulted.
func (a *App) ResolveAPICookie(r *http.Request) (*identity.BrowserSession, error) {
	c, err := r.Cookie(apiCookieName)
	if err != nil {
		return nil, identity.ErrSession
	}
	csrf := r.Header.Get("X-CSRF-TOKEN")
	if csrf == "" {
		csrf = r.FormValue("_token")
	}
	return a.identity.ValidateAPI(r.Context(), c.Value, csrf)
}

// HasBearer reports whether the request carries an explicit Authorization
// credential. API handlers must attempt the bearer path whenever this is
// true and must not fall back to the API cookie on bearer failure.
func HasBearer(r *http.Request) bool {
	header := r.Header.Get("Authorization")
	return header != "" && strings.HasPrefix(strings.TrimSpace(header), "Bearer ") && strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(header), "Bearer ")) != ""
}

// bearerValue returns the raw bearer token, or "" when absent.
func bearerValue(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
}

// apiCSRFMatches compares a submitted CSRF token with the session CSRF in
// constant time for the cookie auth path.
func apiCSRFMatches(submitted, stored string) bool {
	return subtle.ConstantTimeCompare([]byte(submitted), []byte(stored)) == 1
}
