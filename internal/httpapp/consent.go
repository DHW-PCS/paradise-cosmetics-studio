// M4-03 slice B: pending-consent handlers and the /user/oauth/manage page.
// Route registration is owned by app.go (Lead); this file owns only the
// handlers so slice C can reuse the same service methods.
package httpapp

import (
	"errors"
	"html/template"
	"net/http"
	"strings"

	"authelia.com/provider/oauth2"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/oauthserver"
	"paradise-cosmetics-studio/internal/site"
)

// consentView is the authorization-page data rendered after ConsentShow
// stages the pending request. Scope descriptions are already translated
// by the handler; the template only lays them out.
type consentView struct {
	ClientName   string
	Scopes       []oauthserver.ScopeDisplay
	AuthToken    string
	RedirectURI  string
	State        string
	CSRF         string
	BaseURL      string
	SiteName     string
	Title        string
	Introduction string
	Permissions  string
	Approve      string
	Cancel       string
	// Shared auth.base head/foot data (F4/F13): the same sources the
	// standard page layout uses (manifest style/meta/app assets, site
	// options, site head/foot hooks), so the consent page loads the
	// same stylesheet/scripts and shows the current locale instead of
	// unstyled bare HTML with a hard-coded lang.
	Language, ThemeColor, Keywords, Description, CDNHost string
	Favicon                                              string
	MetaExtras, HeadLinks, ExtraHead                     template.HTML
	Scripts, ExtraFoot                                   template.HTML
	CustomCSS                                            template.CSS
	CustomJS                                             template.JS
	CSS, MetaJS, AppJS                                   []string
	Globals, Extra                                       map[string]any
}

// consentTemplate restores the frozen authorize view: the auth.base
// login-box layout, translated title/introduction/permissions/buttons and
// translated scope descriptions. The two forms keep the Go pending
// design (hidden auth_token bound to the single Session slot, no fixed
// expiry) and carry the BaseURL prefix so a subpath deployment posts to
// the registered routes.
var consentTemplate = template.Must(template.New("authorize").Parse(`<!DOCTYPE html><html lang="{{.Language}}"><head><meta charset="utf-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no"><meta name="csrf-token" content="{{.CSRF}}"><meta name="theme-color" content="{{.ThemeColor}}"><meta name="keywords" content="{{.Keywords}}"><meta name="description" content="{{.Description}}">{{.MetaExtras}}<link rel="preconnect" href="https://unpkg.com/" crossorigin>{{if .CDNHost}}<link rel="preconnect" href="{{.CDNHost}}" id="cdn-host" crossorigin>{{end}}<script id="pcs-globals" type="application/json">{{.Globals}}</script>{{range .MetaJS}}<script src="{{.}}"></script>{{end}}<link rel="stylesheet" href="https://unpkg.com/@fortawesome/fontawesome-free@5.15.4/css/all.min.css" crossorigin>{{range .CSS}}<link rel="stylesheet" href="{{.}}">{{end}}{{.HeadLinks}}<link rel="shortcut icon" href="{{.Favicon}}"><link rel="icon" type="image/png" href="{{.Favicon}}" sizes="192x192"><link rel="apple-touch-icon" href="{{.Favicon}}" sizes="180x180">{{if .CustomCSS}}<style>{{.CustomCSS}}</style>{{end}}{{.ExtraHead}}<title>{{.Title}} - {{.SiteName}}</title></head><body class="hold-transition login-page"><div class="login-box"><div class="login-logo"><a href="{{.BaseURL}}/">{{.SiteName}}</a></div><div class="card"><div class="card-body login-card-body"><p class="login-box-msg">{{.Introduction}}</p>{{if .Scopes}}<div class="scopes"><p><strong>{{.Permissions}}</strong></p><ul>{{range .Scopes}}<li>{{.Description}}</li>{{end}}</ul></div>{{end}}<div class="d-flex justify-content-between"><form method="post" action="{{.BaseURL}}/oauth/authorize"><input type="hidden" name="_token" value="{{.CSRF}}"><input type="hidden" name="auth_token" value="{{.AuthToken}}"><button type="submit" class="btn btn-success btn-block pl-5 pr-5">{{.Approve}}</button></form><form method="post" action="{{.BaseURL}}/oauth/authorize/deny"><input type="hidden" name="_token" value="{{.CSRF}}"><input type="hidden" name="auth_token" value="{{.AuthToken}}"><button type="submit" class="btn btn-default btn-block pl-5 pr-5">{{.Cancel}}</button></form></div></div></div></div><script id="pcs-extra" type="application/json">{{.Extra}}</script>{{range .AppJS}}<script src="{{.}}"></script>{{end}}{{.Scripts}}{{if .CustomJS}}<script>{{.CustomJS}}</script>{{end}}{{.ExtraFoot}}</body></html>`))

// oauthAuthorizeShow implements GET /oauth/authorize: validate the request,
// stage the single pending slot, and render the authorization page. When a
// valid grant already covers these scopes it redirects straight away.
func (a *App) oauthAuthorizeShow(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if !a.passportVerified(w, r, b) {
		return
	}
	view, err := a.oauth.ConsentShow(r.Context(), r, b)
	if err != nil {
		a.oauthConsentError(w, r, b, err)
		return
	}
	if view.AuthToken == "" {
		http.Redirect(w, r, view.RedirectURI, http.StatusFound)
		return
	}
	scopes := make([]oauthserver.ScopeDisplay, 0, len(view.Scopes))
	for _, scope := range view.Scopes {
		// Frozen twig renders trans(scope.description): a translation key
		// resolves to its text, any other stored text passes through.
		scopes = append(scopes, oauthserver.ScopeDisplay{Name: scope.Name, Description: a.message(r, b, scope.Description)})
	}
	siteName := ""
	options := map[string]any{}
	if a.site != nil {
		var err error
		options, err = a.site.Options(r.Context())
		if err != nil {
			a.serverError(w, r, b)
			return
		}
		siteName, _ = site.LocalizedOption(options, "site_name", a.locale(r, b)).(string)
	}
	locale := a.locale(r, b)
	messages, _ := r.Context().Value(messagesKey{}).(map[string]any)
	frontend, _ := messages["front-end"].(map[string]any)
	extra := map[string]any{"tooManyFails": false, "recaptcha": "", "invisible": false}
	if b.User != nil {
		extra["currentUser"] = b.User
		extra["unverified"] = site.Truth(options["require_verification"]) && !b.User.Verified
	}
	favicon := optionText(options["favicon_url"])
	if !strings.HasPrefix(favicon, "http") {
		favicon = a.cfg.BaseURL + "/" + strings.TrimPrefix(favicon, "/")
	}
	page := consentView{
		ClientName:   view.ClientName,
		Scopes:       scopes,
		AuthToken:    view.AuthToken,
		RedirectURI:  view.RedirectURI,
		State:        view.State,
		CSRF:         b.CSRF,
		BaseURL:      a.cfg.BaseURL,
		SiteName:     siteName,
		Title:        a.message(r, b, "auth.oauth.authorization.title"),
		Introduction: a.message(r, b, "auth.oauth.authorization.introduction", ":name", view.ClientName),
		Permissions:  a.message(r, b, "auth.oauth.authorization.permissions"),
		Approve:      a.message(r, b, "auth.oauth.authorization.button"),
		Cancel:       a.message(r, b, "general.cancel"),
		Language:     site.LocaleTag(locale),
		ThemeColor:   map[string]string{"primary": "#007bff", "secondary": "#6c757d", "success": "#28a745", "warning": "#ffc107", "danger": "#dc3545", "navy": "#001f3f", "olive": "#3d9970", "lime": "#01ff70", "fuchsia": "#f012be", "maroon": "#d81b60", "indigo": "#6610f2", "purple": "#6f42c1", "pink": "#e83e8c", "orange": "#fd7e14", "teal": "#20c997", "cyan": "#17a2b8", "gray": "#6c757d"}[optionText(options["navbar_color"])],
		Keywords:     optionText(options["meta_keywords"]),
		Description:  optionText(options["meta_description"]),
		CDNHost:      optionText(options["cdn_address"]),
		Favicon:      favicon,
		MetaExtras:   template.HTML(stripTags(optionText(options["meta_extras"]), map[string]bool{"meta": true})),
		HeadLinks:    a.site.HeadLinks,
		ExtraHead:    a.site.ExtraHead,
		Scripts:      a.site.Scripts,
		ExtraFoot:    a.site.ExtraFoot,
		CustomCSS:    template.CSS(stripTags(optionText(options["custom_css"]), nil)),
		CustomJS:     template.JS(stripTags(optionText(options["custom_js"]), map[string]bool{"div": true, "span": true, "ul": true, "li": true, "p": true, "a": true, "img": true, "i": true})),
		Globals:      map[string]any{"base_url": a.cfg.BaseURL, "site_name": siteName, "route": "oauth/authorize", "locale": locale, "i18n": frontend, "version": "6.0.2"},
		Extra:        extra,
	}
	for _, file := range a.assets.Manifest["style"] {
		if strings.HasSuffix(file, ".css") {
			page.CSS = append(page.CSS, a.cfg.BaseURL+"/app/"+file)
		}
	}
	for _, file := range a.assets.Manifest["meta"] {
		page.MetaJS = append(page.MetaJS, a.cfg.BaseURL+"/app/"+file)
	}
	for _, file := range a.assets.Manifest["app"] {
		if strings.HasSuffix(file, ".js") {
			page.AppJS = append(page.AppJS, a.cfg.BaseURL+"/app/"+file)
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = consentTemplate.ExecuteTemplate(w, "authorize", page)
}

// oauthAuthorizeApprove implements POST /oauth/authorize.
func (a *App) oauthAuthorizeApprove(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if !a.passportVerified(w, r, b) {
		return
	}
	v, err := decode(r)
	if err != nil {
		validation(w, map[string][]string{"request": {a.fieldMessage(r, b, "request", "json")}})
		return
	}
	if !a.csrf(w, r, b, v) {
		return
	}
	token := v.text("auth_token")
	if token == "" {
		failure(w, 400, a.message(r, b, "auth.check.anonymous"))
		return
	}
	redirect, err := a.oauth.ConsentApprove(r.Context(), b, token)
	if err != nil {
		a.oauthConsentError(w, r, b, err)
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// oauthAuthorizeDeny implements POST /oauth/authorize/deny (deny consumes
// the pending request and redirects back with error=access_denied).
func (a *App) oauthAuthorizeDeny(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if !a.passportVerified(w, r, b) {
		return
	}
	v, err := decode(r)
	if err != nil {
		validation(w, map[string][]string{"request": {a.fieldMessage(r, b, "request", "json")}})
		return
	}
	if !a.csrf(w, r, b, v) {
		return
	}
	token := v.text("auth_token")
	if token == "" {
		failure(w, 400, a.message(r, b, "auth.check.anonymous"))
		return
	}
	redirect, err := a.oauth.ConsentDeny(r.Context(), b, token)
	if err != nil {
		a.oauthConsentError(w, r, b, err)
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// oauthManagePage serves /user/oauth/manage (the existing frontend OAuth
// view). The client/PAT management APIs land in a later slice; this page
// only needs the browser, so it renders through the shared page path.
func (a *App) oauthManagePage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if !a.passportVerified(w, r, b) {
		return
	}
	a.render(w, r, b, "user/oauth/manage", "general.oauth-manage", false)
}

// oauthAuthorizations returns the current user's active grants for the
// manage page data (JSON). It is the only manage-page data read in this
// slice; the Passport client/token management endpoints (slice C) are
// separate.
func (a *App) oauthAuthorizations(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	rows, err := a.oauth.ListAuthorizations(r.Context(), b)
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	jsonResponse(w, 200, rows)
}

// oauthConsentError maps the consent service errors to HTTP responses.
// Pending problems stay distinguishable: staleness asks for a fresh
// authorization page, absence or binding failure is unavailable. Protocol
// errors the engine raises while the approve flow rebuilds the authorize
// request (a scope deleted online, a revoked client, a malformed stored
// field) keep the engine's own RFC 6749 status and description; only
// server-side faults (SQL failures, unavailable storage) keep the service
// error.
func (a *App) oauthConsentError(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, err error) {
	var protocol *oauth2.RFC6749Error
	switch {
	case errors.Is(err, oauthserver.ErrConsentStale):
		failure(w, 409, oauthserver.ErrConsentStale.Error())
	case errors.Is(err, oauthserver.ErrConsent):
		failure(w, 400, oauthserver.ErrConsent.Error())
	case errors.Is(err, identity.ErrSession):
		failure(w, 401, a.message(r, b, "auth.check.anonymous"))
	case errors.As(err, &protocol) && protocol.StatusCode() < 500:
		failure(w, protocol.StatusCode(), protocol.GetDescription())
	default:
		a.serverError(w, r, b)
	}
}
