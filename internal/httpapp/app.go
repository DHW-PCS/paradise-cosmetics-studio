// Package httpapp owns route registration, browser middleware and input adapters.
package httpapp

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"golang.org/x/text/language"
	"html"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"paradise-cosmetics-studio/internal/account"
	"paradise-cosmetics-studio/internal/admission"
	"paradise-cosmetics-studio/internal/apilimits"
	"paradise-cosmetics-studio/internal/captcha"
	"paradise-cosmetics-studio/internal/closet"
	"paradise-cosmetics-studio/internal/config"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/images"
	"paradise-cosmetics-studio/internal/invitation"
	"paradise-cosmetics-studio/internal/modules"
	"paradise-cosmetics-studio/internal/notifications"
	"paradise-cosmetics-studio/internal/oauthserver"
	"paradise-cosmetics-studio/internal/players"
	"paradise-cosmetics-studio/internal/reports"
	"paradise-cosmetics-studio/internal/routes"
	"paradise-cosmetics-studio/internal/searchstring"
	"paradise-cosmetics-studio/internal/site"
	"paradise-cosmetics-studio/internal/textures"
	"paradise-cosmetics-studio/internal/users"
	"paradise-cosmetics-studio/internal/yggdrasil"
	"paradise-cosmetics-studio/web"
)

const sessionCookie = "pcs_session"
const rememberCookie = "pcs_remember"

type App struct {
	apiLimits     *apilimits.Service
	accounts      *account.Service
	players       *players.Service
	textures      *textures.Service
	closet        *closet.Service
	reports       *reports.Service
	notifications *notifications.Service
	usersAdmin    *users.Service
	modules       *modules.Manager
	invitation    *invitation.Service
	oauth         *oauthserver.Server
	clock         func() time.Time
	images        *images.Service
	captcha       *captcha.Service
	cfg           config.Config
	identity      *identity.Service
	site          *site.Service
	assets        *web.Assets
	basePath      string
	ygg           *yggdrasil.Service
	buildVersion  string
}

// newMailTransport is swappable so an end-to-end test can point the server at a
// loopback SMTP simulator; production keeps account.DefaultTransport.
var newMailTransport account.NewTransportFunc = account.DefaultTransport

func New(c config.Config, id *identity.Service, service *site.Service, oauth *oauthserver.Server, ygg *yggdrasil.Service, buildVersion string) (http.Handler, error) {
	assets, err := web.Load()
	if err != nil {
		return nil, err
	}
	var mail *account.Mail
	if c.Mail.Mailer != "" {
		transport, err := newMailTransport(c.Mail)
		if err != nil {
			return nil, err
		}
		mail, err = account.NewMail(c.AppKey, c.BaseURL, c.FallbackLocale, service, assets.Messages, transport, c.Mail.RetryDelay)
		if err != nil {
			return nil, err
		}
	}
	texturesDir := c.TexturesDir
	if texturesDir == "" {
		texturesDir = "storage/textures"
	}
	accounts := account.New(id.Store, id, service, mail)
	accounts.Modules = service.Modules
	return newWithAccounts(c, id, service, oauth, accounts, mail, ygg, buildVersion)
}

// newWithAccounts lets acceptance tests supply the account service (and thus a
// loopback mail transport) without duplicating the route table.
func newWithAccounts(c config.Config, id *identity.Service, service *site.Service, oauth *oauthserver.Server, accounts *account.Service, mail *account.Mail, ygg *yggdrasil.Service, buildVersion string) (http.Handler, error) {
	assets, err := web.Load()
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(c.BaseURL)
	textureService := textures.New(id.Store, id, service, c.TexturesDir, id.Now)
	playerService := players.New(id.Store, id, service, id.Now).WithTextures(textureService)
	closetService := closet.New(id.Store, id, service, textureService, playerService, id.Now)
	a := &App{cfg: c, identity: id, site: service, assets: assets, basePath: u.Path, accounts: accounts, players: playerService, textures: textureService, closet: closetService, apiLimits: apilimits.New(id.Store), reports: reports.New(id.Store, id, service, textureService, closetService, id.Now), notifications: notifications.New(id.Store, id.Now), usersAdmin: users.New(id.Store, service, id.Now), modules: service.Modules, invitation: invitation.New(id.Store, id.Now), oauth: oauth, clock: id.Now, images: images.New(id.Store, service, textureService, id.Now), captcha: &captcha.Service{Store: id.Store, Identity: id, Client: http.DefaultClient}, ygg: ygg, buildVersion: buildVersion}
	if a.modules != nil && ygg != nil {
		ygg.ModuleLock = a.yggModuleLockFunc()
	}
	if a.modules != nil {
		playerService.ModuleLock = a.yggModuleLockFunc()
	}
	mux := http.NewServeMux()
	register := func(method, path string, fn func(http.ResponseWriter, *http.Request)) {
		mux.HandleFunc(method+" "+u.Path+path, fn)
	}
	register("GET", "/{$}", a.browser(false, false, a.homePage))
	register("GET", route("auth.login"), a.browser(false, false, a.loginPage))
	register("POST", route("auth.login"), a.browser(false, false, a.login))
	register("GET", "/auth/register", a.browser(false, false, a.registerPage))
	register("POST", "/auth/register", a.browser(false, false, a.registerAccount))
	register("GET", "/auth/login/{driver}", a.browser(false, false, a.oauthLogin))
	register("GET", "/auth/login/{driver}/callback", a.browser(false, false, a.oauthLogin))
	register("GET", "/auth/forgot", a.browser(false, false, a.forgotPage))
	register("POST", "/auth/forgot", a.browser(false, false, a.forgotPassword))
	register("GET", "/auth/reset/{uid}", a.browser(false, false, a.resetPage))
	register("POST", "/auth/reset/{uid}", a.browser(false, false, a.resetPassword))
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		register(method, "/auth/captcha", a.browser(false, false, a.captchaImage))
	}
	register("GET", "/auth/bind", a.browser(true, false, a.bindPage))
	register("POST", "/auth/bind", a.browser(true, false, a.bindEmail))
	register("GET", "/auth/verify/{user}", a.browser(false, false, a.verifyPage))
	register("POST", "/auth/verify/{user}", a.browser(false, false, a.verifyEmail))
	register("POST", route("auth.logout"), a.browser(true, false, a.logout))
	register("GET", route("user.home"), a.browser(true, false, a.userPage))
	register("GET", "/skinlib", a.browser(false, false, a.skinlibIndex))
	register("GET", "/skinlib/list", a.browser(false, false, a.skinlibList))
	register("GET", "/skinlib/show/{texture}", a.browser(false, false, a.skinlibShow))
	register("GET", "/skinlib/info/{texture}", a.browser(false, false, a.skinlibInfo))
	register("GET", "/texture/{texture}", a.browser(false, false, a.skinlibInfo))
	register("GET", "/skinlib/upload", a.browser(true, false, a.skinlibUploadPage))
	register("POST", "/texture", a.browser(true, false, a.textureUpload))
	register("GET", route("user.closet.page"), a.browser(true, false, a.closetPage))
	register("GET", route("user.closet.list"), a.browser(true, false, a.closetList))
	register("GET", route("user.closet.ids"), a.browser(true, false, a.closetIDs))
	register("POST", route("user.closet.add"), a.browser(true, false, a.closetAdd))
	register("PUT", "/user/closet/{tid}", a.browser(true, false, a.closetRename))
	register("DELETE", "/user/closet/{tid}", a.browser(true, false, a.closetRemove))
	register("PUT", "/user/player/{player}/textures", a.browser(true, false, a.verifiedTexture(a.playerSetTexture)))
	register("DELETE", "/user/player/{player}/textures", a.browser(true, false, a.verifiedTexture(a.playerClearTexture)))
	register("PUT", "/admin/players/{player}/textures", a.browser(true, true, a.adminPlayerTexture))
	register("PUT", "/texture/{texture}/name", a.browser(true, false, a.verifiedTexture(a.textureRename)))
	register("PUT", "/texture/{texture}/type", a.browser(true, false, a.verifiedTexture(a.textureType)))
	register("PUT", "/texture/{texture}/privacy", a.browser(true, false, a.verifiedTexture(a.texturePrivacy)))
	register("DELETE", "/texture/{texture}", a.browser(true, false, a.verifiedTexture(a.textureDelete)))
	register("POST", "/admin/closet/{user}", a.browser(true, true, a.adminClosetAdd))
	register("DELETE", "/admin/closet/{user}", a.browser(true, true, a.adminClosetRemove))
	register("GET", route("user.player.page"), a.browser(true, false, a.playerPage))
	register("GET", route("user.player.list"), a.browser(true, false, a.playerList))
	register("POST", route("user.player.add"), a.browser(true, false, a.playerAdd))
	register("PUT", "/user/player/{player}/name", a.browser(true, false, a.playerRename))
	register("DELETE", "/user/player/{player}", a.browser(true, false, a.playerDelete))
	register("GET", route("user.score"), a.browser(true, false, a.score))
	register("POST", "/user/sign", a.browser(true, false, a.sign))
	register("GET", "/user/profile", a.browser(true, false, a.profilePage))
	register("POST", "/user/profile", a.browser(true, false, a.profile))
	register("POST", "/user/profile/avatar", a.browser(true, false, a.avatar))
	register("POST", "/user/email-verification", a.browser(true, false, a.sendVerification))
	register("PUT", "/user/dark-mode", a.browser(true, false, a.darkMode))
	register("GET", "/admin", a.browser(true, true, a.adminDashboard))
	register("GET", "/admin/players", a.browser(true, true, a.adminPlayersPage))
	register("GET", route("admin.players.list"), a.browser(true, true, a.adminPlayersList))
	register("GET", "/admin/chart", a.browser(true, true, a.adminChart))
	register("POST", "/admin/notifications/send", a.browser(true, true, a.adminSendNotification))
	register("GET", "/admin/users/list", a.browser(true, true, a.adminUsersList))
	register("GET", "/admin/reports", a.browser(true, true, a.adminReportsPage))
	register("GET", "/admin/reports/list", a.browser(true, true, a.adminReportList))
	register("PUT", "/admin/reports/{report}", a.browser(true, true, a.adminReportReview))
	register("GET", "/user/reports", a.browser(true, false, a.userReportsPage))
	register("GET", "/user/reports/list", a.browser(true, false, a.userReportList))
	register("POST", "/skinlib/report", a.browser(true, false, a.reportSubmit))
	register("GET", "/notifications", a.browser(true, false, a.unreadNotifications))
	register("POST", "/user/notifications/{id}", a.browser(true, false, a.readNotification))
	register("PUT", "/admin/players/{player}/name", a.browser(true, true, a.adminPlayerRename))
	register("PUT", "/admin/players/{player}/owner", a.browser(true, true, a.adminPlayerOwner))
	register("DELETE", "/admin/players/{player}", a.browser(true, true, a.adminPlayerDelete))
	register("GET", "/admin/users", a.browser(true, true, a.adminPage))
	for _, action := range []string{"email", "verification", "nickname", "password", "permission", "score"} {
		register("PUT", "/admin/users/{user}/"+action, a.browser(true, true, a.adminAccount(action)))
	}
	register("DELETE", "/admin/users/{user}", a.browser(true, true, a.adminAccount("delete")))
	register("GET", "/admin/plugins/data", a.browser(true, true, a.pluginsData))
	register("GET", "/admin/plugins/manage", a.browser(true, true, a.adminPluginsPage))
	register("POST", "/admin/plugins/manage", a.browser(true, true, a.pluginsManage))
	register("GET", "/admin/invitation-codes", a.browser(true, true, a.adminInvitationPage))
	register("POST", "/admin/invitation-codes/generate", a.browser(true, true, a.invitationGenerate))
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		register(method, "/admin/plugins/config/{name}", a.browser(true, true, a.pluginConfig))
	}
	register("GET", "/admin/plugins/readme/{name}", a.browser(true, true, a.pluginReadme))
	register("POST", route("passport.token"), a.apiToken(oauth.Token))
	register("GET", "/admin/oauth/scopes", a.browser(true, true, a.oauthScopesList))
	register("POST", "/admin/oauth/scopes", a.browser(true, true, a.oauthScopesCreate))
	register("PUT", "/admin/oauth/scopes/{id}", a.browser(true, true, a.oauthScopesUpdate))
	register("DELETE", "/admin/oauth/scopes/{id}", a.browser(true, true, a.oauthScopesDelete))
	register("GET", "/oauth/authorize", a.browser(true, false, a.oauthAuthorizeShow))
	register("POST", "/oauth/authorize", a.browser(true, false, a.oauthAuthorizeApprove))
	register("DELETE", "/oauth/authorize", a.browser(true, false, a.oauthAuthorizeDeny))
	register("POST", "/oauth/authorize/deny", a.browser(true, false, a.oauthAuthorizeDeny))
	register("POST", "/oauth/token/refresh", a.browser(true, false, a.oauthTokenRefresh))
	register("GET", "/user/oauth/manage", a.browser(true, false, a.oauthManagePage))
	register("GET", "/user/oauth/authorizations", a.browser(true, false, a.oauthAuthorizations))
	register("GET", "/oauth/clients", a.browser(true, false, a.oauthClientsList))
	register("POST", "/oauth/clients", a.browser(true, false, a.oauthClientCreate))
	register("PUT", "/oauth/clients/{client_id}", a.browser(true, false, a.oauthClientUpdate))
	register("DELETE", "/oauth/clients/{client_id}", a.browser(true, false, a.oauthClientDelete))
	register("GET", "/oauth/scopes", a.browser(true, false, a.oauthPassportScopesList))
	register("GET", "/oauth/personal-access-tokens", a.browser(true, false, a.oauthPersonalTokensList))
	register("POST", "/oauth/personal-access-tokens", a.browser(true, false, a.oauthPersonalTokenCreate))
	register("DELETE", "/oauth/personal-access-tokens/{token_id}", a.browser(true, false, a.oauthPersonalTokenDelete))
	register("GET", "/oauth/tokens", a.browser(true, false, a.oauthTokensList))
	register("DELETE", "/oauth/tokens/{token_id}", a.browser(true, false, a.oauthTokenDelete))
	register("GET", "/textures/{hash}", a.browser(false, false, a.hashTexture))
	register("GET", "/csl/textures/{hash}", a.browser(false, false, a.hashTexture))
	register("GET", "/skin/{player}", a.legacySkin)
	register("GET", "/cape/{player}", a.legacyCape)
	register("GET", "/raw/{texture}", a.browser(false, false, a.rawTexture))
	register("GET", "/avatar/player/{name}", a.browser(false, false, a.playerAvatar))
	register("GET", "/avatar/user/{user}", a.browser(false, false, a.userAvatar))
	register("GET", "/avatar/{texture}", a.browser(false, false, a.textureAvatar))
	register("GET", "/avatar/hash/{hash}", a.browser(false, false, a.hashAvatar))
	register("GET", "/preview/{texture}", a.browser(false, false, a.texturePreview))
	register("GET", "/preview/hash/{hash}", a.browser(false, false, a.hashPreview))
	register("GET", "/app/", http.StripPrefix(u.Path, http.FileServerFS(assets.Static)).ServeHTTP)
	register("GET", "/sw.js", a.serviceWorker)
	register("GET", "/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	// Yggdrasil protocol routes (M4-05): every route is served through
	// the module dispatcher; a disabled module answers 404.
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		register(method, "/api/yggdrasil", a.yggHello)
	}
	register("POST", "/api/yggdrasil/authserver/authenticate", a.yggAuthenticate)
	register("POST", "/api/yggdrasil/authserver/refresh", a.yggRefresh)
	register("POST", "/api/yggdrasil/authserver/validate", a.yggValidate)
	register("POST", "/api/yggdrasil/authserver/invalidate", a.yggInvalidate)
	register("POST", "/api/yggdrasil/authserver/signout", a.yggSignout)
	register("POST", "/api/yggdrasil/sessionserver/session/minecraft/join", a.yggJoin)
	register("GET", "/api/yggdrasil/sessionserver/session/minecraft/hasJoined", a.yggHasJoined)
	register("GET", "/api/yggdrasil/sessionserver/session/minecraft/profile/{uuid}", a.yggProfile)
	register("POST", "/api/yggdrasil/api/profiles/minecraft", a.yggSearchMultiple)
	register("GET", "/api/yggdrasil/api/users/profiles/minecraft/{username}", a.yggSearchSingle)
	register("PUT", "/api/yggdrasil/api/user/profile/{uuid}/{type}", a.yggUpload)
	register("DELETE", "/api/yggdrasil/api/user/profile/{uuid}/{type}", a.yggReset)
	register("GET", "/api/yggdrasil/minecraftservices/publickeys", a.yggPublicKeys)
	register("GET", "/admin/yggdrasil-log", a.browser(true, true, a.yggLogPage))
	register("POST", "/admin/plugins/config/yggdrasil-api/generate", a.browser(true, true, a.yggGenerate))
	// Yggdrasil core API (M4-03 slice C2): frozen /api prefix.
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"} {
		register(method, "/api", a.apiRoot)
		register(method, "/api/{$}", a.apiRoot)
	}
	register("GET", "/api/user", a.api(a.apiUser))
	register("GET", "/api/user/notifications", a.api(a.apiNotificationsUnread))
	register("POST", "/api/user/notifications/{id}", a.api(a.apiNotificationRead))
	register("GET", "/api/players", a.api(a.apiPlayersList))
	register("POST", "/api/players", a.api(a.apiPlayersAdd))
	register("DELETE", "/api/players/{player}", a.api(a.apiPlayersDelete))
	register("PUT", "/api/players/{player}/name", a.api(a.apiPlayersRename))
	register("PUT", "/api/players/{player}/textures", a.api(a.apiPlayersSetTextures))
	register("DELETE", "/api/players/{player}/textures", a.api(a.apiPlayersClearTextures))
	register("GET", "/api/closet", a.api(a.apiClosetList))
	register("POST", "/api/closet", a.api(a.apiClosetAdd))
	register("PUT", "/api/closet/{tid}", a.api(a.apiClosetRename))
	register("DELETE", "/api/closet/{tid}", a.api(a.apiClosetRemove))
	register("GET", "/api/admin/users", a.api(a.apiAdminUsersList))
	register("PUT", "/api/admin/users/{user}/email", a.api(a.apiAdminUserAction("email")))
	register("PUT", "/api/admin/users/{user}/verification", a.api(a.apiAdminUserAction("verification")))
	register("PUT", "/api/admin/users/{user}/nickname", a.api(a.apiAdminUserAction("nickname")))
	register("PUT", "/api/admin/users/{user}/password", a.api(a.apiAdminUserAction("password")))
	register("PUT", "/api/admin/users/{user}/score", a.api(a.apiAdminUserAction("score")))
	register("PUT", "/api/admin/users/{user}/permission", a.api(a.apiAdminUserAction("permission")))
	register("DELETE", "/api/admin/users/{user}", a.api(a.apiAdminUserAction("delete")))
	register("GET", "/api/admin/players", a.api(a.apiAdminPlayersList))
	register("PUT", "/api/admin/players/{player}/name", a.api(a.apiAdminPlayerRename))
	register("PUT", "/api/admin/players/{player}/owner", a.api(a.apiAdminPlayerOwner))
	register("PUT", "/api/admin/players/{player}/textures", a.api(a.apiAdminPlayerTextures))
	register("DELETE", "/api/admin/players/{player}", a.api(a.apiAdminPlayersDelete))
	register("GET", "/api/admin/closet/{user}", a.api(a.apiAdminClosetList))
	register("POST", "/api/admin/closet/{user}", a.api(a.apiAdminClosetAdd))
	register("DELETE", "/api/admin/closet/{user}", a.api(a.apiAdminClosetRemove))
	register("GET", "/api/admin/reports", a.api(a.apiAdminReportsManage))
	register("PUT", "/api/admin/reports/{report}", a.api(a.apiAdminReportsReview))
	register("POST", "/api/admin/notifications", a.api(a.apiAdminNotificationSend))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if u.Path != "" && !strings.HasPrefix(r.URL.Path, u.Path+"/") {
			a.notFound(w, r)
			return
		}
		requestPath := strings.TrimPrefix(r.URL.Path, u.Path)
		if name, ok := playerJSONName(requestPath); ok {
			r.SetPathValue("player", name)
			a.browser(false, false, a.playerProfileJSON)(w, r)
			return
		}
		for _, known := range routes.Catalog {
			if matchPath(known.Path, requestPath) {
				jsonResponse(w, http.StatusNotImplemented, map[string]any{"code": 501, "message": a.message(r, nil, "errors.http.msg-500")})
				return
			}
		}
		if strings.HasPrefix(requestPath, "/api/yggdrasil") {
			a.yggNotFound(w)
			return
		}
		a.notFound(w, r)
	})
	return a.apiLocationHeader(mux), nil
}

func route(name string) string {
	for _, r := range routes.Catalog {
		if r.Name == name {
			return r.Path
		}
	}
	panic("unknown named route: " + name)
}
func matchPath(pattern, value string) bool {
	p := strings.Split(pattern, "/")
	v := strings.Split(value, "/")
	if len(p) != len(v) {
		return false
	}
	for i, s := range p {
		if s != v[i] && !(strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")) {
			return false
		}
	}
	return true
}
func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func failure(w http.ResponseWriter, status int, message string) {
	jsonResponse(w, status, map[string]any{"code": status, "message": message})
}
func (a *App) serverError(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	failure(w, 503, a.message(r, b, "errors.http.msg-500"))
}

type messagesKey struct{}

func (a *App) message(r *http.Request, b *identity.BrowserSession, key string, parameters ...string) string {
	messages, _ := r.Context().Value(messagesKey{}).(map[string]any)
	if messages == nil {
		messages = a.assets.Messages[a.locale(r, b)]
	}
	value := lookup(messages, key)
	if value == key {
		value = lookup(a.assets.Messages[a.cfg.FallbackLocale], key)
	}
	if len(parameters) > 0 {
		value = strings.NewReplacer(parameters...).Replace(value)
	}
	return value
}
func (a *App) fieldMessage(r *http.Request, b *identity.BrowserSession, field, rule string, parameters ...string) string {
	attribute := a.message(r, b, "validation.attributes."+field)
	if attribute == "validation.attributes."+field {
		attribute = field
	}
	return a.message(r, b, "validation."+rule, append([]string{":attribute", attribute}, parameters...)...)
}

func (a *App) cookiePath() string {
	if a.basePath == "" {
		return "/"
	}
	return a.basePath + "/"
}
func (a *App) cookie(w http.ResponseWriter, name, value string, expires time.Time) {
	c := &http.Cookie{Name: name, Value: value, Path: a.cookiePath(), Domain: a.cfg.SessionDomain, Secure: a.cfg.SecureCookie, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	if !expires.IsZero() {
		c.Expires = expires
		c.MaxAge = int(time.Until(expires).Seconds())
		if value == "" {
			c.MaxAge = -1
		}
	}
	http.SetCookie(w, c)
}
func (a *App) current(r *http.Request) (*identity.BrowserSession, error) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		b, err := a.identity.Session(r.Context(), c.Value)
		if err == nil {
			return b, nil
		}
		if !errors.Is(err, identity.ErrSession) {
			return nil, err
		}
	}
	if c, err := r.Cookie(rememberCookie); err == nil {
		return a.identity.Recall(r.Context(), c.Value)
	}
	return nil, identity.ErrSession
}
func (a *App) browser(required, admin bool, next func(http.ResponseWriter, *http.Request, *identity.BrowserSession)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := a.current(r)
		if err != nil && !errors.Is(err, identity.ErrSession) {
			a.serverError(w, r, b)
			return
		}
		messages, err := a.site.Translations(r.Context(), a.locale(r, b), a.cfg.FallbackLocale, a.assets.Messages)
		if err != nil {
			a.serverError(w, r, b)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), messagesKey{}, messages))
		if required && (b == nil || b.User == nil) {
			if strings.Contains(r.Header.Get("Accept"), "application/json") {
				failure(w, 401, a.message(r, b, "auth.check.anonymous"))
			} else {
				http.Redirect(w, r, a.cfg.BaseURL+"/auth/login", http.StatusFound)
			}
			return
		}
		if required {
			binding := strings.TrimPrefix(r.URL.Path, a.basePath) == "/auth/bind"
			if b.User.Email == "" && !binding {
				http.Redirect(w, r, a.cfg.BaseURL+"/auth/bind", 302)
				return
			}
			if b.User.Email != "" && binding {
				http.Redirect(w, r, a.cfg.BaseURL+"/user", 302)
				return
			}
		}
		if b != nil && b.User != nil && r.URL.Query().Has("lang") && (r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS") {
			locale := strings.Trim(r.URL.Query().Get("lang"), " \t\n\r\x00\x0b")
			if err = a.persistLocale(r, b, locale); err != nil {
				a.serverError(w, r, b)
				return
			}
		}
		if admin && b.User.Permission < 1 {
			if strings.Contains(r.Header.Get("Accept"), "application/json") {
				failure(w, 403, a.message(r, b, "auth.check.admin"))
			} else {
				a.errorPage(w, r, 403, "errors.http.msg-403")
			}
			return
		}
		if b == nil {
			b, err = a.identity.Guest(r.Context())
			if err != nil {
				a.serverError(w, r, b)
				return
			}
		}
		a.cookie(w, sessionCookie, b.Token, time.Time{})
		w.Header().Set("Cache-Control", "no-store")
		next(w, r, b)
	}
}

func (a *App) csrf(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, v input) bool {
	if !a.bodyLanguage(w, r, b, v) {
		return false
	}
	token := r.Header.Get("X-CSRF-TOKEN")
	if token == "" {
		token = v.text("_token")
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(b.CSRF)) != 1 {
		failure(w, 419, a.message(r, b, "errors.http.csrf-token-mismatch"))
		return false
	}
	if b.User != nil {
		if value, present := requestLanguage(r); present {
			if err := a.persistLocale(r, b, value); err != nil {
				a.serverError(w, r, b)
				return false
			}
		}
	}
	return true
}

// persistLocale saves an authenticated browser's explicit language choice. An
// empty value clears the preference; a value outside the frozen
// config/locales.php allowlist is ignored. This mirrors the fixed upstream
// listener for issue #684 / PR #685 instead of persisting the raw request value.
func (a *App) persistLocale(r *http.Request, b *identity.BrowserSession, raw string) error {
	if raw == "" {
		if err := a.accounts.SetLocale(r.Context(), b, ""); err != nil {
			return err
		}
		b.User.Locale = ""
		return nil
	}
	canonical, ok := canonicalLocale(raw)
	if !ok {
		return nil
	}
	if err := a.accounts.SetLocale(r.Context(), b, canonical); err != nil {
		return err
	}
	b.User.Locale = canonical
	return nil
}
func validation(w http.ResponseWriter, fields map[string][]string) {
	jsonResponse(w, 422, map[string]any{"message": "The given data was invalid.", "errors": fields})
}
func (a *App) login(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if b.User != nil {
		http.Redirect(w, r, a.cfg.BaseURL+"/user", http.StatusFound)
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
	fields := map[string][]string{}
	if v.text("identification") == "" {
		fields["identification"] = []string{a.fieldMessage(r, b, "identification", "required")}
	}
	raw := v.text("password")
	if raw == "" {
		fields["password"] = []string{a.fieldMessage(r, b, "password", "required")}
	} else if utf8.RuneCountInString(raw) < 6 {
		fields["password"] = []string{a.fieldMessage(r, b, "password", "min.string", ":min", "6")}
	} else if utf8.RuneCountInString(raw) > 32 {
		fields["password"] = []string{a.fieldMessage(r, b, "password", "max.string", ":max", "32")}
	}
	keep := v.truth("keep")
	if len(fields) > 0 {
		validation(w, fields)
		return
	}
	fails, err := a.captcha.LoginFailures(r.Context(), clientIP(r))
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if fails > 3 && !a.checkCaptcha(w, r, b, v) {
		return
	}
	result, err := a.identity.Login(r.Context(), v.text("identification"), v.text("password"), keep, b.Token)
	if errors.Is(err, identity.ErrCredentials) || errors.Is(err, identity.ErrStale) {
		key := "auth.validation.password"
		code := 1
		if errors.Is(err, identity.ErrNoAccount) {
			key = "auth.validation.user"
			code = 2
		} else if errors.Is(err, identity.ErrBanned) {
			key = "auth.check.banned"
		}
		data := map[string]any{}
		if code == 1 && !errors.Is(err, identity.ErrBanned) && !errors.Is(err, identity.ErrStale) {
			count, failErr := a.captcha.Failed(r.Context(), clientIP(r))
			if failErr != nil {
				a.serverError(w, r, b)
				return
			}
			data["login_fails"] = count
		}
		jsonResponse(w, 200, map[string]any{"code": code, "message": a.message(r, b, key), "data": data})
		return
	}
	if errors.Is(err, admission.ErrBusy) {
		w.Header().Set("Retry-After", "1")
		failure(w, 503, a.message(r, b, "errors.http.msg-500"))
		return
	}
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if err = a.captcha.Succeeded(r.Context(), clientIP(r)); err != nil {
		a.serverError(w, r, b)
		return
	}
	a.cookie(w, sessionCookie, result.Token, time.Time{})
	if result.Remember != "" {
		a.cookie(w, rememberCookie, result.Remember, time.Now().Add(a.cfg.RememberLifetime))
	} else {
		a.cookie(w, rememberCookie, "", time.Unix(1, 0))
	}
	jsonResponse(w, 200, map[string]any{"code": 0, "message": a.message(r, b, "auth.login.success"), "data": map[string]string{"redirectTo": a.cfg.BaseURL + "/user"}})
}
func (a *App) logout(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	v, err := decode(r)
	if err != nil {
		validation(w, map[string][]string{"request": {a.fieldMessage(r, b, "request", "json")}})
		return
	}
	if !a.csrf(w, r, b, v) {
		return
	}
	if err = a.identity.Logout(r.Context(), b.Token); err != nil {
		a.serverError(w, r, b)
		return
	}
	a.cookie(w, sessionCookie, "", time.Unix(1, 0))
	a.cookie(w, rememberCookie, "", time.Unix(1, 0))
	jsonResponse(w, 200, map[string]any{"code": 0, "message": a.message(r, b, "auth.logout.success")})
}
func (a *App) score(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	value, err := a.site.Score(r.Context(), b.User.UID)
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	jsonResponse(w, 200, value)
}
func (a *App) users(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	page := 1
	var err error
	if raw := r.URL.Query().Get("page"); raw != "" {
		page, err = strconv.Atoi(raw)
	}
	if err != nil || page < 1 {
		validation(w, map[string][]string{"page": {a.fieldMessage(r, b, "page", "min.numeric", ":min", "1")}})
		return
	}
	value, err := a.site.Users(r.Context(), page, r.URL.Query().Get("q"))
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	jsonResponse(w, 200, value)
}
func (a *App) darkMode(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	v, err := decode(r)
	if err != nil {
		validation(w, map[string][]string{"request": {a.fieldMessage(r, b, "request", "json")}})
		return
	}
	if !a.csrf(w, r, b, v) {
		return
	}
	if err = a.site.ToggleDarkMode(r.Context(), b); err != nil {
		if errors.Is(err, identity.ErrSession) {
			failure(w, 401, a.message(r, b, "auth.check.anonymous"))
		} else {
			a.serverError(w, r, b)
		}
		return
	}
	w.WriteHeader(204)
}

type ViewModel struct {
	AvatarWebP, AvatarPNG                                                                                                                              string
	User                                                                                                                                               *identity.User
	Texts                                                                                                                                              map[string]string
	TextHTML                                                                                                                                           map[string]template.HTML
	Home, ProfilePage, Bind, Verify, PlayersPage                                                                                                       bool
	PlayerCount                                                                                                                                        int64
	PlayerNoticeTitle, PlayerNotice                                                                                                                    string
	SkinlibPage, SkinlibShowPage, SkinlibUploadPage, HasUser, ClosetPage                                                                               bool
	ClosetUnverified                                                                                                                                   bool
	ReportsPage, AdminDashboardPage, InvitationCodesPage                                                                                               bool
	AdminSumUsers, AdminSumPlayers, AdminSumTextures, AdminSumStorage                                                                                  int64
	AdminUsageUsers, AdminUsagePlayers, AdminUsageTextures, AdminUsageStorage                                                                          string
	AdminNotifyTitle, AdminNotifyReceiver, AdminNotifyAll, AdminNotifyNormal, AdminNotifyUID, AdminNotifyEmail, AdminNotifySubject, AdminNotifyContent string
	AdminStorageMB, AdminOverview, PlayerManage, AdminSubmit                                                                                           string
	ReportTID, ReportReason, ReportStatus, ReportTime                                                                                                  string
	ReportRows                                                                                                                                         []ReportRow
	ReportPaginator                                                                                                                                    *searchstring.Paginator
	NotificationError, NotificationSent                                                                                                                string
	ShowTitle, UploadTitle, SkinlibClosetLink, SkinlibUploadLink, SkinlibLogin, SkinlibLabel                                                           string
	FormError, FormIntroduction, FormButton                                                                                                            string
	Favicon, ThemeColor, Keywords, Description, CDNHost                                                                                                string
	MetaExtras, HeadLinks, ExtraHead, ExtraFoot, Scripts                                                                                               template.HTML
	CustomCSS                                                                                                                                          template.CSS
	CustomJS                                                                                                                                           template.JS
	SiteDescription, HomePicture, Skinlib, LoginLabel, RegisterLabel                                                                                   string
	FixedBackground, TransparentNavbar, HideIntroduction                                                                                               bool
	Features                                                                                                                                           []Feature
	HomeCSS, HomeJS                                                                                                                                    []string
	NavbarColor, NavbarMode, SidebarColor                                                                                                              string
	NotificationsJSON                                                                                                                                  string
	NoUnread                                                                                                                                           string
	AnnouncementTitle, ScoreTitle, ScoreStorage, ScorePlayer, ScoreCloset, Close                                                                       string
	Announcement, ScoreIntroduction                                                                                                                    template.HTML
	MenuGroups                                                                                                                                         []MenuGroup
	Invitation                                                                                                                                         InvitationView
	YggdrasilConfigPage, YggdrasilLogPage, ReadmePage                                                                                                  bool
	YggConfig                                                                                                                                          YggConfigView
	YggLog                                                                                                                                             YggLogView
	YggDnd                                                                                                                                             *YggDndView
	YggReadme                                                                                                                                          YggReadmeView
	Profile, Reports                                                                                                                                   string
	AdminPage                                                                                                                                          bool
	BaseURL, Locale, Language, SiteName, Title, CSRF, UserCenter, AdminPanel, Users, Logout, Nickname, Version                                         string
	Login, Dark, Admin                                                                                                                                 bool
	CSS, MetaJS, AppJS                                                                                                                                 []string
	Globals, Extra                                                                                                                                     map[string]any
	LoginNotice, RegisterLink, CurrentLanguage                                                                                                         string
	Languages                                                                                                                                          []LanguageLink
	CopyrightStyle                                                                                                                                     int64
	CustomCopyright                                                                                                                                    template.HTML
}

type LanguageLink struct{ Name, URL string }

// InvitationView carries the frozen InvitationCodes::codes twig contract for
// the admin two-column page.
type InvitationView struct {
	Title, CodeLabel, FreeTitle, FreeEmpty, UsedTitle, UsedEmpty string
	AmountLabel, AmountPlaceholder, GenerateTitle                string
	GeneratedAtLabel, UserLabel, UsedAtLabel                     string
	Error                                                        string
	Free, Used                                                   []InvitationRow
}

// InvitationRow mirrors one admin list entry with the displayed time strings.
type InvitationRow struct {
	Code, GeneratedAt, UsedBy, UsedAt string
}

// YggReadmeView mirrors the frozen admin.plugin.readme twig view: the card
// header is the plugin readme label, the body is GFM-converted HTML and the
// footer carries the back button.
type YggReadmeView struct {
	Title   string
	Content template.HTML
	Back    string
}

type ReportRow struct {
	TID      int64
	Reason   string
	Status   string
	ReportAt string
}

// Names and ordering come from the frozen config/locales.php.
var languages = []struct{ ID, Name string }{{"zh_CN", "中文 (简体)"}, {"zh_TW", "中文 (正體)"}, {"en", "English"}, {"es_ES", "Español"}, {"ru_RU", "Русский язык"}}

// Aliases come from the frozen config/locales.php.
var localeAliases = map[string]string{"zh_HANS_CN": "zh_CN", "en_US": "en", "ru": "ru_RU"}

// canonicalLocale accepts only the locales enabled by config/locales.php and
// resolves an alias to its real key. Anything else is neither persisted nor
// applied (issue #684, upstream PR #685).
func canonicalLocale(value string) (string, bool) {
	value = strings.Trim(value, " \t\n\r\x00\x0b")
	if alias, ok := localeAliases[value]; ok {
		value = alias
	}
	for _, configured := range languages {
		if value == configured.ID {
			return value, true
		}
	}
	return "", false
}

func lookup(table map[string]any, key string) string {
	parts := strings.Split(key, ".")
	var value any = table
	for _, part := range parts {
		m, ok := value.(map[string]any)
		if !ok {
			return key
		}
		value = m[part]
	}
	s, ok := value.(string)
	if !ok {
		return key
	}
	return s
}
func (a *App) locale(r *http.Request, b *identity.BrowserSession) string {
	selected, explicit := requestLanguage(r)
	if !explicit && b != nil && b.User != nil && b.User.Locale != "" {
		if canonical, ok := canonicalLocale(b.User.Locale); ok {
			return canonical
		}
	}
	if selected == "" {
		if cookie, err := r.Cookie("locale"); err == nil {
			selected = cookie.Value
		}
	}
	if selected == "" {
		tags, _, _ := language.ParseAcceptLanguage(r.Header.Get("Accept-Language"))
		if len(tags) > 0 {
			selected = strings.ReplaceAll(tags[0].String(), "-", "_")
			if selected == "zh_Hans_CN" {
				selected = "zh_HANS_CN"
			}
		}
	}
	if canonical, ok := canonicalLocale(selected); ok {
		return canonical
	}
	return a.cfg.FallbackLocale
}

func (a *App) render(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, routeName, titleKey string, login bool) {
	a.renderPage(w, r, b, routeName, titleKey, login, false)
}

// renderPage renders either the standard layout or a literal page title (the
// frozen skinlib show page uses the texture name as its title).
func (a *App) renderPage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, routeName, title string, login bool, literal bool) {
	options, err := a.site.Options(r.Context())
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	locale := a.locale(r, b)
	messages := r.Context().Value(messagesKey{}).(map[string]any)
	t := func(key string) string {
		result := lookup(messages, key)
		if result == key {
			result = lookup(a.assets.Messages[a.cfg.FallbackLocale], key)
		}
		return result
	}
	name, _ := site.LocalizedOption(options, "site_name", locale).(string)
	extra := map[string]any{"tooManyFails": false, "recaptcha": "", "invisible": false}
	if b.User != nil {
		extra["currentUser"] = b.User
		extra["unverified"] = site.Truth(options["require_verification"]) && !b.User.Verified
	}
	frontend, _ := messages["front-end"].(map[string]any)
	globals := map[string]any{"base_url": a.cfg.BaseURL, "site_name": name, "route": routeName, "locale": locale, "i18n": frontend, "version": "6.0.2"}
	view := ViewModel{BaseURL: a.cfg.BaseURL, Locale: locale, Language: site.LocaleTag(locale), SiteName: name, Title: title, Version: a.buildVersion, CSRF: b.CSRF, UserCenter: t("general.user-center"), AdminPanel: t("general.admin-panel"), Users: t("general.user-manage"), Logout: t("general.logout"), Login: login, Globals: globals, Extra: extra}
	if !literal {
		view.Title = t(title)
	}
	view.LoginNotice = t("auth.login.message")
	view.RegisterLink = t("auth.register-link")
	if err = a.populateView(r, b, routeName, options, t, &view); err != nil {
		a.serverError(w, r, b)
		return
	}

	for _, language := range languages {
		query := r.URL.Query()
		query.Set("lang", language.ID)
		view.Languages = append(view.Languages, LanguageLink{language.Name, r.URL.Path + "?" + query.Encode()})
		if language.ID == locale {
			view.CurrentLanguage = language.Name
		}
	}
	view.CopyrightStyle = site.Number(site.LocalizedOption(options, "copyright_prefer", locale))
	copyright, _ := site.LocalizedOption(options, "copyright_text", locale).(string)
	siteURL, _ := options["site_url"].(string)
	// copyright_text is administrator-authored HTML in the original contract.
	view.CustomCopyright = template.HTML(strings.NewReplacer("{site_name}", name, "{site_url}", siteURL).Replace(copyright))
	if b.User != nil {
		view.Nickname = b.User.Nickname
		view.Dark = b.User.DarkMode
		view.Admin = b.User.Permission >= 1
		notifications, err := a.site.UnreadNotifications(r.Context(), b.User.UID)
		if err != nil {
			a.serverError(w, r, b)
			return
		}
		encoded, err := json.Marshal(notifications)
		if err != nil {
			a.serverError(w, r, b)
			return
		}
		view.NotificationsJSON = string(encoded)
		view.NoUnread = t("user.no-unread")
	}
	if routeName == "user" {
		announcement, _ := site.LocalizedOption(options, "announcement", locale).(string)
		view.Announcement, err = renderAnnouncement(announcement)
		if err != nil {
			a.serverError(w, r, b)
			return
		}
		view.AnnouncementTitle = t("user.announcement")
		view.ScoreTitle = t("user.score-intro.title")
		view.Close = t("general.close")
		scoreRange, _ := options["sign_score"].(string)
		bounds := strings.Split(scoreRange, ",")
		if len(bounds) != 2 {
			a.serverError(w, r, b)
			return
		}
		returned := "user.score-intro.no-return-score"
		if site.Truth(options["return_score"]) {
			returned = "user.score-intro.will-return-score"
		}
		intro := strings.NewReplacer(":initial_score", optionText(options["user_initial_score"]), ":score-from", bounds[0], ":score-to", bounds[1], ":return-score", t(returned)).Replace(t("user.score-intro.introduction"))
		view.ScoreIntroduction = template.HTML(strings.ReplaceAll(html.EscapeString(intro), "\n", "<br />\n"))
		view.ScoreStorage = strings.ReplaceAll(t("user.score-intro.rates.storage"), ":score", optionText(options["score_per_storage"]))
		view.ScorePlayer = strings.ReplaceAll(t("user.score-intro.rates.player"), ":score", optionText(options["score_per_player"]))
		view.ScoreCloset = strings.ReplaceAll(t("user.score-intro.rates.closet"), ":score", optionText(options["score_per_closet_item"]))
	}
	view.NavbarColor, _ = options["navbar_color"].(string)
	view.NavbarMode = "dark"
	switch view.NavbarColor {
	case "light", "warning", "white", "orange":
		view.NavbarMode = "light"
	}
	view.SidebarColor, _ = options["sidebar_color"].(string)
	if view.Dark {
		view.SidebarColor = strings.ReplaceAll(view.SidebarColor, "light", "dark")
	}
	invitationItems := []MenuItem{}
	if _, enabled, err := a.invitationEnabled(r.Context(), locale); err == nil && enabled {
		invitationItems = append(invitationItems, MenuItem{Title: modules.Message("InvitationCodes::general.code", locale), URL: a.cfg.BaseURL + "/admin/invitation-codes", Icon: "fa-inbox", Active: routeName == "admin/invitation-codes"})
	} else if err != nil {
		a.serverError(w, r, b)
		return
	}
	// The Yggdrasil log entry follows the verbose switch; hiding the
	// entry never unregisters the route.
	if a.cfg.YggVerboseLog {
		served, err := a.servedModule(r.Context(), yggdrasilModule)
		if err != nil {
			a.serverError(w, r, b)
			return
		}
		if served {
			invitationItems = append(invitationItems, MenuItem{Title: modules.Message("Yggdrasil::log.title", locale), URL: a.cfg.BaseURL + "/admin/yggdrasil-log", Icon: "fa-history", Active: routeName == "admin/yggdrasil-log"})
		}
	}
	view.MenuGroups = sidebar(a.cfg.BaseURL, routeName, view.Admin, t, invitationItems)
	view.Profile = t("general.profile")
	view.Reports = t("general.report-manage")
	view.AdminPage = strings.HasPrefix(routeName, "admin")
	for _, file := range a.assets.Manifest["style"] {
		if strings.HasSuffix(file, ".css") {
			view.CSS = append(view.CSS, a.cfg.BaseURL+"/app/"+file)
		}
	}
	for _, file := range a.assets.Manifest["meta"] {
		view.MetaJS = append(view.MetaJS, a.cfg.BaseURL+"/app/"+file)
	}
	for _, file := range a.assets.Manifest["app"] {
		if strings.HasSuffix(file, ".js") {
			view.AppJS = append(view.AppJS, a.cfg.BaseURL+"/app/"+file)
		}
	}
	templateName := "page"
	if view.SkinlibPage {
		templateName = "skinlib"
	}
	var buffer bytes.Buffer
	if err = a.assets.Templates.ExecuteTemplate(&buffer, templateName, view); err != nil {
		a.serverError(w, r, b)
		return
	}
	a.cookie(w, "locale", locale, time.Now().Add(2*time.Hour))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buffer.Bytes())
}
func (a *App) loginPage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	if b.User != nil {
		http.Redirect(w, r, a.cfg.BaseURL+"/user", 302)
		return
	}
	a.render(w, r, b, "auth/login", "auth.login.title", true)
}
func (a *App) userPage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.render(w, r, b, "user", "general.dashboard", false)
}
func (a *App) adminPage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	a.render(w, r, b, "admin/users", "general.user-manage", false)
}
func (a *App) serviceWorker(w http.ResponseWriter, r *http.Request) {
	for _, file := range a.assets.Manifest["sw"] {
		if path.Ext(file) == ".js" {
			w.Header().Set("Cache-Control", "no-cache")
			http.ServeFileFS(w, r, a.assets.Static, "app/"+file)
			return
		}
	}
	a.notFound(w, r)
}

// playerJSONName matches the frozen /{player}.json and /csl/{player}.json
// routes, which net/http ServeMux cannot express as wildcard suffixes.
func playerJSONName(requestPath string) (string, bool) {
	value := strings.TrimPrefix(requestPath, "/csl")
	if !strings.HasSuffix(value, ".json") || strings.Count(value, "/") != 1 {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(value, "/"), ".json"), true
}
