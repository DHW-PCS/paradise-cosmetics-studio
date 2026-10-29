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

	"blessing-skin-go/internal/admission"
	"blessing-skin-go/internal/config"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/oauthserver"
	"blessing-skin-go/internal/routes"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/web"
)

const sessionCookie = "bs_go_session"
const rememberCookie = "bs_go_remember"

type App struct {
	cfg      config.Config
	identity *identity.Service
	site     *site.Service
	assets   *web.Assets
	basePath string
}

func New(c config.Config, id *identity.Service, service *site.Service, oauth *oauthserver.Server) (http.Handler, error) {
	assets, err := web.Load()
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(c.BaseURL)
	a := &App{c, id, service, assets, u.Path}
	mux := http.NewServeMux()
	register := func(method, path string, fn func(http.ResponseWriter, *http.Request)) {
		mux.HandleFunc(method+" "+u.Path+path, fn)
	}
	register("GET", "/{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, c.BaseURL+"/user", http.StatusFound) })
	register("GET", route("auth.login"), a.browser(false, false, a.loginPage))
	register("POST", route("auth.login"), a.browser(false, false, a.login))
	register("POST", route("auth.logout"), a.browser(true, false, a.logout))
	register("GET", route("user.home"), a.browser(true, false, a.userPage))
	register("GET", route("user.score"), a.browser(true, false, a.score))
	register("PUT", "/user/dark-mode", a.browser(true, false, a.darkMode))
	register("GET", "/admin", a.browser(true, true, func(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
		http.Redirect(w, r, c.BaseURL+"/admin/users", http.StatusFound)
	}))
	register("GET", "/admin/users", a.browser(true, true, a.adminPage))
	register("GET", route("admin.users.list"), a.browser(true, true, a.users))
	register("POST", route("passport.token"), oauth.Token)
	register("GET", "/app/", http.StripPrefix(u.Path, http.FileServerFS(assets.Static)).ServeHTTP)
	register("GET", "/sw.js", a.serviceWorker)
	register("GET", "/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if u.Path != "" && !strings.HasPrefix(r.URL.Path, u.Path+"/") {
			a.notFound(w, r)
			return
		}
		requestPath := strings.TrimPrefix(r.URL.Path, u.Path)
		for _, known := range routes.Catalog {
			if matchPath(known.Path, requestPath) {
				jsonResponse(w, http.StatusNotImplemented, map[string]any{"code": 501, "message": a.message(r, nil, "errors.http.msg-500")})
				return
			}
		}
		if strings.HasPrefix(requestPath, "/api/yggdrasil") {
			jsonResponse(w, 501, map[string]string{"error": "UnsupportedOperationException", "errorMessage": a.message(r, nil, "errors.http.msg-500")})
			return
		}
		a.notFound(w, r)
	})
	return mux, nil
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
	token := r.Header.Get("X-CSRF-TOKEN")
	if token == "" {
		token = v.text("_token")
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(b.CSRF)) != 1 {
		failure(w, 419, a.message(r, b, "errors.http.csrf-token-mismatch"))
		return false
	}
	return true
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
		jsonResponse(w, 200, map[string]any{"code": code, "message": a.message(r, b, key), "data": map[string]any{}})
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
	NavbarColor, NavbarMode, SidebarColor                                                             string
	NotificationsJSON                                                                                 string
	NoUnread                                                                                          string
	AnnouncementTitle, ScoreTitle, ScoreStorage, ScorePlayer, ScoreCloset, Close                      string
	Announcement, ScoreIntroduction                                                                   template.HTML
	MenuGroups                                                                                        []MenuGroup
	Profile, Reports                                                                                  string
	AdminPage                                                                                         bool
	BaseURL, Locale, Language, SiteName, Title, CSRF, UserCenter, AdminPanel, Users, Logout, Nickname string
	Login, Dark, Admin                                                                                bool
	CSS, MetaJS, AppJS                                                                                []string
	Globals, Extra                                                                                    map[string]any
	LoginNotice, RegisterLink, CurrentLanguage                                                        string
	Languages                                                                                         []LanguageLink
	CopyrightStyle                                                                                    int64
	CustomCopyright                                                                                   template.HTML
}

type LanguageLink struct{ Name, URL string }

// Names and ordering come from the frozen config/locales.php.
var languages = []struct{ ID, Name string }{{"zh_CN", "中文 (简体)"}, {"zh_TW", "中文 (正體)"}, {"en", "English"}, {"es_ES", "Español"}, {"ru_RU", "Русский язык"}}

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
func (a *App) locale(r *http.Request, _ *identity.BrowserSession) string {
	selected := r.URL.Query().Get("lang")
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
	switch selected {
	case "zh_HANS_CN":
		selected = "zh_CN"
	case "en_US":
		selected = "en"
	case "ru":
		selected = "ru_RU"
	}
	for _, configured := range languages {
		if selected == configured.ID {
			return selected
		}
	}
	return a.cfg.FallbackLocale
}

func (a *App) render(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, routeName, titleKey string, login bool) {
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
	view := ViewModel{BaseURL: a.cfg.BaseURL, Locale: locale, Language: site.LocaleTag(locale), SiteName: name, Title: t(titleKey), CSRF: b.CSRF, UserCenter: t("general.user-center"), AdminPanel: t("general.admin-panel"), Users: t("general.user-manage"), Logout: t("general.logout"), Login: login, Globals: globals, Extra: extra}
	view.LoginNotice = t("auth.login.message")
	view.RegisterLink = t("auth.register-link")
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
	view.MenuGroups = sidebar(a.cfg.BaseURL, routeName, view.Admin, t)
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
	var buffer bytes.Buffer
	if err = a.assets.Templates.ExecuteTemplate(&buffer, "page", view); err != nil {
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
