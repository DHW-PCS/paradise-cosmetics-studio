package httpapp

import (
	"blessing-skin-go/internal/identity"
	"bytes"
	"context"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"blessing-skin-go/internal/site"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	renderer "github.com/yuin/goldmark/renderer/html"
)

// The original announcement is administrator-authored GFM with raw HTML.
var announcementMarkdown = goldmark.New(goldmark.WithExtensions(extension.GFM), goldmark.WithRendererOptions(renderer.WithUnsafe()))

func renderAnnouncement(source string) (template.HTML, error) {
	var buffer bytes.Buffer
	err := announcementMarkdown.Convert([]byte(source), &buffer)
	return template.HTML(buffer.String()), err
}
func optionText(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case bool:
		if v {
			return "1"
		}
	}
	return ""
}

type errorView struct {
	Admin                                                       bool
	Language, SiteName, BaseURL, Title, Detail, CurrentLanguage string
	CSS                                                         []string
	Languages                                                   []LanguageLink
}

func (a *App) notFound(w http.ResponseWriter, r *http.Request) {
	a.errorPage(w, r, 404, "errors.http.msg-404")
}
func (a *App) errorPage(w http.ResponseWriter, r *http.Request, status int, messageKey string) {
	locale := a.locale(r, nil)
	messages, err := a.site.Translations(r.Context(), locale, a.cfg.FallbackLocale, a.assets.Messages)
	if err != nil {
		a.serverError(w, r, nil)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), messagesKey{}, messages))
	view := errorView{Language: site.LocaleTag(locale), SiteName: "Blessing Skin", BaseURL: a.cfg.BaseURL, Title: strconv.Itoa(status) + " " + http.StatusText(status)}
	if options, err := a.site.Options(r.Context()); err == nil {
		view.SiteName, _ = site.LocalizedOption(options, "site_name", locale).(string)
	}
	browser, authErr := a.current(r)
	if authErr != nil && !errors.Is(authErr, identity.ErrSession) {
		a.serverError(w, r, nil)
		return
	}
	if browser != nil && browser.User != nil {
		view.Admin = browser.User.Permission >= 1
		a.cookie(w, sessionCookie, browser.Token, time.Time{})
	}
	view.Detail = a.message(r, nil, "errors.exception.detail", ":msg", a.message(r, nil, messageKey))
	for _, language := range languages {
		query := r.URL.Query()
		query.Set("lang", language.ID)
		view.Languages = append(view.Languages, LanguageLink{language.Name, r.URL.Path + "?" + query.Encode()})
		if language.ID == locale {
			view.CurrentLanguage = language.Name
		}
	}
	for _, file := range a.assets.Manifest["spectre"] {
		if strings.HasSuffix(file, ".css") {
			view.CSS = append(view.CSS, a.cfg.BaseURL+"/app/"+file)
		}
	}
	var buffer bytes.Buffer
	if err := a.assets.Templates.ExecuteTemplate(&buffer, "error", view); err != nil {
		a.serverError(w, r, nil)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buffer.Bytes())
}
