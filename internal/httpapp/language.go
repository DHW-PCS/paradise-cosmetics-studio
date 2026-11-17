package httpapp

import (
	"context"
	"net/http"
	"strings"
	"time"

	"paradise-cosmetics-studio/internal/identity"
)

type languageInput struct{ value string }

func requestLanguage(r *http.Request) (string, bool) {
	if value, ok := r.Context().Value(languageInput{}).(languageInput); ok {
		return value.value, true
	}
	return strings.Trim(r.URL.Query().Get("lang"), " \t\n\r\x00\x0b"), r.URL.Query().Has("lang")
}

// Body input takes precedence over query input, as in the original Request.
// Persistence happens only after the webpage CSRF check succeeds.
func (a *App) bodyLanguage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, v input) bool {
	raw, present := v["lang"]
	if !present {
		return true
	}
	value, ok := raw.(string)
	if raw != nil && !ok {
		validation(w, map[string][]string{"lang": {a.fieldMessage(r, b, "lang", "string")}})
		return false
	}
	*r = *r.WithContext(context.WithValue(r.Context(), languageInput{}, languageInput{value}))
	locale := a.locale(r, b)
	messages, err := a.site.Translations(r.Context(), locale, a.cfg.FallbackLocale, a.assets.Messages)
	if err != nil {
		a.serverError(w, r, b)
		return false
	}
	*r = *r.WithContext(context.WithValue(r.Context(), messagesKey{}, messages))
	a.cookie(w, "locale", locale, time.Now().Add(2*time.Hour))
	return true
}
