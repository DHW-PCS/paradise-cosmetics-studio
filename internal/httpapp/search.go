package httpapp

import (
	"errors"
	"net/http"

	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/searchstring"
)

func (a *App) searchError(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, err error) {
	if errors.Is(err, searchstring.ErrInvalidQuery) {
		validation(w, map[string][]string{"q": {a.fieldMessage(r, b, "q", "regex")}})
		return
	}
	a.serverError(w, r, b)
}
