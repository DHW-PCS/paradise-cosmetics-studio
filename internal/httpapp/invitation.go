package httpapp

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/invitation"
	"blessing-skin-go/internal/modules"
	"net/http"
)

// servedModule reports whether the module is registered and enabled on one
// consistent statement. Unregistered or disabled modules behave like absent
// routes; nothing returns a fake success.
func (a *App) servedModule(ctx context.Context, name string) (bool, error) {
	state, err := a.modules.RequestState(ctx)
	if err != nil {
		return false, err
	}
	return state.HasInstalled(name) && state.HasEnabled(name), nil
}

// adminInvitationPage serves the frozen two-list codes page. Route, menu and
// page all un-register with the module state.
func (a *App) adminInvitationPage(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	served, err := a.servedModule(r.Context(), "invitation-codes")
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !served {
		a.notFound(w, r)
		return
	}
	a.render(w, r, b, "admin/invitation-codes", "", false)
}

// invitationGenerate keeps the original form roundtrip: POST amount, the
// first validation error returns to the page, and success redirects back.
func (a *App) invitationGenerate(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession) {
	served, err := a.servedModule(r.Context(), "invitation-codes")
	if err != nil {
		a.serverError(w, r, b)
		return
	}
	if !served {
		a.notFound(w, r)
		return
	}
	v, ok := a.body(w, r, b)
	if !ok {
		return
	}
	raw := v.text("amount")
	fields := map[string][]string{}
	switch {
	case raw == "":
		fields["amount"] = []string{a.fieldMessage(r, b, "amount", "required")}
	default:
		amount, parseErr := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		switch {
		case parseErr != nil:
			fields["amount"] = []string{a.fieldMessage(r, b, "amount", "integer")}
		case amount < 1:
			fields["amount"] = []string{a.fieldMessage(r, b, "amount", "min.numeric", ":min", "1")}
		default:
			if err := a.invitation.Generate(r.Context(), a.invitation.Store, amount); err != nil {
				if errors.Is(err, invitation.ErrGeneration) {
					a.serverError(w, r, b)
					return
				}
				a.serverError(w, r, b)
				return
			}
			http.Redirect(w, r, a.cfg.BaseURL+"/admin/invitation-codes", http.StatusFound)
			return
		}
	}
	first := ""
	for _, messages := range fields {
		first = messages[0]
		break
	}
	if err := a.putFormError(r.Context(), b, invitationForm, first); err != nil {
		a.serverError(w, r, b)
		return
	}
	// The frozen form returns the browser to the codes page itself.
	http.Redirect(w, r, a.cfg.BaseURL+"/admin/invitation-codes", http.StatusFound)
}

// invitationEnabled resolves the register page field label when the module is
// registered and enabled; the field itself rides only the register request.
func (a *App) invitationEnabled(ctx context.Context, locale string) (string, bool, error) {
	state, err := a.modules.RequestState(ctx)
	if err != nil {
		return "", false, err
	}
	if !state.HasInstalled("invitation-codes") || !state.HasEnabled("invitation-codes") {
		return "", false, nil
	}
	return modules.Message("InvitationCodes::front-end.placeholder", locale), true, nil
}
