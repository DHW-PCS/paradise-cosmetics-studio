package httpapp

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"paradise-cosmetics-studio/internal/identity"
)

// Form errors belong to the current browser session. The session lock precedes
// the flash row, so logout/reset cannot leave a usable flash on an old snapshot.
func (a *App) formSession(ctx context.Context, tx *sql.Tx, b *identity.BrowserSession) (int64, error) {
	if b.User != nil {
		if _, err := a.identity.CheckBrowserTx(ctx, tx, b); err != nil {
			return 0, err
		}
	}
	var expires int64
	err := tx.QueryRowContext(ctx, "SELECT expires_at FROM "+a.identity.Store.Table("go_web_sessions")+" WHERE digest=? FOR UPDATE", identity.Digest(b.Token)).Scan(&expires)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, identity.ErrSession
	}
	if err != nil {
		return 0, err
	}
	if expires <= a.identity.Now().Unix() {
		return 0, identity.ErrSession
	}
	return expires, nil
}

// Flash forms. The frozen dashboard renders errors.first and
// session_pull('sentResult') as two callouts at the top of the notification
// card, so the admin page keeps two independent slots.
const (
	bindForm   = "bind"
	verifyForm = "verify"
	// The go_web_flashes.form column is VARCHAR(8); values must stay within it.
	notificationForm     = "notice"
	notificationSentForm = "noticeok"
	// The invitation generate form keeps the same palette.
	invitationForm = "inv-code"
)

var knownForms = map[string]bool{
	bindForm:             true,
	verifyForm:           true,
	notificationForm:     true,
	notificationSentForm: true,
	invitationForm:       true,
	yggConfigForm:        true,
}

func (a *App) putFormError(ctx context.Context, b *identity.BrowserSession, form, message string) error {
	if !knownForms[form] {
		panic("unknown account form")
	}
	return a.identity.Store.Transaction(ctx, func(tx *sql.Tx) error {
		expiry, err := a.formSession(ctx, tx, b)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO "+a.identity.Store.Table("go_web_flashes")+" (session_digest,form,message,expires_at) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE message=VALUES(message),expires_at=VALUES(expires_at)", identity.Digest(b.Token), form, message, expiry)
		return err
	})
}

// putFlash stores a message for a known form without redirecting.
func (a *App) putFlash(ctx context.Context, b *identity.BrowserSession, form, message string) error {
	return a.putFormError(ctx, b, form, message)
}

func (a *App) takeFormError(ctx context.Context, b *identity.BrowserSession, form string) (string, error) {
	var message string
	err := a.identity.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err := a.formSession(ctx, tx, b); err != nil {
			return err
		}
		err := tx.QueryRowContext(ctx, "SELECT message FROM "+a.identity.Store.Table("go_web_flashes")+" WHERE session_digest=? AND form=? AND expires_at>? FOR UPDATE", identity.Digest(b.Token), form, a.identity.Now().Unix()).Scan(&message)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM "+a.identity.Store.Table("go_web_flashes")+" WHERE session_digest=? AND form=?", identity.Digest(b.Token), form)
		return err
	})
	return message, err
}
func (a *App) redirectFormError(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, form, message string) {
	if err := a.putFormError(r.Context(), b, form, message); err != nil {
		a.serverError(w, r, b)
		return
	}
	location := a.cfg.BaseURL + strings.TrimPrefix(r.URL.Path, a.basePath)
	if r.URL.RawQuery != "" {
		location += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, location, http.StatusFound)
}
func (a *App) formValidation(w http.ResponseWriter, r *http.Request, b *identity.BrowserSession, form string, fields map[string][]string) {
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		validation(w, fields)
		return
	}
	a.redirectFormError(w, r, b, form, fields["email"][0])
}
