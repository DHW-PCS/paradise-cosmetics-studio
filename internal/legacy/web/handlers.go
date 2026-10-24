package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"blessing-skin-go/internal/legacy/auth"
	"blessing-skin-go/internal/legacy/laravel"
	"blessing-skin-go/internal/legacy/password"
	"blessing-skin-go/internal/legacy/remember"
	"blessing-skin-go/internal/legacy/users"
)

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	st := stateFrom(r)
	token, err := ensureToken(st)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	body := fmt.Sprintf("<!doctype html><html><head><meta name=\"csrf-token\" content=\"%s\"></head>"+
		"<body>login</body></html>", htmlEscape(token))
	writeHTML(w, http.StatusOK, body)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	st := stateFrom(r)
	identification := inputString(r, "identification")
	rawPassword := inputString(r, "password")

	fieldErrors := map[string][]string{}
	if identification == "" {
		fieldErrors["identification"] = []string{"The email or player name field is required."}
	}
	switch {
	case rawPassword == "":
		fieldErrors["password"] = []string{"The password field is required."}
	case utf8.RuneCountInString(rawPassword) < 6:
		fieldErrors["password"] = []string{"The password must be at least 6 characters."}
	case utf8.RuneCountInString(rawPassword) > 32:
		fieldErrors["password"] = []string{"The password may not be greater than 32 characters."}
	}
	if len(fieldErrors) > 0 {
		s.validationError(w, r, st, fieldErrors)
		return
	}

	result, err := s.cfg.Auth.Login(r.Context(), identification, rawPassword, inputTruthy(r, "keep"))
	switch {
	case err == nil:
	case errors.Is(err, auth.ErrUnknownUser):
		writeLegacyJSON(w, 2, msgNoSuchUser, nil)
		return
	case errors.Is(err, auth.ErrBadPassword):
		failures := s.recordLoginFailure(r)
		writeLegacyJSON(w, 1, msgWrongPass, map[string]any{"login_fails": failures})
		return
	case errors.Is(err, password.ErrLength):
		s.validationError(w, r, st, map[string][]string{"password": {"The password must be at least 6 characters."}})
		return
	default:
		s.internalError(w, r, err)
		return
	}
	user := result.User

	st.attrs.Delete("login_fails")
	if s.cfg.Cache != nil {
		_ = s.cfg.Cache.Forget(loginFailKey(clientIP(r)))
	}
	if result.Remember != "" {
		if err := s.writeRecaller(w, r, user, result.Remember); err != nil {
			s.internalError(w, r, err)
			return
		}
	}

	newID, err := s.cfg.Sessions.Rotate(st.id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	st.id = newID
	st.attrs.Set(s.cfg.LoginKey, user.UID)
	setGoAuth(st.attrs, user.UID, result.State.SessionVersion, s.cfg.now().Unix())

	redirect := absoluteURL(r, "/user")
	if previous, ok := st.attrs.GetString("last_requested_path"); ok && previous != "" {
		redirect = previous
		st.attrs.Delete("last_requested_path")
	}
	writeLegacyJSON(w, 0, msgLoginSuccess, map[string]any{"redirectTo": redirect})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	st := stateFrom(r)
	user := userFrom(r)

	if user != nil && user.RememberToken != "" {
		token, err := randomToken(60)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if err := s.cfg.Users.UpdateRememberToken(r.Context(), user.UID, token); err != nil {
			s.internalError(w, r, err)
			return
		}
	}

	// SessionGuard::logout in the frozen framework removes the auth key but
	// does not migrate the session, so the id is preserved.
	clearLoginData(st, s.cfg.LoginKey)
	if _, err := r.Cookie(s.cfg.RememberCookie); err == nil {
		// EncryptCookies encrypts the queued deletion cookie as well, so the
		// expired value is an encrypted empty string, not an empty wire value.
		value, err := s.cfg.Encrypter.EncryptCookie(s.cfg.RememberCookie, "")
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		deleteCookie(w.Header(), laravel.CookieAttributes{
			Name:     s.cfg.RememberCookie,
			Path:     s.cfg.SessionCookie.Path,
			Domain:   s.cfg.SessionCookie.Domain,
			Secure:   s.cfg.SessionCookie.Secure,
			SameSite: s.cfg.SessionCookie.SameSite,
		}, value, true)
	}
	writeLegacyJSON(w, 0, msgLogout, nil)
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	writeHTML(w, http.StatusOK, "<!doctype html><html><body>user</body></html>")
}

func (s *Server) handleBind(w http.ResponseWriter, r *http.Request) {
	writeHTML(w, http.StatusOK, "<!doctype html><html><body>bind</body></html>")
}

func (s *Server) handleAPIUser(w http.ResponseWriter, r *http.Request) {
	identity := identityFrom(r)
	user, found, err := s.cfg.Users.ByUID(r.Context(), identity.UID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": msgUnauthorized})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"uid":        user.UID,
		"email":      user.Email,
		"nickname":   user.Nickname,
		"permission": user.Permission,
		"verified":   user.Verified,
	})
}

// writeRecaller sets the recaller cookie for a token already committed by the
// authentication transaction; it never updates the database outside that
// transaction.
func (s *Server) writeRecaller(w http.ResponseWriter, r *http.Request, user *users.User, token string) error {
	value, err := remember.CookieValue(s.cfg.Encrypter, s.cfg.RememberCookie,
		&remember.Recaller{UID: user.UID, Token: token, Password: user.Password})
	if err != nil {
		return err
	}
	addCookie(w.Header(), laravel.CookieAttributes{
		Name:     s.cfg.RememberCookie,
		Path:     s.cfg.SessionCookie.Path,
		Domain:   s.cfg.SessionCookie.Domain,
		Secure:   s.cfg.SessionCookie.Secure,
		SameSite: s.cfg.SessionCookie.SameSite,
		Lifetime: s.cfg.RememberLifetime,
	}, value, true, s.cfg.now())
	return nil
}

func (s *Server) validationError(w http.ResponseWriter, r *http.Request, st *sessionState, fieldErrors map[string][]string) {
	if expectsJSON(r) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"message": "The given data was invalid.",
			"errors":  fieldErrors,
		})
		return
	}
	// This PoC only reproduces the redirect. Laravel also flashes errors and
	// old input; that HTML validation path remains a compatibility gap.
	back := r.Referer()
	if back == "" {
		back = absoluteURL(r, "/auth/login")
	}
	w.Header().Set("Location", back)
	w.WriteHeader(http.StatusFound)
}

func (s *Server) recordLoginFailure(r *http.Request) int64 {
	if s.cfg.Cache == nil {
		return 1
	}
	key := loginFailKey(clientIP(r))
	value, ok, err := s.cfg.Cache.Get(key)
	current := int64(0)
	if err == nil && ok {
		if stored, ok := value.(int64); ok {
			current = stored
		}
	}
	current++
	if err := s.cfg.Cache.Put(key, current, time.Hour); err != nil {
		return current
	}
	return current
}

func loginFailKey(ip string) string {
	return sha1Hex("login_fails_" + ip)
}

func htmlEscape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return replacer.Replace(value)
}
