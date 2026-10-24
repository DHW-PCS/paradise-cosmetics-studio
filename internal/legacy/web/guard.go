package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"blessing-skin-go/internal/legacy/auth"
	"blessing-skin-go/internal/legacy/php"
	"blessing-skin-go/internal/legacy/remember"
	"blessing-skin-go/internal/legacy/users"
)

type userKey struct{}
type identityKey struct{}

const (
	msgAnonymous    = "Illegal access. Please log in first."
	msgBanned       = "You are banned on this site. Please contact the admin."
	msgLoginSuccess = "Logged in successfully."
	msgLogout       = "You are now logged out."
	msgWrongPass    = "Wrong password."
	msgNoSuchUser   = "No such user."
	msgUnauthorized = "Unauthenticated."
	// msgMissingScope is MissingScopeException's default message as rendered
	// by the frozen exception handler.
	msgMissingScope = "Invalid scope(s) provided."
)

type authOutcome struct {
	user   *users.User
	banned bool
}

func userFrom(r *http.Request) *users.User {
	user, _ := r.Context().Value(userKey{}).(*users.User)
	return user
}

func identityFrom(r *http.Request) *BearerIdentity {
	identity, _ := r.Context().Value(identityKey{}).(*BearerIdentity)
	return identity
}

// resolve implements SessionGuard::user(): the session login key first, then
// the remember-me recaller. A revoked or unverifiable Go session is treated as
// a guest instead of resurrecting it.
func (s *Server) resolve(r *http.Request) (*authOutcome, error) {
	st := stateFrom(r)
	if st == nil {
		return nil, nil
	}
	if uid, ok := sessionLoginUID(st.attrs, s.cfg.LoginKey); ok && uid > 0 {
		validation, err := s.cfg.Auth.ValidateSession(r.Context(), st.attrs)
		switch {
		case err == nil:
			if validation.Legacy {
				state, upgradeErr := s.cfg.Auth.UpgradeLegacy(r.Context(), validation.User.UID)
				if upgradeErr != nil {
					if errors.Is(upgradeErr, auth.ErrLegacyUnverifiable) {
						clearLoginData(st, s.cfg.LoginKey)
						break
					}
					return nil, upgradeErr
				}
				setGoAuth(st.attrs, validation.User.UID, state.SessionVersion, s.cfg.now().Unix())
			}
			return &authOutcome{user: validation.User}, nil
		case errors.Is(err, auth.ErrBanned):
			user, found, lookupErr := s.cfg.Users.ByUID(r.Context(), uid)
			if lookupErr != nil {
				return nil, lookupErr
			}
			if found {
				return &authOutcome{user: user, banned: true}, nil
			}
			clearLoginData(st, s.cfg.LoginKey)
		case errors.Is(err, auth.ErrNoSession), errors.Is(err, auth.ErrStaleSession):
			clearLoginData(st, s.cfg.LoginKey)
		default:
			return nil, err
		}
	}
	user, err := s.recallerUser(r, st)
	if err != nil {
		return nil, err
	}
	if user != nil {
		return &authOutcome{user: user, banned: user.Permission == users.Banned}, nil
	}
	return nil, nil
}

func (s *Server) recallerUser(r *http.Request, st *sessionState) (*users.User, error) {
	cookie, err := r.Cookie(s.cfg.RememberCookie)
	if err != nil {
		return nil, nil
	}
	recaller, err := remember.Cookie(s.cfg.Encrypter, s.cfg.RememberCookie, cookie.Value)
	if err != nil {
		if decoded, decodeErr := url.QueryUnescape(cookie.Value); decodeErr == nil {
			recaller, err = remember.Cookie(s.cfg.Encrypter, s.cfg.RememberCookie, decoded)
		}
	}
	if err != nil {
		return nil, nil
	}
	user, state, err := s.cfg.Auth.RememberState(r.Context(), recaller.UID, recaller.Token)
	if errors.Is(err, auth.ErrRememberRejected) || errors.Is(err, auth.ErrUnknownUser) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	newID, err := s.cfg.Sessions.Rotate(st.id)
	if err != nil {
		return nil, err
	}
	st.id = newID
	st.attrs.Set(s.cfg.LoginKey, user.UID)
	setGoAuth(st.attrs, user.UID, state.SessionVersion, s.cfg.now().Unix())
	return user, nil
}

func clearLoginData(st *sessionState, loginKey string) {
	st.attrs.Delete(loginKey)
	st.attrs.Delete("go_auth")
}

func sessionLoginUID(attrs *php.Array, loginKey string) (int64, bool) {
	if attrs == nil {
		return 0, false
	}
	return attrs.GetInt(loginKey)
}

func setGoAuth(attrs *php.Array, uid, rev, iat int64) {
	attrs.Set("go_auth", php.NewArray().
		Set("uid", uid).
		Set("rev", rev).
		Set("iat", iat))
}

func (s *Server) guest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outcome, err := s.resolve(r)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if outcome != nil {
			redirectTo(w, r, "/user")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authorize mirrors the "authorize" route middleware group.
func (s *Server) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outcome, err := s.resolve(r)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if outcome == nil {
			s.unauthenticated(w, r)
			return
		}
		if outcome.banned {
			s.banned(w, r)
			return
		}
		user := outcome.user
		onBind := r.URL.Path == "/auth/bind"
		if user.Email != "" && onBind {
			redirectTo(w, r, "/user")
			return
		}
		if user.Email == "" && !onBind {
			redirectTo(w, r, "/auth/bind")
			return
		}
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), user)))
	})
}

func (s *Server) unauthenticated(w http.ResponseWriter, r *http.Request) {
	if st := stateFrom(r); st != nil && !expectsJSON(r) {
		st.attrs.Set("last_requested_path", requestURL(r))
		st.attrs.Set("msg", msgAnonymous)
	}
	if expectsJSON(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": msgUnauthorized})
		return
	}
	redirectTo(w, r, "/auth/login")
}

func (s *Server) banned(w http.ResponseWriter, r *http.Request) {
	if expectsJSON(r) {
		writeJSON(w, http.StatusForbidden, jsonBody{Code: -1, Message: msgBanned})
		return
	}
	writeHTML(w, http.StatusForbidden, "<!doctype html><html><head><title>403 Forbidden</title></head>"+
		"<body><h1>403 Forbidden</h1><p>"+msgBanned+"</p></body></html>")
}

// withUser stores the resolved user in the request context.
func withUser(ctx context.Context, user *users.User) context.Context {
	return context.WithValue(ctx, userKey{}, user)
}
