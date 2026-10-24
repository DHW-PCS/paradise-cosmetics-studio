package web

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"blessing-skin-go/internal/legacy/laravel"
	"blessing-skin-go/internal/legacy/php"
	"blessing-skin-go/internal/legacy/session"
)

type contextKey struct{ name string }

var sessionKey = contextKey{"session"}

// sessionState is the request-scoped view of the file session.
type sessionState struct {
	id    string
	attrs *php.Array
	// skipXSRF is set when VerifyCsrfToken rejected the request: StartSession
	// still persists the session, but the XSRF cookie is not refreshed.
	skipXSRF bool
}

func stateFrom(r *http.Request) *sessionState {
	st, _ := r.Context().Value(sessionKey).(*sessionState)
	return st
}

func withState(r *http.Request, st *sessionState) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), sessionKey, st))
}

// web loads the session and persists it after the route pipeline renders its
// response, including authentication, validation and CSRF errors. A CSRF
// failure suppresses only the XSRF cookie, not the session save.
func (s *Server) web(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st, err := s.loadSession(r)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if r.Method == http.MethodGet && !isAjax(r) {
			setPreviousURL(st.attrs, requestURL(r))
		}
		rec := newRecorder()
		next.ServeHTTP(rec, withState(r, st))
		if err := s.saveSession(rec.Header(), st); err != nil {
			s.internalError(w, r, err)
			return
		}
		rec.flush(w)
	})
}

func (s *Server) loadSession(r *http.Request) (*sessionState, error) {
	st := &sessionState{attrs: php.NewArray()}
	if cookie, err := r.Cookie(s.cfg.SessionCookie.Name); err == nil {
		id, err := s.sessionIDFromCookie(cookie.Value)
		if err == nil {
			st.id = id
			attrs, err := s.cfg.Sessions.Read(id)
			switch {
			case err == nil:
				st.attrs = attrs
			case errors.Is(err, session.ErrNotFound):
				// The native handler unlinks an expired file and reports an
				// empty session; the id is kept either way.
				_ = s.cfg.Sessions.Destroy(id)
			case errors.Is(err, session.ErrCorrupt):
				// Store::readFromHandler returns [] for an unparsable payload.
			default:
				return nil, err
			}
			return st, nil
		}
	}
	id, err := session.NewID()
	if err != nil {
		return nil, err
	}
	st.id = id
	return st, nil
}

func (s *Server) saveSession(header http.Header, st *sessionState) error {
	token, err := ensureToken(st)
	if err != nil {
		return err
	}
	session.AgeFlashData(st.attrs)
	if err := s.cfg.Sessions.Write(st.id, st.attrs); err != nil {
		return err
	}
	value, err := session.SessionCookieValue(s.cfg.Encrypter, s.cfg.SessionCookie.Name, st.id)
	if err != nil {
		return err
	}
	addCookie(header, s.cfg.SessionCookie, value, s.cfg.SessionCookie.HTTPOnly, s.cfg.now())
	if st.skipXSRF {
		return nil
	}

	xsrf := laravel.CookieAttributes{
		Name:     s.cfg.XSRFCookie,
		Path:     s.cfg.SessionCookie.Path,
		Domain:   s.cfg.SessionCookie.Domain,
		Secure:   s.cfg.SessionCookie.Secure,
		HTTPOnly: false,
		SameSite: s.cfg.SessionCookie.SameSite,
		Lifetime: s.cfg.SessionCookie.Lifetime,
	}
	xsrfValue, err := s.cfg.Encrypter.EncryptCookie(s.cfg.XSRFCookie, token)
	if err != nil {
		return err
	}
	addCookie(header, xsrf, xsrfValue, false, s.cfg.now())
	return nil
}

// sessionIDFromCookie mirrors PHP's cookie decoding: Symfony URL-encodes
// cookie values on the wire and PHP decodes them before Laravel sees them.
func (s *Server) sessionIDFromCookie(value string) (string, error) {
	id, err := session.SessionIDFromCookie(s.cfg.Encrypter, s.cfg.SessionCookie.Name, value)
	if err == nil {
		return id, nil
	}
	decoded, decodeErr := url.QueryUnescape(value)
	if decodeErr != nil {
		return "", err
	}
	return session.SessionIDFromCookie(s.cfg.Encrypter, s.cfg.SessionCookie.Name, decoded)
}

func addCookie(header http.Header, attrs laravel.CookieAttributes, value string, httpOnly bool, now time.Time) {
	cookie := &http.Cookie{
		Name:     attrs.Name,
		Value:    url.QueryEscape(value),
		Path:     attrs.Path,
		Domain:   attrs.Domain,
		Secure:   attrs.Secure,
		HttpOnly: httpOnly,
		SameSite: sameSite(attrs.SameSite),
	}
	if attrs.Lifetime > 0 {
		cookie.MaxAge = int(attrs.Lifetime.Seconds())
		cookie.Expires = now.Add(attrs.Lifetime).UTC()
	}
	header.Add("Set-Cookie", cookie.String())
}

func deleteCookie(header http.Header, attrs laravel.CookieAttributes, value string, httpOnly bool) {
	cookie := &http.Cookie{
		Name:     attrs.Name,
		Value:    url.QueryEscape(value),
		Path:     attrs.Path,
		Domain:   attrs.Domain,
		Secure:   attrs.Secure,
		HttpOnly: httpOnly,
		SameSite: sameSite(attrs.SameSite),
		MaxAge:   -1,
		Expires:  time.Unix(1, 0).UTC(),
	}
	header.Add("Set-Cookie", cookie.String())
}

func sameSite(value string) http.SameSite {
	switch strings.ToLower(value) {
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}

func ensureToken(st *sessionState) (string, error) {
	if token, ok := session.CSRF(st.attrs); ok && token != "" {
		return token, nil
	}
	token, err := randomToken(40)
	if err != nil {
		return "", err
	}
	st.attrs.Set("_token", token)
	return token, nil
}

func setPreviousURL(attrs *php.Array, url string) {
	if current, ok := attrs.Get("_previous"); ok {
		if previous, ok := current.(*php.Array); ok {
			previous.Set("url", url)
			return
		}
	}
	attrs.Set("_previous", php.NewArray().Set("url", url))
}

const tokenCharset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randomToken(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = tokenCharset[int(buf[i])%len(tokenCharset)]
	}
	return string(buf), nil
}
