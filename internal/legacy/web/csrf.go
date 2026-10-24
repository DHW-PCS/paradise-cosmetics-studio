package web

import (
	"crypto/subtle"
	"net/http"
	"net/url"
)

// csrf mirrors VerifyCsrfToken: reads are skipped, the token may arrive as the
// _token input, the X-CSRF-TOKEN header or the decrypted X-XSRF-TOKEN header.
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cache := &inputCache{}
		r = withInputs(r, cache)

		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}

		st := stateFrom(r)
		if st == nil {
			s.internalError(w, r, errNoSessionState)
			return
		}
		expected, err := ensureToken(st)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if subtle.ConstantTimeCompare([]byte(s.csrfToken(r)), []byte(expected)) != 1 {
			st.skipXSRF = true
			s.csrfFailure(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) csrfToken(r *http.Request) string {
	if token := inputString(r, "_token"); token != "" {
		return token
	}
	if token := r.Header.Get("X-CSRF-TOKEN"); token != "" {
		return token
	}
	if header := r.Header.Get("X-XSRF-TOKEN"); header != "" {
		if token, err := s.cfg.Encrypter.DecryptCookie(s.cfg.XSRFCookie, header); err == nil {
			return token
		}
		if decoded, err := url.QueryUnescape(header); err == nil {
			if token, err := s.cfg.Encrypter.DecryptCookie(s.cfg.XSRFCookie, decoded); err == nil {
				return token
			}
		}
	}
	return ""
}

func (s *Server) csrfFailure(w http.ResponseWriter, r *http.Request) {
	if expectsJSON(r) {
		writeJSON(w, 419, map[string]string{"message": "CSRF token mismatch."})
		return
	}
	writeHTML(w, 419, "<!doctype html><html><head><title>419 Page Expired</title></head>"+
		"<body><h1>419 Page Expired</h1></body></html>")
}
