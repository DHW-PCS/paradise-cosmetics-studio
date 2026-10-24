package web

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

var errNoSessionState = errors.New("web: request has no session state")

// Server wires the legacy routes onto a net/http mux. The mux is exposed for
// httptest and the serve subcommand.
type Server struct {
	cfg Config
	mux *http.ServeMux
}

// New validates the configuration and registers the PoC routes.
func New(cfg Config) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg}
	mux := http.NewServeMux()
	mux.Handle("GET /auth/login", s.web(s.csrf(s.guest(http.HandlerFunc(s.handleLoginPage)))))
	mux.Handle("POST /auth/login", s.web(s.csrf(s.guest(http.HandlerFunc(s.handleLogin)))))
	mux.Handle("POST /auth/logout", s.web(s.csrf(s.authorize(http.HandlerFunc(s.handleLogout)))))
	mux.Handle("GET /user", s.web(s.csrf(s.authorize(http.HandlerFunc(s.handleUser)))))
	mux.Handle("GET /auth/bind", s.web(s.csrf(s.authorize(http.HandlerFunc(s.handleBind)))))
	mux.Handle("GET /api/user", s.bearer(s.scope("User.Read", http.HandlerFunc(s.handleAPIUser))))
	s.mux = mux
	return s, nil
}

// scope mirrors Passport's scope middleware. The frozen Handler renders a
// MissingScopeException through json(message, 403), which is HTTP 200 with a
// business code of 403; the HTTP status must not be "fixed" here.
func (s *Server) scope(required string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := identityFrom(r)
		if identity == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": msgUnauthorized})
			return
		}
		if !hasScope(identity.Scopes, required) {
			writeJSON(w, http.StatusOK, jsonBody{Code: 403, Message: msgMissingScope})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hasScope mirrors Passport Token::can without inherited-scope resolution:
// a wildcard token satisfies any requirement, otherwise the name must match
// exactly.
func hasScope(scopes []string, required string) bool {
	for _, scope := range scopes {
		if scope == "*" || scope == required {
			return true
		}
	}
	return false
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// Handler exposes the mux for tests and embedding.
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) bearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) || s.cfg.Bearer == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": msgUnauthorized})
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": msgUnauthorized})
			return
		}
		identity, err := s.cfg.Bearer(r.Context(), token)
		if err != nil || identity == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": msgUnauthorized})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, identity)))
	})
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("web: %s %s: %v", r.Method, r.URL.Path, err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Server Error"})
}

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		first := strings.TrimSpace(strings.Split(forwarded, ",")[0])
		if net.ParseIP(first) != nil {
			return first
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func sha1Hex(value string) string {
	sum := sha1.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

// Serve starts an HTTP server and returns it. The caller owns shutdown.
func (s *Server) Serve(addr string) (*http.Server, error) {
	server := &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("web: serve: %v", err)
		}
	}()
	return server, nil
}
