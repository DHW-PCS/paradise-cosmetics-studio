package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
)

// recorder buffers a handler response so the session can be persisted and its
// cookies appended before anything reaches the real writer.
type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newRecorder() *recorder {
	return &recorder{header: make(http.Header)}
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}

func (r *recorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(p)
}

func (r *recorder) flush(w http.ResponseWriter) {
	for key, values := range r.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	status := r.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(r.body.Bytes())
}

// jsonBody mirrors the legacy json() helper. Data is omitted when nil.
type jsonBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeLegacyJSON(w http.ResponseWriter, code int, message string, data any) {
	writeJSON(w, http.StatusOK, jsonBody{Code: code, Message: message, Data: data})
}

func writeHTML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func expectsJSON(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return true
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	return strings.Contains(accept, "application/json")
}

func isAjax(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest")
}

func absoluteURL(r *http.Request, path string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	return scheme + "://" + r.Host + path
}

func requestURL(r *http.Request) string {
	return absoluteURL(r, r.URL.RequestURI())
}

func redirectTo(w http.ResponseWriter, r *http.Request, path string) {
	w.Header().Set("Location", absoluteURL(r, path))
	w.WriteHeader(http.StatusFound)
}
