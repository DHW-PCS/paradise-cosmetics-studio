package captcha

import (
	"bytes"
	"errors"
	"image/jpeg"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/testsupport"
)

func TestImageContractAndNormalization(t *testing.T) {
	phrase, pixels, err := render()
	if err != nil {
		t.Fatal(err)
	}
	img, err := jpeg.Decode(bytes.NewReader(pixels))
	if err != nil || img.Bounds().Dx() != 100 || img.Bounds().Dy() != 34 || len(phrase) != 5 {
		t.Fatal("image CAPTCHA contract changed", err)
	}
	if niceize("O01IL") != niceize("oolil") {
		t.Fatal("Gregwar phrase normalization changed")
	}
}
func TestSessionChallengeReplacementAndSingleAttempt(t *testing.T) {
	store, id := testsupport.Database(t, "captcha-")
	s := &Service{store, id, http.DefaultClient}
	b, err := id.Guest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	seed := func() {
		t.Helper()
		_, err := store.DB.Exec("INSERT INTO "+store.Table("go_captchas")+" (session_digest,answer_digest,expires_at) VALUES (?,?,?) ON DUPLICATE KEY UPDATE answer_digest=VALUES(answer_digest)", identity.Digest(b.Token), identity.Digest(niceize("AbC01")), b.Expires.Unix())
		if err != nil {
			t.Fatal(err)
		}
	}
	seed()
	if ok, err := s.Check(t.Context(), b, "abcOl", ""); !ok || err != nil {
		t.Fatal("normalized answer rejected", err)
	}
	if ok, err := s.Check(t.Context(), b, "AbC01", ""); ok || err != nil {
		t.Fatal("challenge replayed", err)
	}
	seed()
	if ok, err := s.Check(t.Context(), b, "wrong", ""); ok || err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Check(t.Context(), b, "AbC01", ""); ok || err != nil {
		t.Fatal("wrong answer did not consume challenge", err)
	}
	seed()
	if _, err := s.Generate(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := store.DB.QueryRow("SELECT answer_digest FROM "+store.Table("go_captchas")+" WHERE session_digest=?", identity.Digest(b.Token)).Scan(&stored); err != nil || bytes.Equal(stored, identity.Digest(niceize("AbC01"))) {
		t.Fatal("refresh did not replace challenge", err)
	}
	seed()
	if _, err := store.DB.Exec("UPDATE "+store.Table("go_web_sessions")+" SET expires_at=?", time.Now().Add(-time.Second).Unix()); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Check(t.Context(), b, "AbC01", ""); ok || !errors.Is(err, identity.ErrSession) {
		t.Fatal("expired session snapshot accepted", err)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (fn roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }
func TestRecaptchaNetworkAndResponseFailures(t *testing.T) {
	store, id := testsupport.Database(t, "recaptcha-")
	b, err := id.Guest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"success":false}`, `{"success":true}`, `{}`, `garbage`} {
		client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host != "www.recaptcha.net" {
				t.Error("unexpected endpoint")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})}
		s := &Service{store, id, client}
		valid, err := s.Check(t.Context(), b, "answer", "secret")
		if body == `{"success":true}` {
			if !valid || err != nil {
				t.Fatal(err)
			}
		} else if body == `{"success":false}` {
			if valid || err != nil {
				t.Fatal("negative reCAPTCHA result misclassified")
			}
		} else if valid || !errors.Is(err, ErrUnavailable) {
			t.Fatal("malformed reCAPTCHA result accepted")
		}
	}
	s := &Service{store, id, &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("synthetic network fault") })}}
	if valid, err := s.Check(t.Context(), b, "answer", "secret"); valid || !errors.Is(err, ErrUnavailable) {
		t.Fatal("network failure accepted")
	}
}
