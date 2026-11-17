package httpapp

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/config"
	"paradise-cosmetics-studio/internal/database"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/oauthserver"
	"paradise-cosmetics-studio/internal/site"
	"paradise-cosmetics-studio/internal/yggdrasil"
)

// TestCoreAPIConstructorRegistersWithoutPanic exercises the real
// composition root to catch ServeMux pattern conflicts at construction.
// No database queries run, so it stays green without M2_TEST_DSN.
func TestCoreAPIConstructorRegistersWithoutPanic(t *testing.T) {
	store := &database.Store{DB: nil, Prefix: "synthetic_"}
	id := &identity.Service{Store: store, Now: time.Now}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oauth, err := oauthserver.New(oauthserver.Config{Store: store, Identity: id, PrivateKey: key, Secret: []byte("synthetic-m2-secret-at-least-32-bytes"), Issuer: "http://localhost/skin", Scopes: oauthserver.DefaultScopes, AccessLifetime: time.Hour, RefreshLifetime: 24 * time.Hour, CodeLifetime: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	view := &site.Service{Store: store, Identity: id, Location: time.UTC}
	handler, err := New(config.Config{BaseURL: "http://localhost/skin", Locale: "zh_CN", FallbackLocale: "en", TexturesDir: t.TempDir()}, id, view, oauth, yggdrasil.New(store, id, nil, []byte("synthetic-yggdrasil-hs256-key-32b"), false, id.Now), "m4-05-test")
	if err != nil {
		t.Fatal(err)
	}
	if handler == nil {
		t.Fatal("handler is nil")
	}
}
