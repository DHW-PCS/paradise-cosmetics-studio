package httpapp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"blessing-skin-go/internal/config"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/oauthserver"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/testsupport"
	"blessing-skin-go/internal/yggdrasil"
)

type m408Endpoint struct {
	BaseURL string
	Client  *http.Client
}
type m408Property struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Signature string `json:"signature,omitempty"`
}
type m408Profile struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Properties []m408Property `json:"properties"`
}
type m408GameSession struct {
	AccessToken       string        `json:"accessToken"`
	ClientToken       string        `json:"clientToken"`
	SelectedProfile   *m408Profile  `json:"selectedProfile"`
	AvailableProfiles []m408Profile `json:"availableProfiles"`
	UserID            string        `json:"-"`
}
type m408Fixture struct {
	Endpoint        m408Endpoint
	Identity        *identity.Service
	OAuth           *oauthserver.Server
	Key             *rsa.PrivateKey
	TexturesDir     string
	Clock           atomic.Int64
	OnlineToInGame  map[string]string
	RestorerEnabled bool
}

const m408UUID = "12345678123442348234123456789abc"
const m408AppKey = "synthetic-m408-application-key-32bytes"

func m408NewFixture(t *testing.T, basePath string, change func(*oauthserver.Config)) *m408Fixture {
	t.Helper()
	store, id := testsupport.Database(t, "m408_")
	f := &m408Fixture{Identity: id, TexturesDir: t.TempDir(), OnlineToInGame: map[string]string{m408UUID: m408OfflinePlayerOne}, RestorerEnabled: false}
	f.Clock.Store(time.Now().Unix())
	id.Now = func() time.Time { return time.Unix(f.Clock.Load(), 0) }
	server := httptest.NewUnstartedServer(nil)
	f.Endpoint = m408Endpoint{BaseURL: "http://" + server.Listener.Addr().String() + basePath, Client: server.Client()}
	t.Cleanup(server.Close)
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal("test RSA generation failed")
	}
	f.Key = key
	c := oauthserver.Config{Store: store, Identity: id, PrivateKey: key, Secret: []byte(m408AppKey), Issuer: f.Endpoint.BaseURL, Scopes: oauthserver.DefaultScopes, AccessLifetime: time.Hour, RefreshLifetime: 24 * time.Hour, CodeLifetime: 10 * time.Minute}
	if change != nil {
		change(&c)
	}
	f.OAuth, err = oauthserver.New(c)
	if err != nil {
		t.Fatal("OAuth composition failed")
	}
	for _, migrate := range []func() error{func() error { return f.OAuth.Migrate(t.Context()) }, func() error { return oauthserver.MigrateConsents(t.Context(), store) }, func() error { return oauthserver.MigrateAPIDigest(t.Context(), store) }} {
		if migrate() != nil {
			t.Fatal("OAuth migration failed")
		}
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := store.DB.Exec(q, args...); err != nil {
			t.Fatal("synthetic fixture statement failed")
		}
	}
	exec("INSERT INTO "+store.Table("uuid")+" (name,uuid) VALUES ('PlayerOne',?)", m408UUID)
	var row int64
	if err = store.DB.QueryRow("SELECT id FROM " + store.Table("uuid") + " WHERE name='PlayerOne'").Scan(&row); err != nil {
		t.Fatal("UUID fixture read failed")
	}
	exec("INSERT INTO "+store.Table("go_uuid_bindings")+" (pid,uuid_row_id,uuid,version) VALUES (1,?,?,1)", row, m408UUID)
	for n, v := range map[string]string{"plugins_enabled": `[{"name":"yggdrasil-api","version":"5.2.1"}]`, "go_module_installations": `[{"name":"yggdrasil-api","version":"5.2.1"}]`} {
		exec("UPDATE "+store.Table("options")+" SET option_value=? WHERE option_name=?", v, n)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	for n, v := range map[string]string{"site_url": f.Endpoint.BaseURL, "ygg_private_key": keyPEM, "ygg_token_expire_1": "3600", "ygg_token_expire_2": "86400", "ygg_tokens_limit": "20", "ygg_rate_limit": "0", "ygg_enable_ali": "1"} {
		exec("INSERT INTO "+store.Table("options")+" (option_name,option_value) VALUES (?,?)", n, v)
	}
	view := &site.Service{Store: store, Identity: id, Location: time.UTC, Modules: testsupport.Modules(store, id)}
	handler, err := New(config.Config{BaseURL: f.Endpoint.BaseURL, AppKey: []byte(m408AppKey), Locale: "en", FallbackLocale: "en", RememberLifetime: time.Hour, TexturesDir: f.TexturesDir}, id, view, f.OAuth, yggdrasil.New(store, id, nil, []byte(m408AppKey), false, id.Now), "m4-08-test")
	if err != nil {
		t.Fatal("App composition failed")
	}
	server.Config.Handler = handler
	server.Start()
	f.Endpoint.Client = server.Client()
	return f
}

// TestM408DeploymentMetadata checks native URL composition without rewriting
// response bodies, for both root and subpath deployments.
func TestM408DeploymentMetadata(t *testing.T) {
	for _, path := range []string{"", "/skin"} {
		t.Run("path="+path, func(t *testing.T) {
			f := m408NewFixture(t, path, nil)
			r, err := f.Endpoint.Client.Get(f.Endpoint.BaseURL + "/api/yggdrasil")
			if err != nil {
				t.Fatal("metadata request failed")
			}
			defer r.Body.Close()
			if r.StatusCode != 200 {
				t.Fatalf("metadata status=%d", r.StatusCode)
			}
			if r.Header.Get("X-Authlib-Injector-API-Location") != f.Endpoint.BaseURL+"/api/yggdrasil" {
				t.Fatal("API location did not preserve deployment URL")
			}
		})
	}
}

// TestM408GameChain runs the complete single-profile game
// chain: serverHash generation, join, hasJoined, RSA-SHA1 verification with
// the HTTP metadata key, and texture download/hash of a copied Steve skin and
// cape.
func TestM408GameChain(t *testing.T) {
	m408EachBasePath(t, func(t *testing.T, f *m408Fixture) {
		m408SetScore(t, f, 1, 100000)
		// HTTP metadata key (authlib-injector contract).
		metaURL := f.Endpoint.BaseURL + "/api/yggdrasil"
		_, meta, err := m408DiscoverAPI(f.Endpoint, metaURL, false)
		if err != nil {
			t.Fatalf("discover: %v", err)
		}
		pub, err := meta.PublicKey()
		if err != nil {
			t.Fatalf("metadata key: %v", err)
		}
		if pub.N.Cmp(f.Key.N) != 0 {
			t.Fatalf("metadata key differs from fixture key")
		}
		legacy := m408LegacyJWT(m408UUIDv5Email, m408RandomCompactUUID(), f.Clock.Load(), f.Clock.Load()+3600, []byte(m408AppKey))
		if !m408VerifyLegacyJWT(legacy, []byte(m408AppKey), m408UUIDv5Email) {
			t.Fatal("legacy fixture signature invalid")
		}
		for _, endpoint := range []string{"validate", "refresh"} {
			status, body := m408PostJSON(f.Endpoint, "/api/yggdrasil/authserver/"+endpoint, map[string]any{"accessToken": legacy, "clientToken": "legacy-client"})
			rem, ok := m408OptionalError(status, body).(*m408RemoteError)
			if !ok || status != 403 || rem.Name != "ForbiddenOperationException" || rem.Message != "Invalid AccessToken. Please re-login." {
				t.Fatal("legacy credential not rejected by frozen contract")
			}
		}
		c := m408NewHMCL(f.Endpoint)
		sess, err := c.withPassword(m408GameEmail, m408GamePass, nil)
		if err != nil {
			t.Fatalf("withPassword: %v", err)
		}
		// Seed real fixture rows/files: Steve skin and cape are copied
		// from testdata/m4-08 and uploaded through the real App.
		stevePath, steveHash := m408StageTexture(t, "steve-64x64.png")
		capePath, capeHash := m408StageTexture(t, "cape-64x32.png")
		m408UploadTexture(t, f.Endpoint, sess.AccessToken, m408UUID, "skin", "", stevePath)
		m408UploadTexture(t, f.Endpoint, sess.AccessToken, m408UUID, "cape", "", capePath)
		// Signed serverHash (Velocity EncryptionUtils shape) with
		// synthetic client-side server key material.
		serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		serverPubDER, err := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		sharedSecret := m408BytesRange(0x00, 0x10)
		serverID := m408ServerID(sharedSecret, serverPubDER)
		g := m408GameClient{ep: f.Endpoint}
		if err := g.join(sess.AccessToken, m408UUID, serverID); err != nil {
			t.Fatalf("join: %v", err)
		}
		doc, found, err := g.hasJoined("PlayerOne", serverID, "127.0.0.1")
		if err != nil || !found || doc == nil {
			t.Fatalf("hasJoined found=%v err=%v", found, err)
		}
		if doc.ID != m408UUID || doc.Name != "PlayerOne" {
			t.Fatalf("hasJoined doc = %s/%s", doc.ID, doc.Name)
		}
		if len(doc.Properties) != 2 {
			t.Fatal("hasJoined property count mismatch")
		}
		uploadable := false
		for _, property := range doc.Properties {
			if property.Name == "uploadableTextures" && property.Value == "skin,cape" {
				uploadable = true
			}
		}
		if !uploadable {
			t.Fatal("uploadableTextures property missing")
		}
		if err := m408VerifySignedProperties(pub, doc.Properties); err != nil {
			t.Fatalf("RSA-SHA1 verify: %v", err)
		}
		tp, err := m408DecodeTextures(doc.Properties)
		if err != nil {
			t.Fatalf("textures decode: %v", err)
		}
		if tp.ProfileID != m408UUID || tp.ProfileName != "PlayerOne" || !tp.IsPublic || !tp.SignatureRequired {
			t.Fatalf("texture payload = %+v", tp)
		}
		skin, okSkin := tp.Textures["SKIN"]
		cape, okCape := tp.Textures["CAPE"]
		if !okSkin || !okCape || skin.URL == "" || cape.URL == "" {
			t.Fatalf("textures map = %+v", tp.Textures)
		}
		if skin.Metadata != nil {
			t.Fatalf("steve skin has metadata")
		}
		for _, entry := range []m408TextureEntry{skin, cape} {
			textureURL, err := url.Parse(entry.URL)
			if err != nil || !meta.AllowsDomain(textureURL.Hostname()) {
				t.Fatal("texture URL outside metadata skinDomains")
			}
		}
		// Download and hash the served copies.
		skinData, status, err := m408Download(f.Endpoint, skin.URL)
		if err != nil || status != 200 {
			t.Fatalf("skin download status=%d err=%v", status, err)
		}
		capeData, status, err := m408Download(f.Endpoint, cape.URL)
		if err != nil || status != 200 {
			t.Fatalf("cape download status=%d err=%v", status, err)
		}
		skinSum := sha256.Sum256(skinData)
		capeSum := sha256.Sum256(capeData)
		if hex.EncodeToString(skinSum[:]) != steveHash || hex.EncodeToString(capeSum[:]) != capeHash {
			t.Fatalf("downloaded texture hash mismatch")
		}
		if f.RestorerEnabled {
			t.Fatal("synthetic fixture requires restorer OFF")
		}
		inGameUUID, ok := f.OnlineToInGame[doc.ID]
		if !ok || inGameUUID != m408OfflinePlayerOne {
			t.Fatal("synthetic UUID mapping missing")
		}
		props := make([]m408ForwardingProperty, 0, len(doc.Properties))
		for _, p := range doc.Properties {
			props = append(props, m408ForwardingProperty{Name: p.Name, Value: p.Value, HasSignature: p.Signature != "", Signature: p.Signature})
		}
		for _, version := range []int{1, 4} {
			msg := m408EncodeModernForwarding([]byte(m408ForwardingSec), version, m408ForwardingAddr, inGameUUID, doc.Name, props)
			decoded, err := m408DecodeModernForwarding([]byte(m408ForwardingSec), msg)
			if err != nil || decoded.Version != version || decoded.UUID != inGameUUID || decoded.Name != doc.Name || decoded.Address != m408ForwardingAddr {
				t.Fatal("backend forwarding identity mismatch")
			}
			if len(decoded.Properties) != len(props) {
				t.Fatal("backend forwarding properties count mismatch")
			}
			for i := range props {
				if decoded.Properties[i] != props[i] {
					t.Fatal("backend forwarding property mismatch")
				}
			}
			if _, err := m408DecodeModernForwarding([]byte("wrong-secret"), msg); err == nil {
				t.Fatal("backend accepted bad HMAC")
			}
		}
	})
}
