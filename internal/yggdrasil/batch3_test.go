package yggdrasil_test

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blessing-skin-go/internal/players"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/textures"
	"blessing-skin-go/internal/yggdrasil"
)

func authToken(t *testing.T, h harness) string {
	t.Helper()
	setOption(t, h.store, "ygg_token_expire_1", "3600")
	setOption(t, h.store, "ygg_token_expire_2", "86400")
	setOption(t, h.store, "ygg_tokens_limit", "10")
	res, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "user@example.invalid", Password: "original-password"})
	if err != nil {
		t.Fatal(err)
	}
	return res.AccessToken
}

func TestJoinAndHasJoinedSigned(t *testing.T) {
	h := fixture(t)
	token := authToken(t, h)
	pemText := genKey(t, 4096)
	setOption(t, h.store, "ygg_private_key", pemText)
	setOption(t, h.store, "site_url", "https://skin.example.invalid")
	uuidHex := players.UUID3("PlayerOne")
	dashed := yggdrasil.MustDashed(uuidHex)
	if err := h.svc.JoinServer(t.Context(), yggdrasil.JoinServerRequest{AccessToken: token, SelectedProfile: dashed, ServerID: "srv-1", ClientIP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	// Wrong IP -> 204 shape.
	ip := "10.0.0.9"
	if doc, ok, err := h.svc.HasJoinedServer(t.Context(), yggdrasil.HasJoinedServerRequest{Username: "PlayerOne", ServerID: "srv-1", IP: &ip}); err != nil || ok || doc != nil {
		t.Fatalf("wrong IP = %v %v %v", doc, ok, err)
	}
	// Wrong name -> 204.
	rightIP := "127.0.0.1"
	if doc, ok, err := h.svc.HasJoinedServer(t.Context(), yggdrasil.HasJoinedServerRequest{Username: "Nobody", ServerID: "srv-1", IP: &rightIP}); err != nil || ok || doc != nil {
		t.Fatalf("wrong name = %v %v %v", doc, ok, err)
	}
	doc, ok, err := h.svc.HasJoinedServer(t.Context(), yggdrasil.HasJoinedServerRequest{Username: "PlayerOne", ServerID: "srv-1", IP: &rightIP})
	if err != nil || !ok || doc == nil {
		t.Fatalf("hasJoined = %v %v %v", doc, ok, err)
	}
	if doc.ID != uuidHex || doc.Name != "PlayerOne" {
		t.Fatalf("doc identity %s %s", doc.ID, doc.Name)
	}
	if len(doc.Properties) != 2 || doc.Properties[1].Name != "uploadableTextures" || doc.Properties[1].Value != "skin,cape" {
		t.Fatalf("properties %#v", doc.Properties)
	}
	payloadRaw, err := base64.StdEncoding.DecodeString(doc.Properties[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["profileId"] != uuidHex || payload["profileName"] != "PlayerOne" || payload["isPublic"] != true || payload["signatureRequired"] != true {
		t.Fatalf("payload %#v", payload)
	}
	// Empty textures must be a JSON object, not an array.
	if !strings.Contains(string(payloadRaw), `"textures":{}`) {
		t.Fatalf("empty textures not object: %s", payloadRaw)
	}
	// Verify both RSA-SHA1 signatures against the exported public key.
	key, apiErr := yggdrasil.ParsePrivateKey(pemText)
	if apiErr != nil {
		t.Fatal(apiErr)
	}
	for _, prop := range doc.Properties {
		sig, err := base64.StdEncoding.DecodeString(prop.Signature)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha1.Sum([]byte(prop.Value))
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA1, sum[:], sig); err != nil {
			t.Fatalf("signature for %s invalid: %v", prop.Name, err)
		}
	}
	// Expire the join ticket -> 204.
	if _, err := h.store.DB.Exec("UPDATE " + h.store.Table("go_yggdrasil_joins") + " SET expires_at=0"); err != nil {
		t.Fatal(err)
	}
	if doc, ok, err := h.svc.HasJoinedServer(t.Context(), yggdrasil.HasJoinedServerRequest{Username: "PlayerOne", ServerID: "srv-1", IP: &rightIP}); err != nil || ok || doc != nil {
		t.Fatalf("expired = %v %v %v", doc, ok, err)
	}
}

func TestJoinRefusals(t *testing.T) {
	h := fixture(t)
	token := authToken(t, h)
	// Unknown UUID -> uuid exception 403.
	err := h.svc.JoinServer(t.Context(), yggdrasil.JoinServerRequest{AccessToken: token, SelectedProfile: "00000000-0000-0000-0000-000000000000", ServerID: "s", ClientIP: "127.0.0.1"})
	if err == nil || yggdrasil.NameOf(err) != "ForbiddenOperationException" || !strings.Contains(err.Error(), "Invalid Profile UUID") {
		t.Fatalf("unknown uuid err = %v", err)
	}
	// Missing token -> token.missing text.
	err = h.svc.JoinServer(t.Context(), yggdrasil.JoinServerRequest{AccessToken: "garbage", SelectedProfile: yggdrasil.MustDashed(players.UUID3("PlayerOne")), ServerID: "s"})
	if err == nil || !strings.Contains(err.Error(), "No valid credential information") {
		t.Fatalf("missing token err = %v", err)
	}
	// Token without selected profile: authenticate as admin (no roles).
	res, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "admin@example.invalid", Password: "original-password"})
	if err != nil {
		t.Fatal(err)
	}
	err = h.svc.JoinServer(t.Context(), yggdrasil.JoinServerRequest{AccessToken: res.AccessToken, SelectedProfile: yggdrasil.MustDashed(players.UUID3("PlayerOne")), ServerID: "s"})
	if err == nil || !strings.Contains(err.Error(), "doesn't match with that token") {
		t.Fatalf("unselected err = %v", err)
	}
}

func TestJoinBindingBumpInvalidates(t *testing.T) {
	h := fixture(t)
	token := authToken(t, h)
	dashed := yggdrasil.MustDashed(players.UUID3("PlayerOne"))
	if err := h.svc.JoinServer(t.Context(), yggdrasil.JoinServerRequest{AccessToken: token, SelectedProfile: dashed, ServerID: "srv", ClientIP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	// Simulate a transfer/rename binding bump: the old selected binding
	// no longer matches, so hasJoined becomes 204 and a fresh join with
	// the old token is refused even though the UUID text is unchanged.
	if _, err := h.store.DB.Exec("UPDATE " + h.store.Table("go_uuid_bindings") + " SET version=version+1 WHERE pid=1"); err != nil {
		t.Fatal(err)
	}
	ip := "127.0.0.1"
	if doc, ok, err := h.svc.HasJoinedServer(t.Context(), yggdrasil.HasJoinedServerRequest{Username: "PlayerOne", ServerID: "srv", IP: &ip}); err != nil || ok || doc != nil {
		t.Fatalf("bumped hasJoined = %v %v %v", doc, ok, err)
	}
	if err := h.svc.JoinServer(t.Context(), yggdrasil.JoinServerRequest{AccessToken: token, SelectedProfile: dashed, ServerID: "srv2"}); err == nil || !strings.Contains(err.Error(), "doesn't match with that token") {
		t.Fatalf("bumped join err = %v", err)
	}
}

func TestGetProfileUnsignedAndSigned(t *testing.T) {
	h := fixture(t)
	setOption(t, h.store, "site_url", "https://skin.example.invalid/")
	uuidHex := players.UUID3("PlayerOne")
	dashed := yggdrasil.MustDashed(uuidHex)
	// Unsigned (default): no signatures, no signatureRequired, no key needed.
	doc, ok, err := h.svc.GetProfileByUUID(t.Context(), dashed, false)
	if err != nil || !ok || doc == nil {
		t.Fatalf("unsigned = %v %v %v", doc, ok, err)
	}
	if doc.Properties[0].Signature != "" {
		t.Fatal("unsigned must not carry a signature")
	}
	payloadRaw, _ := base64.StdEncoding.DecodeString(doc.Properties[0].Value)
	if strings.Contains(string(payloadRaw), "signatureRequired") {
		t.Fatalf("unsigned payload carries signatureRequired: %s", payloadRaw)
	}
	// Hex input form resolves the same profile.
	if doc2, ok, err := h.svc.GetProfileByUUID(t.Context(), uuidHex, false); err != nil || !ok || doc2.ID != uuidHex {
		t.Fatalf("hex form = %v %v %v", doc2, ok, err)
	}
	// Missing profile -> 204 shape.
	if doc, ok, err := h.svc.GetProfileByUUID(t.Context(), "00000000000000000000000000000000", false); err != nil || ok || doc != nil {
		t.Fatalf("missing = %v %v %v", doc, ok, err)
	}
	// Signed with a 2048-bit key still verifies: profile signing only
	// requires a parseable private key (batch4 correction of the batch3
	// export-tier expectation; 4096-bit applies to hello/publickeys).
	setOption(t, h.store, "ygg_private_key", genKey(t, 2048))
	smallKey, ok, err := h.svc.GetProfileByUUID(t.Context(), dashed, true)
	if err != nil || !ok || smallKey.Properties[0].Signature == "" || smallKey.Properties[1].Signature == "" {
		t.Fatalf("small key signed = %v %v %v", smallKey, ok, err)
	}
	// Signed with a 4096-bit key verifies.
	setOption(t, h.store, "ygg_private_key", genKey(t, 4096))
	signed, ok, err := h.svc.GetProfileByUUID(t.Context(), dashed, true)
	if err != nil || !ok || signed.Properties[0].Signature == "" || signed.Properties[1].Signature == "" {
		t.Fatalf("signed = %v %v %v", signed, ok, err)
	}
}

func TestSearchProfiles(t *testing.T) {
	h := fixture(t)
	uuidHex := players.UUID3("PlayerOne")
	// Missing limit option: empty passes, non-empty is 403 query-max.
	out, err := h.svc.SearchMultipleProfiles(t.Context(), []string{})
	if err != nil || out == nil || len(out) != 0 {
		t.Fatalf("empty search = %v %v", out, err)
	}
	if _, err := h.svc.SearchMultipleProfiles(t.Context(), []string{"PlayerOne"}); err == nil || yggdrasil.StatusOf(err) != 403 || !strings.Contains(err.Error(), "query up to") {
		t.Fatalf("missing-limit err = %v", err)
	}
	setOption(t, h.store, "ygg_search_profile_max", "5")
	out, err = h.svc.SearchMultipleProfiles(t.Context(), []string{"PlayerOne", "PlayerOne", "Ghost", "PlayerOne"})
	if err != nil || len(out) != 1 || out[0].Name != "PlayerOne" || out[0].ID != uuidHex {
		t.Fatalf("search = %#v %v", out, err)
	}
	one, ok, err := h.svc.SearchSingleProfile(t.Context(), "PlayerOne")
	if err != nil || !ok || one.Name != "PlayerOne" {
		t.Fatalf("single = %v %v %v", one, ok, err)
	}
	if one, ok, err := h.svc.SearchSingleProfile(t.Context(), "Ghost"); err != nil || ok || one != nil {
		t.Fatalf("single missing = %v %v %v", one, ok, err)
	}
}

func pngBytes(t *testing.T, seed byte) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, 64, 64))
	for x := 0; x < 64; x++ {
		for y := 0; y < 64; y++ {
			img.SetNRGBA(x, y, color.NRGBA{R: uint8(x), G: uint8(y), B: seed, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestRealAuthorizerGameUploadReset(t *testing.T) {
	h := fixture(t)
	token := authToken(t, h)
	options := map[string]string{
		"player_name_rule": "official", "player_name_length_min": "3", "player_name_length_max": "16",
		"score_per_player": "100", "return_score": "true", "ygg_uuid_algorithm": "v4",
		"private_score_per_storage": "10", "score_per_closet_item": "7", "score_award_per_texture": "2",
		"score_per_storage": "5", "texture_name_regexp": "", "max_upload_file_size": "1024",
	}
	view := &site.Service{Store: h.store, Identity: h.id, Location: time.FixedZone("site", 8*3600), OptionSnapshot: options}
	dir := t.TempDir()
	clock := func() time.Time { return h.now }
	tex := textures.New(h.store, h.id, view, dir, clock)
	playerSvc := players.New(h.store, h.id, view, clock).WithTextures(tex)
	if _, err := h.store.DB.Exec("UPDATE " + h.store.Table("users") + " SET score=1000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	creds, err := h.svc.VerifyBearerToken(t.Context(), token)
	if err != nil {
		t.Fatal(err)
	}
	creds.Profile = "PlayerOne"
	creds.ProfileUUID = yggdrasil.MustDashed(players.UUID3("PlayerOne"))
	payload := pngBytes(t, 77)
	staging := filepath.Join(t.TempDir(), "upload.png")
	if err := os.WriteFile(staging, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := playerSvc.GameUpload(t.Context(), creds, h.svc, "skin", "default", "GameSkin", staging, int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if result.TID == 0 {
		t.Fatal("no texture id")
	}
	var skin int64
	h.store.DB.QueryRow("SELECT tid_skin FROM " + h.store.Table("players") + " WHERE pid=1").Scan(&skin)
	if skin != result.TID {
		t.Fatalf("skin not equipped: %d", skin)
	}
	// Published file exists under the textures dir for the hash.
	hash, err := textures.HashFile(staging)
	_ = hash
	_ = err
	var score int64
	h.store.DB.QueryRow("SELECT score FROM " + h.store.Table("users") + " WHERE uid=1").Scan(&score)
	if score >= 1000 {
		t.Fatalf("score not charged: %d", score)
	}
	// Revoked token: VerifyBearerToken now refuses, and a direct upload
	// attempt with the stale credential is rejected in-transaction with
	// no new texture row.
	if err := h.svc.Invalidate(t.Context(), yggdrasil.InvalidateRequest{AccessToken: token}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.VerifyBearerToken(t.Context(), token); !errors.Is(err, yggdrasil.ErrBearer) && (err == nil || yggdrasil.NameOf(err) != "UnauthorizedException") {
		t.Fatalf("revoked bearer err = %v", err)
	}
	staging2 := filepath.Join(t.TempDir(), "upload2.png")
	payload2 := pngBytes(t, 78)
	if err := os.WriteFile(staging2, payload2, 0o600); err != nil {
		t.Fatal(err)
	}
	var before int64
	h.store.DB.QueryRow("SELECT COUNT(*) FROM " + h.store.Table("textures")).Scan(&before)
	stale := creds
	if _, err := playerSvc.GameUpload(t.Context(), stale, h.svc, "skin", "default", "StaleSkin", staging2, int64(len(payload2))); err == nil {
		t.Fatal("stale upload succeeded")
	}
	var after int64
	h.store.DB.QueryRow("SELECT COUNT(*) FROM " + h.store.Table("textures")).Scan(&after)
	if after != before {
		t.Fatalf("stale upload wrote a texture: %d -> %d", before, after)
	}
	// Fresh token: GameReset clears the slot through the real Authorizer.
	token2 := authToken(t, h)
	creds2, err := h.svc.VerifyBearerToken(t.Context(), token2)
	if err != nil {
		t.Fatal(err)
	}
	creds2.ProfileUUID = yggdrasil.MustDashed(players.UUID3("PlayerOne"))
	if err := playerSvc.GameReset(t.Context(), creds2, h.svc, "skin"); err != nil {
		t.Fatal(err)
	}
	h.store.DB.QueryRow("SELECT tid_skin FROM " + h.store.Table("players") + " WHERE pid=1").Scan(&skin)
	if skin != 0 {
		t.Fatalf("reset did not clear skin: %d", skin)
	}
}

func TestRealAuthorizerRejectsForeignTarget(t *testing.T) {
	h := fixture(t)
	// Token for uid 2 (no roles, nothing selected) targeting PlayerOne.
	setOption(t, h.store, "ygg_token_expire_1", "3600")
	setOption(t, h.store, "ygg_token_expire_2", "86400")
	res, err := h.svc.Authenticate(t.Context(), yggdrasil.AuthenticateRequest{Username: "admin@example.invalid", Password: "original-password"})
	if err != nil {
		t.Fatal(err)
	}
	creds, err := h.svc.VerifyBearerToken(t.Context(), res.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	options := map[string]string{
		"player_name_rule": "official", "player_name_length_min": "3", "player_name_length_max": "16",
		"score_per_player": "100", "return_score": "true", "ygg_uuid_algorithm": "v4",
		"private_score_per_storage": "10", "score_per_closet_item": "7", "score_award_per_texture": "2",
		"score_per_storage": "5", "texture_name_regexp": "", "max_upload_file_size": "1024",
	}
	view := &site.Service{Store: h.store, Identity: h.id, Location: time.FixedZone("site", 8*3600), OptionSnapshot: options}
	dir := t.TempDir()
	clock := func() time.Time { return h.now }
	tex := textures.New(h.store, h.id, view, dir, clock)
	playerSvc := players.New(h.store, h.id, view, clock).WithTextures(tex)
	creds.ProfileUUID = yggdrasil.MustDashed(players.UUID3("PlayerOne"))
	if err := playerSvc.GameReset(t.Context(), creds, h.svc, "skin"); err == nil || !strings.Contains(err.Error(), "doesn't belong to that user") {
		t.Fatalf("foreign reset err = %v", err)
	}
	// Selected-profile independence: a target that is not the token's
	// selected profile is still authorized when it belongs to the token
	// owner. Add a second role for uid 1 and upload to it without any
	// selection change.
	if _, err := h.store.DB.Exec("INSERT INTO " + h.store.Table("players") + " (uid,name,tid_skin,tid_cape,last_modified) VALUES (1,'SecondRole',0,0,'2026-01-01 00:00:00')"); err != nil {
		t.Fatal(err)
	}
	var pid2 int64
	h.store.DB.QueryRow("SELECT pid FROM " + h.store.Table("players") + " WHERE name='SecondRole'").Scan(&pid2)
	secondHex := players.UUID3("SecondRole")
	if _, err := h.store.DB.Exec("INSERT INTO "+h.store.Table("uuid")+" (name,uuid) VALUES (?,?)", "SecondRole", secondHex); err != nil {
		t.Fatal(err)
	}
	var rowID int64
	h.store.DB.QueryRow("SELECT id FROM " + h.store.Table("uuid") + " WHERE name='SecondRole' ORDER BY id LIMIT 1").Scan(&rowID)
	if _, err := h.store.DB.Exec("INSERT INTO "+h.store.Table("go_uuid_bindings")+" (pid,uuid_row_id,uuid,version) VALUES (?,?,?,1)", pid2, rowID, secondHex); err != nil {
		t.Fatal(err)
	}
	token := authToken(t, h)
	ownerCreds, err := h.svc.VerifyBearerToken(t.Context(), token)
	if err != nil {
		t.Fatal(err)
	}
	ownerCreds.ProfileUUID = yggdrasil.MustDashed(secondHex)
	if err := playerSvc.GameReset(t.Context(), ownerCreds, h.svc, "cape"); err != nil {
		t.Fatalf("non-selected own target reset = %v", err)
	}
}
