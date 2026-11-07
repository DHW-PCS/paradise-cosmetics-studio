package players

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/testsupport"
	"blessing-skin-go/internal/textures"
)

type equipFixture struct {
	service  *Service
	textures *textures.Service
	id       *identity.Service
	store    *database.Store
	dir      string
}

func equipEnv(t *testing.T) equipFixture {
	t.Helper()
	store, id := testsupport.Database(t, "equip-")
	options := map[string]string{
		"player_name_rule": "official", "player_name_length_min": "3", "player_name_length_max": "16",
		"score_per_player": "100", "return_score": "true", "ygg_uuid_algorithm": "v4",
		"private_score_per_storage": "10", "score_per_closet_item": "7", "score_award_per_texture": "2",
		"score_per_storage": "5", "texture_name_regexp": "", "max_upload_file_size": "1024",
	}
	view := &site.Service{Store: store, Identity: id, Location: time.FixedZone("site", 8*3600), OptionSnapshot: options}
	dir := t.TempDir()
	clock := func() time.Time { return time.Date(2026, 10, 30, 12, 0, 0, 0, time.FixedZone("site", 8*3600)) }
	tex := textures.New(store, id, view, dir, clock)
	service := New(store, id, view, clock).WithTextures(tex)
	return equipFixture{service: service, textures: tex, id: id, store: store, dir: dir}
}

func pngFixture(t *testing.T, width, height int, seed byte) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	for x := 0; x < width; x++ {
		for y := 0; y < height; y++ {
			img.SetNRGBA(x, y, color.NRGBA{R: uint8(x), G: uint8(y), B: seed, A: 255})
		}
	}
	var buffer bytes.Buffer
	if err := png.Encode(&buffer, img); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func stageFile(t *testing.T, env equipFixture, payload []byte) (string, int64) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "upload.png")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	staged, written, err := env.textures.StageUpload(file, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return staged, written
}

func uploadAsUserKind(t *testing.T, env equipFixture, b *identity.BrowserSession, name, kind string, public bool, payload []byte) int64 {
	t.Helper()
	source, written := stageFile(t, env, payload)
	tid, err := env.textures.Upload(context.Background(), textures.UploadInput{Browser: b, Name: name, Type: kind, Public: public, Source: source, Bytes: written})
	if err != nil {
		t.Fatal(err)
	}
	return tid
}

func uploadAsUser(t *testing.T, env equipFixture, b *identity.BrowserSession, name string, public bool, payload []byte) int64 {
	return uploadAsUserKind(t, env, b, name, "steve", public, payload)
}

func addPlayer(t *testing.T, env equipFixture, uid int64, name string) int64 {
	t.Helper()
	result, err := env.store.DB.Exec("INSERT INTO "+env.store.Table("players")+" (uid,name,tid_skin,tid_cape,last_modified) VALUES (?,?,0,0,'2026-01-01 00:00:00')", uid, name)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := result.LastInsertId()
	return pid
}

func userScore(t *testing.T, store *database.Store, uid int64) int64 {
	t.Helper()
	var score int64
	if err := store.DB.QueryRow("SELECT score FROM "+store.Table("users")+" WHERE uid=?", uid).Scan(&score); err != nil {
		t.Fatal(err)
	}
	return score
}

func TestSetTexturesValidatesBothSlotsBeforeWriting(t *testing.T) {
	env := equipEnv(t)
	b := loginIdentity(t, env.id, "user@example.invalid")
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET score=100000 WHERE uid IN (1,2)"); err != nil {
		t.Fatal(err)
	}
	pid := addPlayer(t, env, 1, "EquipPlayer")
	skinTID := uploadAsUser(t, env, b, "ValidSkin", true, pngFixture(t, 64, 64, 61))
	capeTID := uploadAsUserKind(t, env, b, "ValidCape", "cape", true, pngFixture(t, 64, 32, 62))
	// Second slot fails (a skin texture in the cape slot) → no first-slot write.
	if _, err := env.service.SetTextures(context.Background(), b, pid, &skinTID, &skinTID); !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("type mismatch error = %v", err)
	}
	var skin, cape int64
	env.store.DB.QueryRow("SELECT tid_skin,tid_cape FROM "+env.store.Table("players")+" WHERE pid=?", pid).Scan(&skin, &cape)
	if skin != 0 || cape != 0 {
		t.Fatalf("failed pair wrote slots skin=%d cape=%d", skin, cape)
	}
	if _, err := env.service.SetTextures(context.Background(), b, pid, &skinTID, &capeTID); err != nil {
		t.Fatal(err)
	}
	env.store.DB.QueryRow("SELECT tid_skin,tid_cape FROM "+env.store.Table("players")+" WHERE pid=?", pid).Scan(&skin, &cape)
	if skin != skinTID || cape != capeTID {
		t.Fatalf("slots after success skin=%d cape=%d", skin, cape)
	}
	if _, err := env.service.ClearTextures(context.Background(), b, pid, true, false); err != nil {
		t.Fatal(err)
	}
	env.store.DB.QueryRow("SELECT tid_skin,tid_cape FROM "+env.store.Table("players")+" WHERE pid=?", pid).Scan(&skin, &cape)
	if skin != 0 || cape != capeTID {
		t.Fatalf("clear slots skin=%d cape=%d", skin, cape)
	}
	// Textures outside the closet are rejected.
	otherTID := uploadAsUser(t, env, loginIdentity(t, env.id, "admin@example.invalid"), "OtherSkin", true, pngFixture(t, 64, 64, 63))
	if _, err := env.service.SetTextures(context.Background(), b, pid, &otherTID, nil); !errors.Is(err, ErrNotInCloset) {
		t.Fatalf("non-closet texture error = %v", err)
	}
}

func TestSetTexturesMissingTexture(t *testing.T) {
	service, id, store := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	pid := insertPlayer(t, store, 1, "MissingTexture")
	tid := int64(9999)
	_, err := service.SetTextures(context.Background(), b, pid, &tid, nil)
	if !errors.Is(err, ErrNotFound) || errors.Is(err, ErrNotInCloset) {
		t.Fatalf("missing texture error = %v, want only ErrNotFound", err)
	}
}

func TestSetTexturesTextureNotInCloset(t *testing.T) {
	service, id, store := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	pid := insertPlayer(t, store, 1, "NotInCloset")
	result, err := store.DB.Exec("INSERT INTO " + store.Table("textures") + " (name,type,hash,size,uploader,public,likes,upload_at) VALUES ('OutsideCloset','steve','outside-closet',1,2,1,0,'2026-01-01 00:00:00')")
	if err != nil {
		t.Fatal(err)
	}
	tid, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.SetTextures(context.Background(), b, pid, &tid, nil)
	if !errors.Is(err, ErrNotInCloset) || errors.Is(err, ErrNotFound) {
		t.Fatalf("non-closet texture error = %v, want only ErrNotInCloset", err)
	}
}

func TestAdminSetTextureDirect(t *testing.T) {
	env := equipEnv(t)
	admin := loginIdentity(t, env.id, "admin@example.invalid")
	pid := addPlayer(t, env, 1, "AdminEquip")
	result, err := env.store.DB.Exec("INSERT INTO " + env.store.Table("textures") + " (name,type,hash,size,uploader,public,likes,upload_at) VALUES ('T','steve','h1',1,1,1,1,'2026-01-01 00:00:00')")
	if err != nil {
		t.Fatal(err)
	}
	tid, _ := result.LastInsertId()
	if err = env.service.AdminSetTexture(context.Background(), admin, pid, tid, "skin"); err != nil {
		t.Fatal(err)
	}
	var skin int64
	env.store.DB.QueryRow("SELECT tid_skin FROM "+env.store.Table("players")+" WHERE pid=?", pid).Scan(&skin)
	if skin != tid {
		t.Fatalf("admin set texture = %d", skin)
	}
	if err = env.service.AdminSetTexture(context.Background(), admin, pid, 0, "skin"); err != nil {
		t.Fatal(err)
	}
	env.store.DB.QueryRow("SELECT tid_skin FROM "+env.store.Table("players")+" WHERE pid=?", pid).Scan(&skin)
	if skin != 0 {
		t.Fatalf("admin clear texture = %d", skin)
	}
	if err = env.service.AdminSetTexture(context.Background(), admin, pid, 9999, "skin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing texture error = %v", err)
	}
	if err = env.service.AdminSetTexture(context.Background(), admin, pid, tid, "cape"); !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("bad slot error = %v", err)
	}
}

type fakeAuthorizer struct {
	store         *database.Store
	expectVersion int64
}

func (f fakeAuthorizer) Recheck(ctx context.Context, tx *sql.Tx, creds GameAuth, pid int64) error {
	var version int64
	if err := tx.QueryRowContext(ctx, "SELECT version FROM "+f.store.Table("go_auth_versions")+" WHERE user_uid=?", creds.UID).Scan(&version); err != nil {
		return err
	}
	if version != creds.Version || version != f.expectVersion {
		return ErrStaleCredential
	}
	var owner int64
	if err := tx.QueryRowContext(ctx, "SELECT uid FROM "+f.store.Table("players")+" WHERE pid=?", pid).Scan(&owner); err != nil {
		return err
	}
	if owner != creds.UID {
		return ErrStaleCredential
	}
	return nil
}

func gameCreds(uid int64, profile string) GameAuth {
	return GameAuth{UID: uid, Version: 1, Permission: 0, Profile: profile}
}

func TestGameUploadPolicies(t *testing.T) {
	env := equipEnv(t)
	store := env.store
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=1000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	pid := addPlayer(t, env, 1, "GameSkin")
	payload := pngFixture(t, 64, 64, 64)
	source, written := stageFile(t, env, payload)
	authorizer := fakeAuthorizer{store: env.store, expectVersion: 1}
	result, err := env.service.GameUpload(context.Background(), gameCreds(1, "GameSkin"), authorizer, "skin", "default", "GameNew", source, written)
	if err != nil {
		t.Fatal(err)
	}
	if result.TID == 0 || result.Closet {
		t.Fatalf("game upload result %#v", result)
	}
	var public bool
	var likes, size int64
	store.DB.QueryRow("SELECT public,likes,size FROM "+store.Table("textures")+" WHERE tid=?", result.TID).Scan(&public, &likes, &size)
	if public || likes != 1 || size != (written+1023)/1024 {
		t.Fatalf("game texture public=%v likes=%d size=%d", public, likes, size)
	}
	wantCost := 10*size + 7
	if userScore(t, store, 1) != 1000-wantCost {
		t.Fatalf("game upload cost = %d", 1000-userScore(t, store, 1))
	}
	var skin int64
	store.DB.QueryRow("SELECT tid_skin FROM "+store.Table("players")+" WHERE pid=?", pid).Scan(&skin)
	if skin != result.TID {
		t.Fatalf("game upload did not equip: %d", skin)
	}
	// Same hash again with the closet entry present: no fee, same TID.
	source2, written2 := stageFile(t, env, payload)
	again, err := env.service.GameUpload(context.Background(), gameCreds(1, "GameSkin"), authorizer, "skin", "default", "GameNew", source2, written2)
	if err != nil {
		t.Fatal(err)
	}
	if again.TID != result.TID || userScore(t, store, 1) != 1000-wantCost {
		t.Fatalf("reuse charged or changed TID: %#v score=%d", again, userScore(t, store, 1))
	}
	// Missing closet entry: charge the closet fee once, no storage fee.
	if _, err = store.DB.Exec("DELETE FROM "+store.Table("user_closet")+" WHERE user_uid=1 AND texture_tid=?", result.TID); err != nil {
		t.Fatal(err)
	}
	before := userScore(t, store, 1)
	source3, written3 := stageFile(t, env, payload)
	if _, err = env.service.GameUpload(context.Background(), gameCreds(1, "GameSkin"), authorizer, "skin", "default", "GameNew", source3, written3); err != nil {
		t.Fatal(err)
	}
	if before-userScore(t, store, 1) != 7 {
		t.Fatalf("missing closet top-up charged %d", before-userScore(t, store, 1))
	}
	// Type/model conflict: the same bytes cannot become slim.
	source4, written4 := stageFile(t, env, payload)
	if _, err = env.service.GameUpload(context.Background(), gameCreds(1, "GameSkin"), authorizer, "skin", "slim", "GameNew", source4, written4); !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("model conflict error = %v", err)
	}
	// Nil verifier and stale/banned credentials are rejected.
	source5, written5 := stageFile(t, env, payload)
	if _, err = env.service.GameUpload(context.Background(), gameCreds(1, "GameSkin"), nil, "skin", "default", "X", source5, written5); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("nil authorizer error = %v", err)
	}
	banned := gameCreds(1, "GameSkin")
	banned.Banned = true
	source6, written6 := stageFile(t, env, payload)
	if _, err = env.service.GameUpload(context.Background(), banned, authorizer, "skin", "default", "X", source6, written6); !errors.Is(err, ErrStaleCredential) {
		t.Fatalf("banned credential error = %v", err)
	}
	// Reset clears the slot.
	if err = env.service.GameReset(context.Background(), gameCreds(1, "GameSkin"), authorizer, "skin"); err != nil {
		t.Fatal(err)
	}
	store.DB.QueryRow("SELECT tid_skin FROM "+store.Table("players")+" WHERE pid=?", pid).Scan(&skin)
	if skin != 0 {
		t.Fatalf("game reset left slot %d", skin)
	}
}

func TestGameUploadRollbackOnFailure(t *testing.T) {
	env := equipEnv(t)
	store := env.store
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=1000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	addPlayer(t, env, 1, "GameRollback")
	payload := pngFixture(t, 64, 64, 65)
	source, written := stageFile(t, env, payload)
	if _, err := store.DB.Exec("CREATE TRIGGER reject_game_charge BEFORE UPDATE ON " + store.Table("users") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic game charge fault'"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.service.GameUpload(context.Background(), gameCreds(1, "GameRollback"), fakeAuthorizer{store: store, expectVersion: 1}, "skin", "default", "GameFail", source, written); err == nil {
		t.Fatal("game charge failure ignored")
	}
	var texturesCount, closetCount int
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("textures")).Scan(&texturesCount)
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("user_closet")).Scan(&closetCount)
	if texturesCount != 0 || closetCount != 0 || userScore(t, store, 1) != 1000 {
		t.Fatalf("failed game upload textures=%d closet=%d score=%d", texturesCount, closetCount, userScore(t, store, 1))
	}
}

func loginIdentity(t *testing.T, id *identity.Service, email string) *identity.BrowserSession {
	t.Helper()
	b, err := id.Login(context.Background(), email, "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	return b
}
