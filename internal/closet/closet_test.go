package closet

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/database"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/players"
	"paradise-cosmetics-studio/internal/site"
	"paradise-cosmetics-studio/internal/testsupport"
	"paradise-cosmetics-studio/internal/textures"
)

type fixtureEnv struct {
	service  *Service
	textures *textures.Service
	id       *identity.Service
	store    *database.Store
	dir      string
}

func fixture(t *testing.T, overrides map[string]string) fixtureEnv {
	t.Helper()
	store, id := testsupport.Database(t, "closet-")
	options := map[string]string{
		"score_per_storage": "10", "private_score_per_storage": "20", "score_per_closet_item": "7",
		"score_award_per_texture": "2", "score_award_per_like": "3", "return_score": "true",
		"take_back_scores_after_deletion": "true", "texture_name_regexp": "", "max_upload_file_size": "1024",
	}
	for key, value := range overrides {
		options[key] = value
	}
	view := &site.Service{Store: store, Identity: id, Location: time.FixedZone("site", 8*3600), OptionSnapshot: options}
	dir := t.TempDir()
	now := func() time.Time { return time.Date(2026, 10, 30, 12, 0, 0, 0, time.FixedZone("site", 8*3600)) }
	tex := textures.New(store, id, view, dir, now)
	pl := players.New(store, id, view, now)
	return fixtureEnv{service: New(store, id, view, tex, pl, now), textures: tex, id: id, store: store, dir: dir}
}

func login(t *testing.T, id *identity.Service, email string) *identity.BrowserSession {
	t.Helper()
	b, err := id.Login(context.Background(), email, "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func pngBytes(t *testing.T, width, height int, seed byte) []byte {
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

func uploadTexture(t *testing.T, env fixtureEnv, b *identity.BrowserSession, name, kind string, public bool, seed byte) int64 {
	t.Helper()
	payload := pngBytes(t, 64, 64, seed)
	if kind == "cape" {
		payload = pngBytes(t, 64, 32, seed)
	}
	path := filepath.Join(t.TempDir(), "up.png")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	staged, written, err := env.textures.StageUpload(file, 1<<20)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	tid, err := env.textures.Upload(context.Background(), textures.UploadInput{Browser: b, Name: name, Type: kind, Public: public, Source: staged, Bytes: written})
	if err != nil {
		t.Fatal(err)
	}
	return tid
}

func scoreOf(t *testing.T, store *database.Store, uid int64) int64 {
	t.Helper()
	var score int64
	if err := store.DB.QueryRow("SELECT score FROM "+store.Table("users")+" WHERE uid=?", uid).Scan(&score); err != nil {
		t.Fatal(err)
	}
	return score
}

func TestClosetAddRemoveRewardsAndSlots(t *testing.T) {
	env := fixture(t, nil)
	owner := login(t, env.id, "user@example.invalid")
	admin := login(t, env.id, "admin@example.invalid")
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET score=1000 WHERE uid IN (1,2)"); err != nil {
		t.Fatal(err)
	}
	tid := uploadTexture(t, env, owner, "ClosetSkin", "steve", true, 3)
	ownerScore := scoreOf(t, env.store, 1)
	if err := env.service.Add(context.Background(), admin, tid, "AdminPick"); err != nil {
		t.Fatal(err)
	}
	if scoreOf(t, env.store, 1) != ownerScore+3 {
		t.Fatalf("uploader reward not paid: %d -> %d", ownerScore, scoreOf(t, env.store, 1))
	}
	var likes int64
	env.store.DB.QueryRow("SELECT likes FROM "+env.store.Table("textures")+" WHERE tid=?", tid).Scan(&likes)
	if likes != 2 {
		t.Fatalf("likes after add = %d", likes)
	}
	// Give the admin a player referencing the texture to check slot clearing.
	if _, err := env.store.DB.Exec("INSERT INTO "+env.store.Table("players")+" (uid,name,tid_skin,last_modified) VALUES (2,'AdminPlayer',?,'2026-01-01 00:00:00')", tid); err != nil {
		t.Fatal(err)
	}
	adminScore := scoreOf(t, env.store, 2)
	if err := env.service.Remove(context.Background(), admin, tid); err != nil {
		t.Fatal(err)
	}
	if scoreOf(t, env.store, 2) != adminScore+7 {
		t.Fatalf("closet fee not refunded: %d -> %d", adminScore, scoreOf(t, env.store, 2))
	}
	if scoreOf(t, env.store, 1) != ownerScore {
		t.Fatalf("uploader reward not revoked: %d", scoreOf(t, env.store, 1))
	}
	var skin int64
	env.store.DB.QueryRow("SELECT tid_skin FROM " + env.store.Table("players") + " WHERE uid=2").Scan(&skin)
	if skin != 0 {
		t.Fatalf("removed closet item kept player slot %d", skin)
	}
	env.store.DB.QueryRow("SELECT likes FROM "+env.store.Table("textures")+" WHERE tid=?", tid).Scan(&likes)
	if likes != 1 {
		t.Fatalf("likes after remove = %d", likes)
	}
}

func TestClosetAddValidation(t *testing.T) {
	env := fixture(t, nil)
	user := login(t, env.id, "user@example.invalid")
	admin := login(t, env.id, "admin@example.invalid")
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET score=1000 WHERE uid IN (1,2)"); err != nil {
		t.Fatal(err)
	}
	privateTID := uploadTexture(t, env, user, "PrivateSkin", "steve", false, 5)
	if _, err := env.store.DB.Exec("INSERT INTO " + env.store.Table("users") + " (uid,email,nickname,password,permission,verified,score) SELECT 3,'third@example.invalid','Third',password,0,1,1000 FROM " + env.store.Table("users") + " WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.DB.Exec("INSERT INTO " + env.store.Table("go_auth_versions") + " (user_uid,version) VALUES (3,1)"); err != nil {
		t.Fatal(err)
	}
	third := login(t, env.id, "third@example.invalid")
	if err := env.service.Add(context.Background(), third, privateTID, "Nope"); !errors.Is(err, ErrPrivate) {
		t.Fatalf("private add error = %v", err)
	}
	// Admins keep the frozen ability to add private textures they can see.
	if err := env.service.Add(context.Background(), admin, privateTID, "AdminPick"); err != nil {
		t.Fatalf("admin private add error = %v", err)
	}
	if err := env.service.Add(context.Background(), admin, 99999, "Nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing texture error = %v", err)
	}
	publicTID := uploadTexture(t, env, user, "PublicSkin", "steve", true, 6)
	if err := env.service.Add(context.Background(), admin, publicTID, "Pick"); err != nil {
		t.Fatal(err)
	}
	if err := env.service.Add(context.Background(), admin, publicTID, "Pick"); !errors.Is(err, ErrRepeated) {
		t.Fatalf("duplicate add error = %v", err)
	}
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET score=0 WHERE uid=2"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.DB.Exec("INSERT INTO " + env.store.Table("textures") + " (name,type,hash,size,uploader,public,likes,upload_at) VALUES ('NoScoreSkin','steve','noscoreskin',1,1,1,1,'2026-01-01 00:00:00')"); err != nil {
		t.Fatal(err)
	}
	var other int64
	env.store.DB.QueryRow("SELECT tid FROM " + env.store.Table("textures") + " WHERE name='NoScoreSkin'").Scan(&other)
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET score=0 WHERE uid=3"); err != nil {
		t.Fatal(err)
	}
	if err := env.service.Add(context.Background(), login(t, env.id, "third@example.invalid"), other, "Pick"); !errors.Is(err, ErrLackScore) {
		t.Fatalf("lack score error = %v", err)
	}
}

func TestAdminClosetIdempotentAndRewardConsumption(t *testing.T) {
	env := fixture(t, nil)
	owner := login(t, env.id, "user@example.invalid")
	admin := login(t, env.id, "admin@example.invalid")
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET score=1000 WHERE uid IN (1,2)"); err != nil {
		t.Fatal(err)
	}
	tid := uploadTexture(t, env, owner, "AdminCloset", "steve", true, 8)
	if err := env.service.Add(context.Background(), admin, tid, "AdminPick"); err != nil {
		t.Fatal(err)
	}
	ownerBefore := scoreOf(t, env.store, 1)
	adminBefore := scoreOf(t, env.store, 2)
	if _, err := env.service.AdminAdd(context.Background(), admin, 1, tid); err != nil {
		t.Fatal(err)
	}
	if _, err := env.service.AdminAdd(context.Background(), admin, 1, tid); err != nil {
		t.Fatalf("admin add is not idempotent: %v", err)
	}
	var pivots, likes int64
	env.store.DB.QueryRow("SELECT COUNT(*) FROM "+env.store.Table("user_closet")+" WHERE user_uid=1 AND texture_tid=?", tid).Scan(&pivots)
	env.store.DB.QueryRow("SELECT likes FROM "+env.store.Table("textures")+" WHERE tid=?", tid).Scan(&likes)
	if pivots != 1 || likes != 2 {
		t.Fatalf("admin add changed counts pivots=%d likes=%d", pivots, likes)
	}
	if scoreOf(t, env.store, 1) != ownerBefore || scoreOf(t, env.store, 2) != adminBefore {
		t.Fatal("admin add moved scores")
	}
	// Admin detach consumes the admin's reward record without moving money.
	if _, err := env.service.AdminRemove(context.Background(), admin, 2, tid); err != nil {
		t.Fatal(err)
	}
	if scoreOf(t, env.store, 1) != ownerBefore || scoreOf(t, env.store, 2) != adminBefore {
		t.Fatal("admin remove moved scores")
	}
	var active int64
	env.store.DB.QueryRow("SELECT COUNT(*) FROM "+env.store.Table("go_closet_rewards")+" WHERE user_uid=2 AND texture_tid=? AND active=1", tid).Scan(&active)
	if active != 0 {
		t.Fatalf("admin remove left active reward %d", active)
	}
	if err := env.service.Remove(context.Background(), admin, tid); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove after admin detach error = %v", err)
	}
	if scoreOf(t, env.store, 1) != ownerBefore {
		t.Fatal("removed reward was revoked twice")
	}
}

func TestPrivacyTransitionCleansOtherUsers(t *testing.T) {
	env := fixture(t, nil)
	owner := login(t, env.id, "user@example.invalid")
	admin := login(t, env.id, "admin@example.invalid")
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET score=1000 WHERE uid IN (1,2)"); err != nil {
		t.Fatal(err)
	}
	tid := uploadTexture(t, env, owner, "PrivacySkin", "steve", true, 9)
	if err := env.service.Add(context.Background(), admin, tid, "Pick"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.DB.Exec("INSERT INTO "+env.store.Table("players")+" (uid,name,tid_skin,last_modified) VALUES (2,'PrivacyPlayer',?,'2026-01-01 00:00:00')", tid); err != nil {
		t.Fatal(err)
	}
	ownerScore := scoreOf(t, env.store, 1)
	adminScore := scoreOf(t, env.store, 2)
	public, err := env.service.SetPrivacy(context.Background(), owner, tid)
	if err != nil || public {
		t.Fatalf("privacy transition %v %v", public, err)
	}
	// Owner price difference: private 1KiB costs 10 more, award 2 taken back.
	if scoreOf(t, env.store, 1) != ownerScore-12 {
		t.Fatalf("owner privacy diff = %d", ownerScore-scoreOf(t, env.store, 1))
	}
	var pivots int64
	env.store.DB.QueryRow("SELECT COUNT(*) FROM "+env.store.Table("user_closet")+" WHERE texture_tid=?", tid).Scan(&pivots)
	if pivots != 1 {
		t.Fatalf("other closets not cleaned: %d", pivots)
	}
	if scoreOf(t, env.store, 2) != adminScore+7 {
		t.Fatalf("other user closet refund = %d", scoreOf(t, env.store, 2)-adminScore)
	}
	var skin int64
	env.store.DB.QueryRow("SELECT tid_skin FROM " + env.store.Table("players") + " WHERE uid=2").Scan(&skin)
	if skin != 0 {
		t.Fatalf("other player slot not cleared: %d", skin)
	}
	// The owner keeps the texture in its own closet: only other users were
	// cleaned. Turning it public again is allowed while no public copy exists.
	if _, err := env.service.SetPrivacy(context.Background(), owner, tid); err != nil {
		t.Fatalf("privacy back to public failed: %v", err)
	}
	// A public same-hash copy blocks a private texture from becoming public.
	if _, err := env.store.DB.Exec("UPDATE "+env.store.Table("textures")+" SET public=0 WHERE tid=?", tid); err != nil {
		t.Fatal(err)
	}
	var hash string
	env.store.DB.QueryRow("SELECT hash FROM "+env.store.Table("textures")+" WHERE tid=?", tid).Scan(&hash)
	result, err := env.store.DB.Exec("INSERT INTO "+env.store.Table("textures")+" (name,type,hash,size,uploader,public,likes,upload_at) VALUES ('Copy','steve',?,1,2,1,1,'2026-01-01 00:00:00')", hash)
	if err != nil {
		t.Fatal(err)
	}
	copyTID, _ := result.LastInsertId()
	var duplicate *DuplicateTexture
	if _, err = env.service.SetPrivacy(context.Background(), owner, tid); !errors.As(err, &duplicate) || duplicate.TID != copyTID {
		t.Fatalf("public copy conflict = %v %#v", err, duplicate)
	}
}

func TestDeleteTextureSideEffectsAndFileCollection(t *testing.T) {
	for _, entry := range []string{"browser", "actor"} {
		t.Run(entry, func(t *testing.T) {
			env := fixture(t, nil)
			owner := login(t, env.id, "user@example.invalid")
			admin := login(t, env.id, "admin@example.invalid")
			if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET score=1000 WHERE uid IN (1,2)"); err != nil {
				t.Fatal(err)
			}
			tid := uploadTexture(t, env, owner, "DeleteSkin", "steve", true, 11)
			if err := env.service.Add(context.Background(), admin, tid, "Pick"); err != nil {
				t.Fatal(err)
			}
			if _, err := env.store.DB.Exec("INSERT INTO "+env.store.Table("players")+" (uid,name,tid_skin,last_modified) VALUES (1,'OwnerPlayer',?,'2026-01-01 00:00:00'),(2,'AdminPlayer',?,'2026-01-01 00:00:00')", tid, tid); err != nil {
				t.Fatal(err)
			}
			var hash string
			var size int64
			env.store.DB.QueryRow("SELECT hash,size FROM "+env.store.Table("textures")+" WHERE tid=?", tid).Scan(&hash, &size)
			ownerScore := scoreOf(t, env.store, 1)
			adminScore := scoreOf(t, env.store, 2)
			if err := deleteTextureEntryForTest(t, env, admin, tid, entry); err != nil {
				t.Fatal(err)
			}
			if scoreOf(t, env.store, 1) != ownerScore+size*10-2 {
				t.Fatalf("uploader delete refund = %d, want %d", scoreOf(t, env.store, 1), ownerScore+size*10-2)
			}
			if scoreOf(t, env.store, 2) != adminScore+7 {
				t.Fatalf("other user closet refund = %d", scoreOf(t, env.store, 2)-adminScore)
			}
			var pivots, playersLeft, texturesLeft int64
			env.store.DB.QueryRow("SELECT COUNT(*) FROM "+env.store.Table("user_closet")+" WHERE texture_tid=?", tid).Scan(&pivots)
			env.store.DB.QueryRow("SELECT COUNT(*) FROM "+env.store.Table("players")+" WHERE tid_skin=?", tid).Scan(&playersLeft)
			env.store.DB.QueryRow("SELECT COUNT(*) FROM "+env.store.Table("textures")+" WHERE tid=?", tid).Scan(&texturesLeft)
			if pivots != 0 || playersLeft != 0 || texturesLeft != 0 {
				t.Fatalf("delete cleanup pivots=%d players=%d textures=%d", pivots, playersLeft, texturesLeft)
			}
			// The file is still present until the collector observes zero references.
			if _, err := os.Stat(filepath.Join(env.dir, hash)); err != nil {
				t.Fatalf("file removed before collector: %v", err)
			}
			var payload string
			if err := env.store.DB.QueryRow("SELECT payload FROM " + env.store.Table("go_outbox") + " WHERE topic='texture.collect' ORDER BY id DESC LIMIT 1").Scan(&payload); err != nil {
				t.Fatalf("collect task missing: %v", err)
			}
		})
	}
}

func TestClosetRenameAndTextureRenameSeparation(t *testing.T) {
	env := fixture(t, nil)
	owner := login(t, env.id, "user@example.invalid")
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET score=1000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	tid := uploadTexture(t, env, owner, "OriginalName", "steve", true, 12)
	if err := env.service.Rename(context.Background(), owner, tid, "MyItemName"); err != nil {
		t.Fatal(err)
	}
	if err := env.service.RenameTexture(context.Background(), owner, tid, "RenamedTexture"); err != nil {
		t.Fatal(err)
	}
	var itemName, textureName string
	env.store.DB.QueryRow("SELECT item_name FROM "+env.store.Table("user_closet")+" WHERE user_uid=1 AND texture_tid=?", tid).Scan(&itemName)
	env.store.DB.QueryRow("SELECT name FROM "+env.store.Table("textures")+" WHERE tid=?", tid).Scan(&textureName)
	if itemName != "MyItemName" || textureName != "RenamedTexture" {
		t.Fatalf("item=%q texture=%q", itemName, textureName)
	}
	if err := env.service.Rename(context.Background(), owner, 99999, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing pivot rename error = %v", err)
	}
}

func TestTextureRenameConfiguredPCRE(t *testing.T) {
	env := fixture(t, map[string]string{"texture_name_regexp": `/^(Skin|Cape)\1$/`})
	owner := login(t, env.id, "user@example.invalid")
	tid := uploadTexture(t, env, owner, "SkinSkin", "steve", true, 19)
	if err := env.service.RenameTexture(t.Context(), owner, tid, "SkinCape"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("rejected name: %v", err)
	}
	var name string
	if err := env.store.DB.QueryRow("SELECT name FROM "+env.store.Table("textures")+" WHERE tid=?", tid).Scan(&name); err != nil || name != "SkinSkin" {
		t.Fatalf("rejected rename wrote name: %q, %v", name, err)
	}
	if err := env.service.RenameTexture(t.Context(), owner, tid, "CapeCape"); err != nil {
		t.Fatalf("accepted name: %v", err)
	}
}

func TestClosetConcurrentAddAndRemoveAreSingleEffect(t *testing.T) {
	env := fixture(t, nil)
	owner := login(t, env.id, "user@example.invalid")
	admin := login(t, env.id, "admin@example.invalid")
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET score=1000 WHERE uid IN (1,2)"); err != nil {
		t.Fatal(err)
	}
	tid := uploadTexture(t, env, owner, "RaceCloset", "steve", true, 71)
	before := scoreOf(t, env.store, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		go func(index int) {
			defer wg.Done()
			errs[index] = env.service.Add(context.Background(), admin, tid, "Race")
		}(i)
	}
	wg.Wait()
	success := 0
	for _, err := range errs {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrRepeated) {
			t.Fatalf("unexpected add error: %v", err)
		}
	}
	if success != 1 {
		t.Fatalf("concurrent add successes = %d errors=%v", success, errs)
	}
	if scoreOf(t, env.store, 2) != before-7 {
		t.Fatalf("concurrent add charged %d", before-scoreOf(t, env.store, 2))
	}
	var pivots, likes int64
	if err := env.store.DB.QueryRow("SELECT COUNT(*) FROM "+env.store.Table("user_closet")+" WHERE user_uid=2 AND texture_tid=?", tid).Scan(&pivots); err != nil {
		t.Fatalf("pivot scan: %v", err)
	}
	if err := env.store.DB.QueryRow("SELECT likes FROM "+env.store.Table("textures")+" WHERE tid=?", tid).Scan(&likes); err != nil {
		t.Fatalf("likes scan: %v", err)
	}
	if pivots != 1 || likes != 2 {
		t.Fatalf("concurrent add state tid=%d pivots=%d likes=%d errs=%v", tid, pivots, likes, errs)
	}
	// Concurrent removes must refund exactly once.
	before = scoreOf(t, env.store, 2)
	errs = make([]error, 2)
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func(index int) {
			defer wg.Done()
			errs[index] = env.service.Remove(context.Background(), admin, tid)
		}(i)
	}
	wg.Wait()
	success = 0
	for _, err := range errs {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrNotFound) {
			t.Fatalf("unexpected remove error: %v", err)
		}
	}
	if success != 1 || scoreOf(t, env.store, 2) != before+7 {
		t.Fatalf("concurrent remove success=%d refund=%d errors=%v", success, scoreOf(t, env.store, 2)-before, errs)
	}
}

func TestUploaderDeletedStillAllowsClosetAndDelete(t *testing.T) {
	env := fixture(t, nil)
	admin := login(t, env.id, "admin@example.invalid")
	if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET score=1000 WHERE uid IN (1,2)"); err != nil {
		t.Fatal(err)
	}
	result, err := env.store.DB.Exec("INSERT INTO " + env.store.Table("textures") + " (name,type,hash,size,uploader,public,likes,upload_at) VALUES ('Orphan','steve','orphanhash',1,999,1,1,'2026-01-01 00:00:00')")
	if err != nil {
		t.Fatal(err)
	}
	tid, _ := result.LastInsertId()
	if err = env.service.Add(context.Background(), admin, tid, "Pick"); err != nil {
		t.Fatalf("add with deleted uploader: %v", err)
	}
	before := scoreOf(t, env.store, 2)
	if err = env.service.Remove(context.Background(), admin, tid); err != nil {
		t.Fatalf("remove with deleted uploader: %v", err)
	}
	if scoreOf(t, env.store, 2) != before+7 {
		t.Fatalf("remove refund with deleted uploader = %d", scoreOf(t, env.store, 2)-before)
	}
	if err = env.service.DeleteTexture(context.Background(), admin, tid); err != nil {
		t.Fatalf("delete with deleted uploader: %v", err)
	}
	var count int
	env.store.DB.QueryRow("SELECT COUNT(*) FROM " + env.store.Table("textures") + " WHERE tid=?").Scan(&count)
	if count != 0 {
		t.Fatalf("deleted texture with missing uploader remained: %d", count)
	}
}

func TestDeleteRollbackOnRefundFailure(t *testing.T) {
	for _, entry := range []string{"browser", "actor"} {
		t.Run(entry, func(t *testing.T) {
			env := fixture(t, nil)
			owner := login(t, env.id, "user@example.invalid")
			admin := login(t, env.id, "admin@example.invalid")
			if _, err := env.store.DB.Exec("UPDATE " + env.store.Table("users") + " SET score=1000 WHERE uid IN (1,2)"); err != nil {
				t.Fatal(err)
			}
			tid := uploadTexture(t, env, owner, "DeleteRollback", "steve", true, 72)
			if err := env.service.Add(context.Background(), admin, tid, "Pick"); err != nil {
				t.Fatal(err)
			}
			if _, err := env.store.DB.Exec("CREATE TRIGGER reject_delete_refund BEFORE UPDATE ON " + env.store.Table("users") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic closet refund fault'"); err != nil {
				t.Fatal(err)
			}
			if err := deleteTextureEntryForTest(t, env, admin, tid, entry); err == nil {
				t.Fatal("refund failure ignored")
			}
			var textures, pivots int64
			if err := env.store.DB.QueryRow("SELECT COUNT(*) FROM "+env.store.Table("textures")+" WHERE tid=?", tid).Scan(&textures); err != nil {
				t.Fatalf("texture count: %v", err)
			}
			if err := env.store.DB.QueryRow("SELECT COUNT(*) FROM "+env.store.Table("user_closet")+" WHERE texture_tid=?", tid).Scan(&pivots); err != nil {
				t.Fatalf("pivot count: %v", err)
			}
			if textures != 1 || pivots != 2 {
				t.Fatalf("failed delete left textures=%d pivots=%d", textures, pivots)
			}
			_ = admin
		})
	}
}

func TestClosetPageSizeHasNoArbitraryCeiling(t *testing.T) {
	env := fixture(t, map[string]string{"score_per_storage": "0", "score_per_closet_item": "0", "score_award_per_texture": "0"})
	b := login(t, env.id, "user@example.invalid")
	uploadTexture(t, env, b, "First", "steve", true, 211)
	uploadTexture(t, env, b, "Second", "steve", true, 212)
	for _, size := range []int{201, int(^uint(0) >> 1)} {
		page, err := env.service.List(t.Context(), b, "skin", "", 1, size, "http://localhost/skin/user/closet/list")
		if err != nil {
			t.Fatal(err)
		}
		items, _ := page.Data.([]Item)
		if page.PerPage != size || page.LastPage != 1 || page.Total != 2 || len(items) != 2 {
			t.Fatalf("invalid large-page pagination: perPage=%d last=%d total=%d", page.PerPage, page.LastPage, page.Total)
		}
	}
}
