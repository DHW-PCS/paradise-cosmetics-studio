package textures

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/testsupport"
)

func fixture(t *testing.T, overrides map[string]string) (*Service, *identity.Service, *database.Store, string) {
	t.Helper()
	store, id := testsupport.Database(t, "tex-")
	options := map[string]string{
		"score_per_storage":           "10",
		"private_score_per_storage":   "20",
		"score_per_closet_item":       "5",
		"score_award_per_texture":     "2",
		"max_upload_file_size":        "1024",
		"texture_name_regexp":         "",
		"allow_downloading_texture":   "true",
		"status_code_for_private":     "403",
		"reporter_score_modification": "0",
	}
	for key, value := range overrides {
		options[key] = value
	}
	view := &site.Service{Store: store, Identity: id, Location: time.FixedZone("site", 8*3600), OptionSnapshot: options}
	dir := t.TempDir()
	service := New(store, id, view, dir, func() time.Time { return time.Date(2026, 10, 30, 12, 0, 0, 0, time.FixedZone("site", 8*3600)) })
	return service, id, store, dir
}

func login(t *testing.T, id *identity.Service, email string) *identity.BrowserSession {
	t.Helper()
	b, err := id.Login(context.Background(), email, "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writePNG(t *testing.T, width, height int, seed byte) (string, int64) {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	for x := 0; x < width; x++ {
		for y := 0; y < height; y++ {
			img.SetNRGBA(x, y, color.NRGBA{R: uint8(x % 256), G: uint8(y % 256), B: seed, A: 255})
		}
	}
	var buffer bytes.Buffer
	if err := png.Encode(&buffer, img); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "original.png")
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, int64(buffer.Len())
}

func stage(t *testing.T, service *Service, path string) (string, int64) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	staged, written, err := service.StageUpload(bytes.NewReader(data), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return staged, written
}

func TestUploadChargesPublishesAndClosets(t *testing.T) {
	service, id, store, dir := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=1000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	original, size := writePNG(t, 64, 64, 1)
	source, written := stage(t, service, original)
	tid, err := service.Upload(context.Background(), UploadInput{Browser: b, Name: "MySkin", Type: "steve", Public: true, Source: source, Bytes: written})
	if err != nil {
		t.Fatal(err)
	}
	var name, kind, hash string
	var storedSize, uploader, likes int64
	var public bool
	if err := store.DB.QueryRow("SELECT name,type,hash,size,uploader,public,likes FROM "+store.Table("textures")+" WHERE tid=?", tid).
		Scan(&name, &kind, &hash, &storedSize, &uploader, &public, &likes); err != nil {
		t.Fatal(err)
	}
	if name != "MySkin" || kind != "steve" || !public || uploader != 1 || likes != 1 || storedSize != (written+1023)/1024 {
		t.Fatalf("row %q %q public=%v uploader=%d likes=%d size=%d", name, kind, public, uploader, likes, storedSize)
	}
	var score int64
	store.DB.QueryRow("SELECT score FROM " + store.Table("users") + " WHERE uid=1").Scan(&score)
	if want := int64(1000 - (1*10 + 5 - 2)); score != want {
		t.Fatalf("score=%d want %d (bytes=%d)", score, want, size)
	}
	var closetName string
	if err := store.DB.QueryRow("SELECT item_name FROM "+store.Table("user_closet")+" WHERE user_uid=1 AND texture_tid=?", tid).Scan(&closetName); err != nil || closetName != "MySkin" {
		t.Fatalf("closet item %q err=%v", closetName, err)
	}
	published := filepath.Join(dir, hash)
	data, err := os.ReadFile(published)
	if err != nil {
		t.Fatalf("published file missing: %v", err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != hash {
		t.Fatalf("published bytes changed: %x vs %s", sum, hash)
	}
}

func TestUploadConfiguredPCRE(t *testing.T) {
	service, id, store, _ := fixture(t, map[string]string{"texture_name_regexp": `/^(Skin)\1$/`})
	b := login(t, id, "user@example.invalid")
	path, size := writePNG(t, 64, 64, 17)
	if _, err := service.Upload(t.Context(), UploadInput{Browser: b, Name: "SkinCape", Type: "steve", Public: true, Source: path, Bytes: size}); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("rejected name: %v", err)
	}
	var count int
	if err := store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("textures")).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected upload wrote texture: %d, %v", count, err)
	}
	if _, err := service.Upload(t.Context(), UploadInput{Browser: b, Name: "SkinSkin", Type: "steve", Public: true, Source: path, Bytes: size}); err != nil {
		t.Fatalf("accepted PCRE: %v", err)
	}
}

func TestUploadDuplicateAndSharedHash(t *testing.T) {
	service, id, store, _ := fixture(t, nil)
	user := login(t, id, "user@example.invalid")
	admin := login(t, id, "admin@example.invalid")
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=1000 WHERE uid IN (1,2)"); err != nil {
		t.Fatal(err)
	}
	original, _ := writePNG(t, 64, 64, 2)
	// The owner uploads a private texture first: no public copy exists yet.
	source, written := stage(t, service, original)
	if _, err := service.Upload(context.Background(), UploadInput{Browser: user, Name: "PrivateOne", Type: "steve", Public: false, Source: source, Bytes: written}); err != nil {
		t.Fatal(err)
	}
	// Another user may publish the same bytes while the owner keeps them private.
	source, written = stage(t, service, original)
	if _, err := service.Upload(context.Background(), UploadInput{Browser: admin, Name: "PublicCopy", Type: "steve", Public: true, Source: source, Bytes: written}); err != nil {
		t.Fatalf("other user public copy rejected: %v", err)
	}
	// A public copy makes further uploads of the same hash duplicates.
	source, written = stage(t, service, original)
	var duplicate *DuplicateError
	if _, err := service.Upload(context.Background(), UploadInput{Browser: admin, Name: "PublicTwo", Type: "steve", Public: true, Source: source, Bytes: written}); !errors.As(err, &duplicate) {
		t.Fatalf("public duplicate error = %v", err)
	}
	source, written = stage(t, service, original)
	if _, err := service.Upload(context.Background(), UploadInput{Browser: user, Name: "PublicThree", Type: "steve", Public: true, Source: source, Bytes: written}); !errors.As(err, &duplicate) {
		t.Fatalf("owner public duplicate error = %v", err)
	}
	var privateCount, textureCount int
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("textures") + " WHERE public=0").Scan(&privateCount)
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("textures")).Scan(&textureCount)
	if privateCount != 1 || textureCount != 2 {
		t.Fatalf("private=%d textures=%d", privateCount, textureCount)
	}
}

func TestUploadValidationFailures(t *testing.T) {
	service, id, store, dir := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=1000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	original, _ := writePNG(t, 32, 32, 3)
	source, written := stage(t, service, original)
	var dimensions *DimensionError
	if _, err := service.Upload(context.Background(), UploadInput{Browser: b, Name: "Bad", Type: "steve", Public: true, Source: source, Bytes: written}); !errors.As(err, &dimensions) {
		t.Fatalf("dimension error = %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.png")
	os.WriteFile(bad, []byte("not a png"), 0o600)
	badSource, badBytes := stage(t, service, bad)
	if _, err := service.Upload(context.Background(), UploadInput{Browser: b, Name: "Bad", Type: "steve", Public: true, Source: badSource, Bytes: badBytes}); !errors.Is(err, ErrNotPNG) {
		t.Fatalf("png decode error = %v", err)
	}
	if _, err := service.Upload(context.Background(), UploadInput{Browser: b, Name: "Bad", Type: "steve", Public: true, Source: badSource, Bytes: 2 << 20}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("size error = %v", err)
	}
	// The decoded-pixel budget is separate from the byte limit.
	if _, err := validatePNG(writeOversizedPNG(t)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("pixel budget error = %v", err)
	}
	// Every dimension the production inventory recorded must be accepted.
	for _, dims := range [][2]int{{64, 32}, {64, 64}, {128, 128}, {1024, 512}, {2048, 1024}, {2048, 2048}, {4608, 2304}} {
		path, _ := writePNG(t, dims[0], dims[1], 7)
		if _, err := validatePNG(path); err != nil {
			t.Fatalf("%dx%d rejected: %v", dims[0], dims[1], err)
		}
	}
	var textures int
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("textures")).Scan(&textures)
	if textures != 0 {
		t.Fatalf("invalid uploads created rows: %d", textures)
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if entry.Name() != ".tmp" {
			t.Fatalf("invalid upload published %q", entry.Name())
		}
	}
}

func TestUploadConfiguredSize(t *testing.T) {
	for _, tc := range []struct {
		name, option string
		padding      int
		tooLarge     bool
	}{
		{"default", "", 0, false},
		{"zero", "0", 0, true},
		{"positive", "1", 0, false},
		{"over-limit", "1", 2048, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, id, _, _ := fixture(t, nil)
			if tc.option == "" {
				delete(s.Site.OptionSnapshot, "max_upload_file_size")
			} else {
				s.Site.OptionSnapshot["max_upload_file_size"] = tc.option
			}
			b := login(t, id, "user@example.invalid")
			original, _ := writePNG(t, 64, 64, 4)
			data, err := os.ReadFile(original)
			if err != nil {
				t.Fatal(err)
			}
			staged, written, err := s.StageUpload(bytes.NewReader(append(data, make([]byte, tc.padding)...)), 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.Upload(t.Context(), UploadInput{Browser: b, Name: "Sized", Type: "steve", Public: true, Source: staged, Bytes: written})
			if tc.tooLarge {
				if !errors.Is(err, ErrTooLarge) {
					t.Fatalf("upload size error=%v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUploadRenameFailureRollsBack(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	s, id, store, dir := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	original, _ := writePNG(t, 64, 64, 4)
	staged, written := stage(t, s, original)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	_, err := s.Upload(t.Context(), UploadInput{Browser: b, Name: "RenameFailure", Type: "steve", Public: true, Source: staged, Bytes: written})
	var linkErr *os.LinkError
	if !errors.As(err, &linkErr) || linkErr.Op != "rename" || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("rename failure=%v", err)
	}
	var count, score int
	if err := store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("textures")).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed publication textures=%d err=%v", count, err)
	}
	if err := store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("user_closet")).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed publication closet=%d err=%v", count, err)
	}
	if err := store.DB.QueryRow("SELECT score FROM " + store.Table("users") + " WHERE uid=1").Scan(&score); err != nil || score != 71 {
		t.Fatalf("failed publication score=%d err=%v", score, err)
	}
}

func TestUploadRollbackOnScoreFailure(t *testing.T) {
	service, id, store, dir := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=1000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	original, _ := writePNG(t, 64, 64, 4)
	source, written := stage(t, service, original)
	if _, err := store.DB.Exec("CREATE TRIGGER reject_texture_charge BEFORE UPDATE ON " + store.Table("users") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic upload charge fault'"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Upload(context.Background(), UploadInput{Browser: b, Name: "Rollback", Type: "steve", Public: true, Source: source, Bytes: written}); err == nil {
		t.Fatal("charge failure ignored")
	}
	var textures, closet int
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("textures")).Scan(&textures)
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("user_closet")).Scan(&closet)
	if textures != 0 || closet != 0 {
		t.Fatalf("failed upload left textures=%d closet=%d", textures, closet)
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if entry.Name() != ".tmp" {
			t.Fatalf("failed upload left published file %q", entry.Name())
		}
	}
}

func TestCollectRequiresZeroReferences(t *testing.T) {
	service, id, store, dir := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	original, _ := writePNG(t, 64, 64, 5)
	source, written := stage(t, service, original)
	tid, err := service.Upload(context.Background(), UploadInput{Browser: b, Name: "Collect", Type: "steve", Public: true, Source: source, Bytes: written})
	if err != nil {
		t.Fatal(err)
	}
	row, err := service.Get(context.Background(), tid)
	if err != nil {
		t.Fatal(err)
	}
	var generation int64
	store.DB.QueryRow("SELECT generation FROM "+store.Table("go_file_hashes")+" WHERE hash=?", row.Hash).Scan(&generation)
	// A referenced original must survive collection.
	if err := store.Transaction(context.Background(), func(tx *sql.Tx) error {
		removed, err := service.Collect(context.Background(), tx, row.Hash, generation)
		if err != nil {
			return err
		}
		if removed {
			t.Fatal("collected a referenced original")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A stale generation is obsolete.
	if _, err = store.DB.Exec("DELETE FROM "+store.Table("textures")+" WHERE tid=?", tid); err != nil {
		t.Fatal(err)
	}
	if err = store.Transaction(context.Background(), func(tx *sql.Tx) error {
		_, inner := service.Collect(context.Background(), tx, row.Hash, generation-1)
		return inner
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, row.Hash)); err != nil {
		t.Fatalf("stale generation removed file: %v", err)
	}
	// Current generation and zero references removes the original.
	var current int64
	store.DB.QueryRow("SELECT generation FROM "+store.Table("go_file_hashes")+" WHERE hash=?", row.Hash).Scan(&current)
	var removed bool
	if err = store.Transaction(context.Background(), func(tx *sql.Tx) error {
		var inner error
		removed, inner = service.Collect(context.Background(), tx, row.Hash, current)
		return inner
	}); err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("zero-reference original not collected")
	}
	if _, err = os.Stat(filepath.Join(dir, row.Hash)); !os.IsNotExist(err) {
		t.Fatalf("collected file still exists: %v", err)
	}
}

func TestLibraryFiltersAndVisibility(t *testing.T) {
	service, id, store, _ := fixture(t, nil)
	user := login(t, id, "user@example.invalid")
	admin := login(t, id, "admin@example.invalid")
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=1000 WHERE uid IN (1,2)"); err != nil {
		t.Fatal(err)
	}
	steve, _ := writePNG(t, 64, 64, 6)
	alex, _ := writePNG(t, 64, 64, 7)
	cape, _ := writePNG(t, 64, 32, 8)
	for _, item := range []struct {
		name, kind, path string
		public           bool
	}{
		{"StevePublic", "steve", steve, true},
		{"AlexPrivate", "alex", alex, false},
		{"CapePublic", "cape", cape, true},
	} {
		source, written := stage(t, service, item.path)
		if _, err := service.Upload(context.Background(), UploadInput{Browser: user, Name: item.name, Type: item.kind, Public: item.public, Source: source, Bytes: written}); err != nil {
			t.Fatal(err)
		}
	}
	anon, err := service.Library(context.Background(), nil, LibraryParams{Filter: "skin", Sort: "time", Page: 1}, "/skinlib/list", "/skinlib/list?page=")
	if err != nil {
		t.Fatal(err)
	}
	if anon.Total != 1 || anon.Data[0].Name != "StevePublic" {
		t.Fatalf("anonymous library %#v", anon.Data)
	}
	owner, err := service.Library(context.Background(), user.User, LibraryParams{Filter: "skin", Sort: "time", Page: 1}, "/skinlib/list", "/skinlib/list?page=")
	if err != nil {
		t.Fatal(err)
	}
	if owner.Total != 2 {
		t.Fatalf("owner library total = %d", owner.Total)
	}
	adminView, err := service.Library(context.Background(), admin.User, LibraryParams{Filter: "cape", Sort: "likes", Page: 1}, "/skinlib/list", "/skinlib/list?page=")
	if err != nil {
		t.Fatal(err)
	}
	if adminView.Total != 1 || adminView.Data[0].Name != "CapePublic" {
		t.Fatalf("cape filter %#v", adminView.Data)
	}
	keyword, err := service.Library(context.Background(), user.User, LibraryParams{Filter: "skin", Keyword: "Alex", Sort: "time", Page: 1}, "/skinlib/list", "/skinlib/list?page=")
	if err != nil {
		t.Fatal(err)
	}
	if keyword.Total != 1 || keyword.Data[0].Name != "AlexPrivate" {
		t.Fatalf("keyword filter %#v", keyword.Data)
	}
}

func TestGetMissingFileKeepsRow(t *testing.T) {
	service, _, store, dir := fixture(t, nil)
	b := login(t, service.Identity, "user@example.invalid")
	original, _ := writePNG(t, 64, 64, 9)
	source, written := stage(t, service, original)
	tid, err := service.Upload(context.Background(), UploadInput{Browser: b, Name: "Missing", Type: "steve", Public: true, Source: source, Bytes: written})
	if err != nil {
		t.Fatal(err)
	}
	row, _ := service.Get(context.Background(), tid)
	os.Remove(filepath.Join(dir, row.Hash))
	if available, err := service.FileAvailable(row.Hash); err != nil || available {
		t.Fatal("missing file reported available")
	}
	if _, err = service.Get(context.Background(), tid); err != nil {
		t.Fatalf("read deleted business row on missing file: %v", err)
	}
	var count int
	store.DB.QueryRow("SELECT COUNT(*) FROM "+store.Table("textures")+" WHERE tid=?", tid).Scan(&count)
	if count != 1 {
		t.Fatalf("missing file removed row: %d", count)
	}
}

func TestUploadRatesAndNegativeCost(t *testing.T) {
	service, id, store, _ := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=1000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	big, size := writePNG(t, 512, 512, 41)
	// Force a >1KiB payload through random-ish pixels.
	publishedBytes, _ := os.ReadFile(big)
	if size <= 1024 {
		t.Fatalf("fixture size %d not > 1KiB", size)
	}
	source, written := stage(t, service, big)
	if _, err := service.Upload(context.Background(), UploadInput{Browser: b, Name: "PrivateBig", Type: "steve", Public: false, Source: source, Bytes: written}); err != nil {
		t.Fatal(err)
	}
	want := int64(1000 - ((written+1023)/1024*20 + 5 - 2))
	if scoreOfUser(t, store, 1) != want {
		t.Fatalf("private 2KiB score = %d want %d", scoreOfUser(t, store, 1), want)
	}
	_ = publishedBytes
	// Negative cost: award larger than storage+closet increases the score.
	negService, negID, negStore, _ := fixture(t, map[string]string{"score_per_storage": "0", "score_per_closet_item": "0", "score_award_per_texture": "5"})
	negUser := login(t, negID, "user@example.invalid")
	if _, err := negStore.DB.Exec("UPDATE " + negStore.Table("users") + " SET score=100 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	negPath, negSize := writePNG(t, 64, 64, 42)
	negSource, negWritten := stage(t, negService, negPath)
	if _, err := negService.Upload(context.Background(), UploadInput{Browser: negUser, Name: "NegativeCost", Type: "steve", Public: true, Source: negSource, Bytes: negWritten}); err != nil {
		t.Fatal(err)
	}
	if scoreOfUser(t, negStore, 1) != 105 {
		t.Fatalf("negative cost score = %d", scoreOfUser(t, negStore, 1))
	}
	_ = negSize
}

func TestUploadLackScoreWritesNothing(t *testing.T) {
	service, id, store, dir := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=1 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	original, _ := writePNG(t, 64, 64, 43)
	source, written := stage(t, service, original)
	if _, err := service.Upload(context.Background(), UploadInput{Browser: b, Name: "NoScore", Type: "steve", Public: true, Source: source, Bytes: written}); !errors.Is(err, ErrLackScore) {
		t.Fatalf("lack score error = %v", err)
	}
	var textures, closet int
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("textures")).Scan(&textures)
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("user_closet")).Scan(&closet)
	if textures != 0 || closet != 0 || scoreOfUser(t, store, 1) != 1 {
		t.Fatalf("lack score side effects textures=%d closet=%d score=%d", textures, closet, scoreOfUser(t, store, 1))
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if entry.Name() != ".tmp" {
			t.Fatalf("lack score published %q", entry.Name())
		}
	}
}

func TestUploadAfterPublishFailureLeavesDiagnosableOrphan(t *testing.T) {
	service, id, store, dir := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=1000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	original, _ := writePNG(t, 64, 64, 44)
	source, written := stage(t, service, original)
	if _, err := store.DB.Exec("CREATE TRIGGER reject_generation AFTER UPDATE ON " + store.Table("go_file_hashes") + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic generation fault'"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Upload(context.Background(), UploadInput{Browser: b, Name: "AfterPublish", Type: "steve", Public: true, Source: source, Bytes: written}); err == nil {
		t.Fatal("generation failure ignored")
	}
	var textures int64
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("textures") + " WHERE name='AfterPublish'").Scan(&textures)
	if textures != 0 {
		t.Fatalf("failed upload committed texture rows: %d", textures)
	}
	if scoreOfUser(t, store, 1) != 1000 {
		t.Fatalf("failed upload charged score: %d", scoreOfUser(t, store, 1))
	}
	// The already published original remains as a diagnosable orphan.
	entries, _ := os.ReadDir(dir)
	orphans := 0
	for _, entry := range entries {
		if entry.Name() != ".tmp" {
			orphans++
		}
	}
	if orphans != 1 {
		t.Fatalf("expected one diagnosable orphan, got %d", orphans)
	}
}

func TestConcurrentFirstPublisherSameHash(t *testing.T) {
	service, id, store, _ := fixture(t, nil)
	user := login(t, id, "user@example.invalid")
	admin := login(t, id, "admin@example.invalid")
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=1000 WHERE uid IN (1,2)"); err != nil {
		t.Fatal(err)
	}
	original, _ := writePNG(t, 64, 64, 45)
	var wg sync.WaitGroup
	wg.Add(2)
	errs := make([]error, 2)
	for i, browser := range []*identity.BrowserSession{user, admin} {
		go func(index int, b *identity.BrowserSession) {
			defer wg.Done()
			source, written := stage(t, service, original)
			_, errs[index] = service.Upload(context.Background(), UploadInput{Browser: b, Name: "Concurrent" + strconv.Itoa(index), Type: "steve", Public: true, Source: source, Bytes: written})
		}(i, browser)
	}
	wg.Wait()
	success, duplicates := 0, 0
	for _, err := range errs {
		var duplicate *DuplicateError
		if err == nil {
			success++
		} else if errors.As(err, &duplicate) {
			duplicates++
		} else {
			t.Fatalf("unexpected concurrent upload error: %v", err)
		}
	}
	if success != 1 || duplicates != 1 {
		t.Fatalf("success=%d duplicates=%d (%v)", success, duplicates, errs)
	}
	var textures int
	store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("textures")).Scan(&textures)
	if textures != 1 {
		t.Fatalf("textures after concurrent first publish = %d", textures)
	}
}

func TestImageVariantsAndCollectionFailure(t *testing.T) {
	service, id, store, dir := fixture(t, nil)
	b := login(t, id, "user@example.invalid")
	if _, err := store.DB.Exec("UPDATE " + store.Table("users") + " SET score=5000 WHERE uid=1"); err != nil {
		t.Fatal(err)
	}
	// Palette PNG is a valid original.
	paletted := image.NewPaletted(image.Rect(0, 0, 64, 64), color.Palette{color.Black, color.White})
	for i := range paletted.Pix {
		paletted.Pix[i] = uint8(i % 2)
	}
	var buffer bytes.Buffer
	png.Encode(&buffer, paletted)
	path := filepath.Join(t.TempDir(), "palette.png")
	os.WriteFile(path, buffer.Bytes(), 0o600)
	source, written := stage(t, service, path)
	if _, err := service.Upload(context.Background(), UploadInput{Browser: b, Name: "Palette", Type: "steve", Public: true, Source: source, Bytes: written}); err != nil {
		t.Fatalf("palette png rejected: %v", err)
	}
	// Truncated PNG is rejected before any write.
	truncated := filepath.Join(t.TempDir(), "truncated.png")
	os.WriteFile(truncated, buffer.Bytes()[:len(buffer.Bytes())/2], 0o600)
	badSource, badBytes := stage(t, service, truncated)
	if _, err := service.Upload(context.Background(), UploadInput{Browser: b, Name: "Truncated", Type: "steve", Public: true, Source: badSource, Bytes: badBytes}); !errors.Is(err, ErrNotPNG) {
		t.Fatalf("truncated png error = %v", err)
	}
	// Alex must be square and a cape 2:1.
	alex, _ := writePNG(t, 64, 32, 46)
	alexSource, alexBytes := stage(t, service, alex)
	var dimensions *DimensionError
	if _, err := service.Upload(context.Background(), UploadInput{Browser: b, Name: "BadAlex", Type: "alex", Public: true, Source: alexSource, Bytes: alexBytes}); !errors.As(err, &dimensions) {
		t.Fatalf("alex ratio error = %v", err)
	}
	cape, _ := writePNG(t, 64, 64, 47)
	capeSource, capeBytes := stage(t, service, cape)
	if _, err := service.Upload(context.Background(), UploadInput{Browser: b, Name: "BadCape", Type: "cape", Public: true, Source: capeSource, Bytes: capeBytes}); !errors.As(err, &dimensions) {
		t.Fatalf("cape ratio error = %v", err)
	}
	// Collection fails on an unreadable directory and stays retryable.
	row, err := service.Get(context.Background(), mustTID(t, store, "Palette"))
	if err != nil {
		t.Fatal(err)
	}
	var generation int64
	store.DB.QueryRow("SELECT generation FROM "+store.Table("go_file_hashes")+" WHERE hash=?", row.Hash).Scan(&generation)
	if _, err = store.DB.Exec("DELETE FROM "+store.Table("textures")+" WHERE tid=?", row.TID); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	if err = store.Transaction(context.Background(), func(tx *sql.Tx) error {
		_, inner := service.Collect(context.Background(), tx, row.Hash, generation)
		return inner
	}); err == nil {
		t.Fatalf("unlink failure ignored")
	}
	os.Chmod(dir, 0o700)
}

func mustTID(t *testing.T, store *database.Store, name string) int64 {
	t.Helper()
	var tid int64
	if err := store.DB.QueryRow("SELECT tid FROM "+store.Table("textures")+" WHERE name=?", name).Scan(&tid); err != nil {
		t.Fatal(err)
	}
	return tid
}

func scoreOfUser(t *testing.T, store *database.Store, uid int64) int64 {
	t.Helper()
	var value int64
	if err := store.DB.QueryRow("SELECT score FROM "+store.Table("users")+" WHERE uid=?", uid).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

// writeOversizedPNG writes a header claiming dimensions past the pixel budget.
// Only the signature and IHDR are needed: validatePNG checks the budget after
// DecodeConfig and before decoding pixels, which is the point of the budget.
func writeOversizedPNG(t *testing.T) string {
	t.Helper()
	width, height := 8192, 8192
	var buffer bytes.Buffer
	buffer.Write([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], uint32(width))
	binary.BigEndian.PutUint32(ihdr[4:8], uint32(height))
	ihdr[8] = 8 // bit depth
	ihdr[9] = 6 // RGBA
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(ihdr)))
	buffer.Write(length)
	buffer.WriteString("IHDR")
	buffer.Write(ihdr)
	checksum := crc32.ChecksumIEEE(append([]byte("IHDR"), ihdr...))
	binary.Write(&buffer, binary.BigEndian, checksum)
	path := filepath.Join(t.TempDir(), "oversized.png")
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
