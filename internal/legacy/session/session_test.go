package session

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"blessing-skin-go/internal/legacy/laravel"
	"blessing-skin-go/internal/legacy/php"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStore(dir, 120*time.Minute)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

func TestWriteReadRoundTrip(t *testing.T) {
	store := newTestStore(t)
	id, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	if !ValidID(id) {
		t.Fatalf("NewID produced invalid id %q", id)
	}
	attrs := NewPayload("login_web_x", 7, "token", "http://example.invalid/user")
	if err := store.Write(id, attrs); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := store.Read(id)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if uid, ok := LoginUID(got, "login_web_x"); !ok || uid != 7 {
		t.Fatalf("uid = %d, %v", uid, ok)
	}
	if token, ok := CSRF(got); !ok || token != "token" {
		t.Fatalf("csrf = %q, %v", token, ok)
	}
	// File format must match PHP's serialize() shape.
	raw, err := os.ReadFile(filepath.Join(store.Dir, id))
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if !strings.HasPrefix(string(raw), "a:4:{") || !strings.Contains(string(raw), `s:11:"login_web_x";i:7;`) {
		t.Fatalf("unexpected payload: %s", raw)
	}
}

func TestExpiryUsesFileMtime(t *testing.T) {
	store := newTestStore(t)
	id, _ := NewID()
	if err := store.Write(id, NewPayload("login_web_x", 1, "t", "/")); err != nil {
		t.Fatal(err)
	}
	store.Now = func() time.Time { return time.Now().Add(121 * time.Minute) }
	if _, err := store.Read(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session error = %v", err)
	}
	store.Now = func() time.Time { return time.Now().Add(119 * time.Minute) }
	if _, err := store.Read(id); err != nil {
		t.Fatalf("session just inside lifetime rejected: %v", err)
	}
}

func TestDestroyAndRotate(t *testing.T) {
	store := newTestStore(t)
	oldID, _ := NewID()
	if err := store.Write(oldID, NewPayload("login_web_x", 1, "t", "/")); err != nil {
		t.Fatal(err)
	}
	newID, err := store.Rotate(oldID)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newID == oldID || !ValidID(newID) {
		t.Fatalf("newID = %q", newID)
	}
	if _, err := store.Read(oldID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old id still readable: %v", err)
	}
	if err := store.Write(newID, NewPayload("login_web_x", 1, "t", "/")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(newID); err != nil {
		t.Fatalf("new id unreadable: %v", err)
	}
}

func TestCorruptPayloadRejected(t *testing.T) {
	store := newTestStore(t)
	id, _ := NewID()
	if err := os.WriteFile(filepath.Join(store.Dir, id), []byte(`O:8:"stdClass":0:{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(id); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt payload error = %v", err)
	}
}

func TestInvalidIDsRejected(t *testing.T) {
	store := newTestStore(t)
	for _, id := range []string{"", "short", "../../etc/passwd", strings.Repeat("a", 39), strings.Repeat("a", 41), strings.Repeat("a", 39) + "-"} {
		if _, err := store.Read(id); !errors.Is(err, ErrInvalidID) {
			t.Fatalf("Read(%q) error = %v", id, err)
		}
		if err := store.Write(id, php.NewArray()); !errors.Is(err, ErrInvalidID) {
			t.Fatalf("Write(%q) error = %v", id, err)
		}
	}
}

func TestFlashAgeing(t *testing.T) {
	attrs := php.NewArray().
		Set("_token", "t").
		Set("_flash", php.NewArray().
			Set("old", php.NewArray().Append("status")).
			Set("new", php.NewArray().Append("notice"))).
		Set("status", "ok").
		Set("notice", "hello")
	AgeFlashData(attrs)
	if _, ok := attrs.Get("status"); ok {
		t.Fatal("_flash.old entry was not forgotten")
	}
	if _, ok := attrs.Get("notice"); !ok {
		t.Fatal("_flash.new entry was dropped")
	}
	old, ok := attrs.GetPath("_flash.old")
	if !ok {
		t.Fatal("_flash.old missing")
	}
	if arr, ok := old.(*php.Array); !ok || len(arr.Entries) != 1 {
		t.Fatalf("_flash.old = %#v", old)
	}
	newer, ok := attrs.GetPath("_flash.new")
	if !ok {
		t.Fatal("_flash.new missing")
	}
	if arr, ok := newer.(*php.Array); !ok || len(arr.Entries) != 0 {
		t.Fatalf("_flash.new = %#v", newer)
	}
}

func TestConcurrentWritesStayParseable(t *testing.T) {
	store := newTestStore(t)
	id, _ := NewID()
	const writers = 8
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(uid int64) {
			defer wg.Done()
			attrs := NewPayload("login_web_x", uid, "token", "/")
			errs <- store.Write(id, attrs)
		}(int64(i + 1))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent write: %v", err)
		}
	}
	// PHP's file handler has no read-modify-write lock either: the last writer
	// wins, but the file must always remain a valid payload.
	attrs, err := store.Read(id)
	if err != nil {
		t.Fatalf("Read after concurrent writes: %v", err)
	}
	uid, ok := LoginUID(attrs, "login_web_x")
	if !ok || uid < 1 || uid > writers {
		t.Fatalf("uid = %d, %v", uid, ok)
	}
}

func TestCookieRoundTrip(t *testing.T) {
	key := laravel.ParseAppKey("base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	enc, err := laravel.NewEncrypter(key, "AES-256-CBC")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := NewID()
	cookie, err := SessionCookieValue(enc, "BS_SESSION", id)
	if err != nil {
		t.Fatalf("SessionCookieValue: %v", err)
	}
	got, err := SessionIDFromCookie(enc, "BS_SESSION", cookie)
	if err != nil || got != id {
		t.Fatalf("SessionIDFromCookie = %q, %v", got, err)
	}
	if _, err := SessionIDFromCookie(enc, "OTHER", cookie); err == nil {
		t.Fatal("cookie accepted under a different name")
	}
}

// A queued writer must not truncate the payload while another process holds
// the session lock. This exercises OS file locking, beyond Go's race detector.
func TestBlockedWriterPreservesLockedPayload(t *testing.T) {
	store := newTestStore(t)
	id, _ := NewID()
	original := NewPayload("login_web_x", 1, strings.Repeat("x", 4096), "/")
	if err := store.Write(id, original); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Dir, id)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	done := make(chan error, 1)
	go func() { done <- store.Write(id, NewPayload("login_web_x", 2, "short", "/")) }()
	select {
	case err := <-done:
		t.Fatalf("writer bypassed shared lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	during, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(during) != string(before) {
		t.Error("blocked writer truncated locked payload")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer failed to complete after unlock")
	}
	attrs, err := store.Read(id)
	if err != nil {
		t.Fatal(err)
	}
	if uid, _ := LoginUID(attrs, "login_web_x"); uid != 2 {
		t.Fatalf("uid = %d", uid)
	}
}
