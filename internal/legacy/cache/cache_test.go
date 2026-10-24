package cache

import (
	"crypto/sha1"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStore(dir, "blessing_skin_cache")
	if err != nil {
		t.Fatal(err)
	}
	store.Now = func() time.Time { return testNow }
	return store
}

func TestPathMatchesLaravelLayout(t *testing.T) {
	store := newTestStore(t)
	path, err := store.Path("login_fails_127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha1.Sum([]byte("blessing_skin_cachelogin_fails_127.0.0.1"))
	want := filepath.Join(store.Dir, hex.EncodeToString(hash[:])[0:2],
		hex.EncodeToString(hash[:])[2:4], hex.EncodeToString(hash[:]))
	if path != want {
		t.Fatalf("path = %s, want %s", path, want)
	}
}

func TestPutWritesExpiryAndSerializedValue(t *testing.T) {
	store := newTestStore(t)
	if err := store.Put("fails", int64(3), time.Hour); err != nil {
		t.Fatal(err)
	}
	path, _ := store.Path("fails")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wantHeader := "1792760400" // testNow + 1h
	if string(data[:10]) != wantHeader {
		t.Fatalf("header = %q, want %q", data[:10], wantHeader)
	}
	if string(data[10:]) != "i:3;" {
		t.Fatalf("payload = %q, want i:3;", data[10:])
	}

	value, ok, err := store.Get("fails")
	if err != nil || !ok {
		t.Fatalf("Get = %v, %v, %v", value, ok, err)
	}
	if n, _ := value.(int64); n != 3 {
		t.Fatalf("value = %v, want 3", value)
	}
}

func TestExpiredPayloadIsRemovedAndMissed(t *testing.T) {
	store := newTestStore(t)
	if err := store.Put("fails", int64(1), -time.Second); err != nil {
		t.Fatal(err)
	}
	path, _ := store.Path("fails")
	if _, ok, err := store.Get("fails"); err != nil || ok {
		t.Fatalf("Get = ok %v, err %v; want miss", ok, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expired file still exists: %v", err)
	}
}

func TestShortOrCorruptPayloadIsRemoved(t *testing.T) {
	for name, payload := range map[string]string{
		"short":   "12345",
		"header":  "abcdefghij" + "i:1;",
		"payload": "9999999999" + "not-serialized",
	} {
		t.Run(name, func(t *testing.T) {
			store := newTestStore(t)
			path, _ := store.Path("fails")
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, ok, err := store.Get("fails"); err != nil || ok {
				t.Fatalf("Get = ok %v, err %v; want miss", ok, err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("corrupt file still exists: %v", err)
			}
		})
	}
}

func TestZeroTTLIsForever(t *testing.T) {
	store := newTestStore(t)
	if err := store.Put("fails", int64(1), 0); err != nil {
		t.Fatal(err)
	}
	path, _ := store.Path("fails")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data[:10])) != "9999999999" {
		t.Fatalf("header = %q, want 9999999999", data[:10])
	}
}

func TestIncrementPreservesExpiry(t *testing.T) {
	store := newTestStore(t)
	if err := store.Put("fails", int64(1), time.Hour); err != nil {
		t.Fatal(err)
	}
	value, err := store.Increment("fails", 1)
	if err != nil {
		t.Fatal(err)
	}
	if value != 2 {
		t.Fatalf("increment = %d, want 2", value)
	}
	path, _ := store.Path("fails")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data[:10]) != "1792760400" {
		t.Fatalf("expiry changed: %q", data[:10])
	}
	if string(data[10:]) != "i:2;" {
		t.Fatalf("payload = %q, want i:2;", data[10:])
	}
}

func TestIncrementMissingKeyIsPermanent(t *testing.T) {
	store := newTestStore(t)
	value, err := store.Increment("fails", 1)
	if err != nil {
		t.Fatal(err)
	}
	if value != 1 {
		t.Fatalf("increment = %d, want 1", value)
	}
	path, _ := store.Path("fails")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data[:10]) != "9999999999" {
		t.Fatalf("expiry = %q, want forever", data[:10])
	}
}

func TestPrefixChangesPath(t *testing.T) {
	a := newTestStore(t)
	b := newTestStore(t)
	b.Prefix = "other_cache"
	pa, _ := a.Path("fails")
	pb, _ := b.Path("fails")
	if pa == pb {
		t.Fatal("prefix did not change the path")
	}
}

func TestEmptyKeyIsRejected(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.Path(""); err == nil {
		t.Fatal("empty key accepted")
	}
}

func TestReadOnlyImportPreservesUnparsedArtifacts(t *testing.T) {
	s, e := NewStore(t.TempDir(), "")
	if e != nil {
		t.Fatal(e)
	}
	s.ReadOnly = true
	path, _ := s.Path("unparsed")
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	raw := []byte("9999999999O:7:\"Unknown\":0:{}")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Get("unparsed"); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(path)
	if e != nil || string(got) != string(raw) {
		t.Fatal("source artifact modified", e)
	}
}

func TestAbsoluteExpiryDoesNotMoveAcrossClockTick(t *testing.T) {
	s, e := NewStore(t.TempDir(), "")
	if e != nil {
		t.Fatal(e)
	}
	s.Now = func() time.Time { return time.Unix(1770000000, 0) }
	if e = s.Put("legacy", int64(1), 10*time.Second); e != nil {
		t.Fatal(e)
	}
	calls := 0
	s.Now = func() time.Time { calls++; return time.Unix(1770000000+int64(calls), 0) }
	_, expiry, ok, e := s.GetWithExpiry("legacy")
	if e != nil || !ok || expiry != 1770000010 {
		t.Fatalf("absolute driver deadline moved: %d %v %v", expiry, ok, e)
	}
}
