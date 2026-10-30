package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"blessing-skin-go/internal/processlock"
	"blessing-skin-go/internal/testsupport"
	"github.com/go-sql-driver/mysql"
)

func TestOfflineCommandsProtectInstalledSite(t *testing.T) {
	store, id := testsupport.Database(t, "cli-")
	cfg, err := mysql.ParseDSN(os.Getenv("M2_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	var name string
	if err = store.DB.QueryRow("SELECT DATABASE()").Scan(&name); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	envFile := filepath.Join(directory, "site.env")
	// The loopback fixture supplies synthetic credentials, never deployment data.
	text := "APP_KEY=synthetic-only-secret-with-thirty-two-bytes\nDB_DATABASE=" + name + "\nDB_USERNAME=" + cfg.User + "\nDB_PASSWORD=" + cfg.Passwd + "\nDB_PREFIX=cli-\nDB_HOST=127.0.0.1\nDB_PORT="
	_, port, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		t.Fatal(err)
	}
	text += port + "\n"
	for key, value := range map[string]string{"APP_KEY": "synthetic-only-secret-with-thirty-two-bytes", "APP_ROOT": directory, "APP_LOCK_FILE": filepath.Join(directory, "storage/go-instance.lock"), "DB_CONNECTION": "mysql", "DB_HOST": "127.0.0.1", "DB_PORT": port, "DB_DATABASE": name, "DB_USERNAME": cfg.User, "DB_PASSWORD": cfg.Passwd, "DB_PREFIX": "cli-"} {
		t.Setenv(key, value)
	}
	if err = os.WriteFile(envFile, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	// Remove the additive player/texture schema so the offline migrate chain
	// must recreate everything CheckSchema requires.
	for _, statement := range []string{
		"DROP TABLE IF EXISTS " + store.Table("go_uuid_bindings"),
		"DROP TABLE IF EXISTS " + store.Table("go_file_hashes"),
		"DELETE FROM " + store.Table("go_migrations") + " WHERE name IN ('012_uuid_bindings','013_file_hashes')",
		"DELETE FROM " + store.Table("go_account_namespaces") + " WHERE name='uuid'",
	} {
		if _, err = store.DB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err = run([]string{"migrate", "-env", envFile}); err != nil {
		t.Fatal(err)
	}
	var uuidRows, hashRows, uuidNamespace int
	if err = store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("go_uuid_bindings")).Scan(&uuidRows); err != nil {
		t.Fatalf("migrate did not create uuid bindings: %v", err)
	}
	if err = store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("go_file_hashes")).Scan(&hashRows); err != nil {
		t.Fatalf("migrate did not create file hashes: %v", err)
	}
	if err = store.DB.QueryRow("SELECT COUNT(*) FROM " + store.Table("go_account_namespaces") + " WHERE name='uuid'").Scan(&uuidNamespace); err != nil || uuidNamespace != 1 {
		t.Fatalf("migrate did not add uuid namespace: %d %v", uuidNamespace, err)
	}
	b, err := id.Login(t.Context(), "user@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(directory, "storage/go-instance.lock")
	online, err := processlock.Acquire(lockPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = run([]string{"auth-reset", "-env", envFile}); err == nil {
		t.Fatal("offline reset bypassed online lock")
	}
	online.Close()
	if err = run([]string{"auth-reset", "-env", envFile}); err != nil {
		t.Fatal(err)
	}
	if _, err = id.Session(t.Context(), b.Token); err == nil {
		t.Fatal("CLI reset left session valid")
	}
	var score int
	if err = store.DB.QueryRow("SELECT score FROM " + store.Table("users") + " WHERE uid=1").Scan(&score); err != nil || score != 71 {
		t.Fatal("CLI changed business data")
	}
}
