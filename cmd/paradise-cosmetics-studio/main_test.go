package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	"paradise-cosmetics-studio/internal/processlock"
	"paradise-cosmetics-studio/internal/testsupport"
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

// The module state takeover runs inside the offline migrate command: without
// the declared manifest it refuses to invent install facts, and a present
// manifest seeds only the missing rows without rewriting runtime state.
func TestMigrateInitializesModuleStateRows(t *testing.T) {
	store, _ := testsupport.Database(t, "modules-cli-")
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
	text := "APP_KEY=synthetic-only-secret-with-thirty-two-bytes\nAPP_ROOT=" + directory + "\nAPP_LOCK_FILE=" + filepath.Join(directory, "storage/go-instance.lock") + "\nDB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=" + func() string {
		_, port, err := net.SplitHostPort(cfg.Addr)
		if err != nil {
			t.Fatal(err)
		}
		return port
	}() + "\nDB_DATABASE=" + name + "\nDB_USERNAME=" + cfg.User + "\nDB_PASSWORD=" + cfg.Passwd + "\nDB_PREFIX=modules-cli-\n"
	if err = os.WriteFile(envFile, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = store.DB.Exec("DELETE FROM " + store.Table("options") + " WHERE option_name IN ('plugins_enabled','go_module_installations')"); err != nil {
		t.Fatal(err)
	}
	if err = run([]string{"migrate", "-env", envFile}); err == nil {
		t.Fatal("migrate invented module install facts without the manifest")
	}
	manifest := filepath.Join(directory, "modules.json")
	if err = os.WriteFile(manifest, []byte(`{"installed":[{"name":"legacy-api","version":"1.1.3"},{"name":"yggdrasil-api","version":"5.2.1"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	text += "MODULES_MANIFEST_FILE=" + manifest + "\n"
	if err = os.WriteFile(envFile, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	if err = run([]string{"migrate", "-env", envFile}); err != nil {
		t.Fatal(err)
	}
	var enabled, installed string
	if err = store.DB.QueryRow("SELECT option_value FROM " + store.Table("options") + " WHERE option_name='plugins_enabled'").Scan(&enabled); err != nil || enabled != "" {
		t.Fatalf("frozen enable default not seeded: %q %v", enabled, err)
	}
	if err = store.DB.QueryRow("SELECT option_value FROM " + store.Table("options") + " WHERE option_name='go_module_installations'").Scan(&installed); err != nil || installed != `[{"name":"legacy-api","version":"1.1.3"},{"name":"yggdrasil-api","version":"5.2.1"}]` {
		t.Fatalf("manifest ledger not seeded: %q %v", installed, err)
	}
	// A repeated takeover must not rewrite the rows.
	if err = run([]string{"migrate", "-env", envFile}); err != nil {
		t.Fatal(err)
	}
	if err = store.DB.QueryRow("SELECT option_value FROM " + store.Table("options") + " WHERE option_name='go_module_installations'").Scan(&installed); err != nil || installed != `[{"name":"legacy-api","version":"1.1.3"},{"name":"yggdrasil-api","version":"5.2.1"}]` {
		t.Fatalf("repeat takeover rewrote the rows: %q", installed)
	}
}

func TestProductCommandIdentity(t *testing.T) {
	if err := run(nil); err == nil || !strings.Contains(err.Error(), "usage: paradise-cosmetics-studio ") {
		t.Fatalf("usage = %v", err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	previous := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = previous }()
	runErr := run([]string{"version"})
	writer.Close()
	os.Stdout = previous
	output, err := io.ReadAll(reader)
	if err != nil || runErr != nil {
		t.Fatalf("version: %v / %v", runErr, err)
	}
	if !strings.HasPrefix(string(output), "Paradise Cosmetics Studio "+buildVersion+" (") {
		t.Fatalf("version = %q", output)
	}
}

func TestMailBrandMigrationRequiresStoppedService(t *testing.T) {
	directory := t.TempDir()
	lockFile := filepath.Join(directory, "instance.lock")
	for key, value := range map[string]string{"APP_ROOT": directory, "APP_LOCK_FILE": lockFile, "APP_KEY": "synthetic-only-secret-with-thirty-two-bytes", "DB_CONNECTION": "mysql", "DB_DATABASE": "synthetic_pcs", "DB_USERNAME": "synthetic_pcs"} {
		t.Setenv(key, value)
	}
	lock, err := processlock.Acquire(lockFile, false)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := run([]string{"migrate-mail-brand"}); err == nil || !strings.Contains(err.Error(), "instance lock unavailable") {
		t.Fatalf("mail migration admitted alongside a running service: %v", err)
	}
}
