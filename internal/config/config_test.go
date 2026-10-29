package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDeclaredFileEnvironmentAndEmptyValues(t *testing.T) {
	file := filepath.Join(t.TempDir(), "site.env")
	if err := os.WriteFile(file, []byte("APP_KEY=synthetic-key-of-thirty-two-bytes-only\nDB_DATABASE=synthetic\nDB_PASSWORD='file password'\nSESSION_DOMAIN=file.invalid\nSESSION_SECURE_COOKIE=(false)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(file, func(k string) (string, bool) {
		if k == "SESSION_DOMAIN" {
			return "", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.SessionDomain != "" || c.SecureCookie || c.Location.String() != "Asia/Shanghai" {
		t.Fatal("configuration precedence or types changed")
	}
	if c.LockFile != filepath.Join(filepath.Dir(file), "storage/go-instance.lock") {
		t.Fatal("lock is not bound to deployment root")
	}
	_, err = Load(file, func(k string) (string, bool) {
		if k == "DB_CONNECTION" {
			return "sqlite", true
		}
		return "", false
	})
	if err == nil {
		t.Fatal("unsupported installer database accepted")
	}
	for _, value := range []string{"0", "42", ""} {
		if OptionValue(value) != value {
			t.Fatalf("text %q changed type", value)
		}
	}
	if OptionValue("TRUE") != true || OptionValue("(true)") != true || OptionValue("(false)") != false || OptionValue("(null)") != nil {
		t.Fatal("option bool/null semantics changed")
	}
}
