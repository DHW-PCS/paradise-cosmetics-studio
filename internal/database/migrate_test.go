package database_test

import (
	"paradise-cosmetics-studio/internal/testsupport"
	"testing"
)

func TestExistingSiteAndMigrationLedger(t *testing.T) {
	s, _ := testsupport.Database(t, "ledger_")
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.DB.QueryRow("SELECT COUNT(*) FROM " + s.Table("users")).Scan(&count); err != nil || count != 2 {
		t.Fatal("migration rebuilt existing users")
	}
	if _, err := s.DB.Exec("UPDATE "+s.Table("go_migrations")+" SET checksum=? WHERE name='001_auth_versions'", make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(t.Context()); err == nil {
		t.Fatal("changed migration accepted")
	}
}
