package site

import (
	"blessing-skin-go/internal/testsupport"
	"testing"
)

func TestAuthoritativeOptionSnapshot(t *testing.T) {
	store, _ := testsupport.Database(t, "options_")
	_, err := store.DB.Exec("INSERT INTO " + store.Table("options") + " (option_name,option_value) VALUES ('site_name','Database name'),('score_per_player','777')")
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{Store: store}
	values, err := s.Options(t.Context())
	if err != nil || values["site_name"] != "Database name" {
		t.Fatal("database option source not used")
	}
	s.OptionSnapshot = map[string]string{"site_name": "Cached name"}
	values, err = s.Options(t.Context())
	if err != nil || values["site_name"] != "Cached name" || values["score_per_player"] != "100" {
		t.Fatal("snapshot incorrectly merged missing values from database")
	}
	s.OptionSnapshot = map[string]string{}
	values, err = s.Options(t.Context())
	if err != nil || values["site_name"] != "Blessing Skin" {
		t.Fatal("empty cached source was ignored")
	}
}
