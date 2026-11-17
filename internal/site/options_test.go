package site

import (
	"paradise-cosmetics-studio/internal/testsupport"
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
	if err != nil || values["site_name"] != "Paradise Cosmetics Studio" {
		t.Fatal("empty cached source was ignored")
	}
}

func TestProductDefaultsPreserveConfiguredBrand(t *testing.T) {
	for _, configured := range []map[string]string{{}, {"site_name": "Blessing Skin", "announcement": "My announcement", "custom_js": "window.blessing.custom = true", "custom_css": ".bs-avatar { opacity: .5 }"}} {
		s := &Service{OptionSnapshot: configured}
		values, err := s.Options(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if len(configured) == 0 {
			if values["site_name"] != "Paradise Cosmetics Studio" || values["announcement"] != "Welcome to Paradise Cosmetics Studio {version}!" {
				t.Fatalf("product defaults = %v / %v", values["site_name"], values["announcement"])
			}
		}
		for key, want := range configured {
			if values[key] != want {
				t.Errorf("configured %s changed: %v", key, values[key])
			}
		}
	}
}
