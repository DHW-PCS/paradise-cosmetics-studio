package players

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestLegacyUUIDRepresentations(t *testing.T) {
	canonical := "0123456789abcdef0123456789abcdef"
	hyphenated := "01234567-89ab-cdef-0123-456789abcdef"
	for _, representation := range []string{canonical, strings.ToUpper(canonical), hyphenated, strings.ToUpper(hyphenated), "urn:uuid:" + hyphenated, "{" + hyphenated + "}"} {
		for _, rename := range []bool{false, true} {
			t.Run(representation+map[bool]string{false: "/allocate", true: "/rename"}[rename], func(t *testing.T) {
				service, id, store := fixture(t, nil)
				pid := insertPlayer(t, store, 1, "LegacyOne")
				if _, err := store.DB.Exec("INSERT INTO "+store.Table("uuid")+" (name,uuid) VALUES (?,?)", "LegacyOne", representation); err != nil {
					t.Fatal(err)
				}
				name := "LegacyOne"
				if rename {
					if _, _, err := service.Rename(t.Context(), login(t, id, "user@example.invalid"), pid, "LegacyTwo", Normal); err != nil {
						t.Fatal(err)
					}
					name = "LegacyTwo"
				}
				binding, err := service.EnsureUUID(t.Context(), pid)
				if err != nil || binding.UUID != canonical || binding.Version != 1 {
					t.Fatalf("binding: %#v, %v", binding, err)
				}
				var original string
				if err := store.DB.QueryRow("SELECT uuid FROM "+store.Table("uuid")+" WHERE name=?", name).Scan(&original); err != nil || original != representation {
					t.Fatalf("legacy value: %q, %v", original, err)
				}
			})
		}
	}
}

func TestEquivalentUUIDBindingConflictRollsBackRename(t *testing.T) {
	service, id, store := fixture(t, nil)
	owner := insertPlayer(t, store, 1, "BoundOne")
	other := insertPlayer(t, store, 1, "LegacyOne")
	if _, err := store.DB.Exec("INSERT INTO " + store.Table("uuid") + " (name,uuid) VALUES ('BoundOne','0123456789abcdef0123456789abcdef'),('LegacyOne','01234567-89AB-CDEF-0123-456789ABCDEF')"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.EnsureUUID(t.Context(), owner); err != nil {
		t.Fatal(err)
	}
	if _, err := service.EnsureUUID(t.Context(), other); !errors.Is(err, ErrUUIDConflict) {
		t.Fatalf("allocation: %v", err)
	}
	if _, _, err := service.Rename(t.Context(), login(t, id, "user@example.invalid"), other, "LegacyTwo", Normal); !errors.Is(err, ErrUUIDConflict) {
		t.Fatalf("rename: %v", err)
	}
	var playerName, mappingName string
	if err := store.DB.QueryRow("SELECT name FROM "+store.Table("players")+" WHERE pid=?", other).Scan(&playerName); err != nil {
		t.Fatal(err)
	}
	if err := store.DB.QueryRow("SELECT name FROM " + store.Table("uuid") + " WHERE uuid='01234567-89AB-CDEF-0123-456789ABCDEF'").Scan(&mappingName); err != nil {
		t.Fatal(err)
	}
	if playerName != "LegacyOne" || mappingName != "LegacyOne" {
		t.Fatalf("partial rename: %q, %q", playerName, mappingName)
	}
}

func TestV3RenamePreservesEquivalentTargetUUID(t *testing.T) {
	service, id, store := fixture(t, map[string]string{"ygg_uuid_algorithm": "v3"})
	pid := insertPlayer(t, store, 1, "LegacyOne")
	canonical := UUID3("LegacyTwo")
	original := strings.ToUpper(canonical[:8] + "-" + canonical[8:12] + "-" + canonical[12:16] + "-" + canonical[16:20] + "-" + canonical[20:])
	if _, err := store.DB.Exec("INSERT INTO "+store.Table("uuid")+" (name,uuid) VALUES (?,?)", "LegacyTwo", original); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Rename(t.Context(), login(t, id, "user@example.invalid"), pid, "LegacyTwo", Normal); err != nil {
		t.Fatal(err)
	}
	binding, err := service.Binding(context.Background(), pid)
	if err != nil || binding.UUID != canonical {
		t.Fatalf("binding: %#v, %v", binding, err)
	}
	var stored string
	if err := store.DB.QueryRow("SELECT uuid FROM " + store.Table("uuid") + " WHERE name='LegacyTwo'").Scan(&stored); err != nil || stored != original {
		t.Fatalf("legacy UUID changed: %q, %v", stored, err)
	}
}
