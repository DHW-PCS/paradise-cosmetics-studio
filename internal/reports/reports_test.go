package reports

import (
	"testing"
	"time"

	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/testsupport"
	"blessing-skin-go/internal/textures"
)

func TestManageAssociationErrors(t *testing.T) {
	for _, broken := range []string{"missing", "textures", "users"} {
		t.Run(broken, func(t *testing.T) {
			store, id := testsupport.Database(t, "reports-")
			view := &site.Service{Store: store, Location: time.UTC}
			tex := textures.New(store, id, view, t.TempDir(), time.Now)
			s := New(store, id, view, tex, nil, time.Now)
			if _, err := store.DB.Exec("INSERT INTO " + store.Table("reports") + " (tid,uploader,reporter,reason,status,report_at) VALUES (999,998,997,'missing relations',0,NOW())"); err != nil {
				t.Fatal(err)
			}
			switch broken {
			case "textures":
				if _, err := store.DB.Exec("DROP TABLE " + store.Table("textures")); err != nil {
					t.Fatal(err)
				}
			case "users":
				if _, err := store.DB.Exec("ALTER TABLE " + store.Table("users") + " DROP COLUMN nickname"); err != nil {
					t.Fatal(err)
				}
			}
			page, err := s.Manage(t.Context(), 1, "", "/admin/reports/list")
			if broken != "missing" {
				if err == nil || page != nil {
					t.Fatalf("association DB failure returned page=%v err=%v", page, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			items := page.Data.([]ManageItem)
			if len(items) != 1 || items[0].Texture != nil || items[0].TextureUploader != nil || items[0].Informer != nil {
				t.Fatalf("missing relations: %+v", items)
			}
		})
	}
}
