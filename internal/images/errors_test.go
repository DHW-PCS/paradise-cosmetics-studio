package images

import (
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"paradise-cosmetics-studio/internal/site"
	"paradise-cosmetics-studio/internal/textures"
)

func TestRawReadPermissionFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "unreadable")
	if err := os.WriteFile(path, []byte("original"), 0o000); err != nil {
		t.Fatal(err)
	}
	s := New(nil, &site.Service{OptionSnapshot: map[string]string{}}, &textures.Service{Dir: dir}, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/textures/unreadable", nil)
	served, err := s.Raw(t.Context(), "unreadable", w, r)
	if served || !errors.Is(err, os.ErrPermission) || w.Body.Len() != 0 {
		t.Fatalf("read permission failure served=%v err=%v body=%q", served, err, w.Body.String())
	}
}
