package site

import (
	"blessing-skin-go/internal/testsupport"
	"testing"
)

func TestLocaleOverlayDoesNotMutateSharedFiles(t *testing.T) {
	store, _ := testsupport.Database(t, "lang-")
	_, err := store.DB.Exec("INSERT INTO "+store.Table("language_lines")+" (`group`,`key`,text) VALUES ('front-end','auth.login',?)", `{"en":"Custom log in","zh_CN":"自定登录"}`)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]map[string]any{"en": {"front-end": map[string]any{"auth": map[string]any{"login": "Log In", "keep": "Remember me"}}}, "zh_CN": {"front-end": map[string]any{"auth": map[string]any{"login": "登录"}}}}
	s := &Service{Store: store}
	messages, err := s.Translations(t.Context(), "zh_CN", "en", files)
	if err != nil {
		t.Fatal(err)
	}
	auth := messages["front-end"].(map[string]any)["auth"].(map[string]any)
	if auth["login"] != "自定登录" || auth["keep"] != "Remember me" {
		t.Fatal("translation precedence changed")
	}
	if files["zh_CN"]["front-end"].(map[string]any)["auth"].(map[string]any)["login"] != "登录" {
		t.Fatal("request changed shared messages")
	}
}
