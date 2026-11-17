package httpapp

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/net/html"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/web"
)

func TestUserMenuIdentity(t *testing.T) {
	assets, err := web.Load()
	if err != nil {
		t.Fatal(err)
	}
	attribute := func(n *html.Node, key string) string {
		for _, a := range n.Attr {
			if a.Key == key {
				return a.Val
			}
		}
		return ""
	}
	var find func(*html.Node, func(*html.Node) bool) *html.Node
	find = func(n *html.Node, match func(*html.Node) bool) *html.Node {
		if match(n) {
			return n
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			if found := find(child, match); found != nil {
				return found
			}
		}
		return nil
	}
	for _, account := range []struct {
		name       string
		nickname   string
		permission int
	}{
		{"normal", "Mira & Sky", 0},
		{"admin", "Juniper", 2},
		{"empty-nickname", "", 0},
	} {
		for _, layout := range []string{"dashboard", "admin-dashboard", "home", "skinlib"} {
			t.Run(account.name+"/"+layout, func(t *testing.T) {
				view := ViewModel{
					BaseURL:    "http://localhost/skin",
					User:       &identity.User{UID: 7, Nickname: account.nickname, Permission: account.permission},
					HasUser:    true,
					Nickname:   account.nickname,
					Admin:      account.permission >= 1,
					AdminPage:  layout == "admin-dashboard",
					Home:       layout == "home",
					AvatarWebP: "http://localhost/skin/avatar/42?size=45",
					AvatarPNG:  "http://localhost/skin/avatar/42?size=45&png=1",
				}
				templateName := "page"
				if layout == "skinlib" {
					templateName = "skinlib"
				}
				var rendered bytes.Buffer
				if err := assets.Templates.ExecuteTemplate(&rendered, templateName, view); err != nil {
					t.Fatal(err)
				}
				document, err := html.Parse(&rendered)
				if err != nil {
					t.Fatal(err)
				}
				menu := find(document, func(n *html.Node) bool {
					return n.Type == html.ElementNode && strings.Contains(" "+attribute(n, "class")+" ", " user-menu ")
				})
				if menu == nil {
					t.Fatal("authenticated user menu missing")
				}
				for _, path := range []string{"/admin", "/admin/users", "/admin/reports"} {
					link := find(menu, func(n *html.Node) bool {
						return n.Type == html.ElementNode && n.Data == "a" && attribute(n, "href") == view.BaseURL+path
					})
					if (link != nil) != view.Admin {
						t.Fatalf("admin link %s visibility does not match permission", path)
					}
				}
				cli := find(menu, func(n *html.Node) bool { return n.Type == html.ElementNode && attribute(n, "id") == "launch-cli" })
				if (cli != nil) != (view.Admin && view.AdminPage) {
					t.Fatal("Web CLI visibility changed")
				}
				picture := find(menu, func(n *html.Node) bool { return n.Type == html.ElementNode && n.Data == "picture" })
				if picture == nil {
					t.Fatal("user menu avatar missing")
				}
				for tag, expected := range map[string]string{"source": view.AvatarWebP, "img": view.AvatarPNG} {
					node := find(picture, func(n *html.Node) bool { return n.Type == html.ElementNode && n.Data == tag })
					if node == nil {
						t.Fatalf("avatar %s missing", tag)
					}
					key := "src"
					if tag == "source" {
						key = "srcset"
					}
					if actual := attribute(node, key); actual != expected {
						t.Fatalf("avatar %s URL = %q, want %q", tag, actual, expected)
					}
				}
				nickname := find(menu, func(n *html.Node) bool {
					return n.Type == html.ElementNode && attribute(n, "data-mark") == "nickname"
				})
				if nickname == nil {
					t.Fatal("nickname missing")
				}
				var actual strings.Builder
				for child := nickname.FirstChild; child != nil; child = child.NextSibling {
					if child.Type != html.TextNode {
						t.Fatal("nickname contains unescaped markup")
					}
					actual.WriteString(child.Data)
				}
				if actual.String() != account.nickname {
					t.Fatalf("nickname = %q, want %q", actual.String(), account.nickname)
				}
			})
		}
	}
}
