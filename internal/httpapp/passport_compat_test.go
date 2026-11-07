package httpapp

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"blessing-skin-go/internal/oauthserver"
	"golang.org/x/net/html"
)

// Focused frozen-contract checks using the production serializers and
// template. They need no database and do not replace the DB-backed
// passport tests.

// The existing frontend declares redirect as a string.
func TestCompatClientRowRedirectIsString(t *testing.T) {
	w := httptest.NewRecorder()
	jsonResponse(w, 200, []oauthserver.ClientRow{{ID: 7, Name: "reference-client", Secret: "owner-secret", Redirect: "https://client.example.invalid/callback,https://client.example.invalid/other"}})
	var frontend []struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		Secret   string `json:"secret"`
		Redirect string `json:"redirect"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &frontend); err != nil {
		t.Fatalf("frontend string contract rejected production JSON: %v; body=%s", err, w.Body.String())
	}
	if len(frontend) != 1 || frontend[0].Redirect != "https://client.example.invalid/callback,https://client.example.invalid/other" || frontend[0].Secret != "owner-secret" {
		t.Fatalf("frontend row=%+v body=%s", frontend, w.Body.String())
	}
}

// Passport Scope::toArray uses id, not name.
func TestCompatScopeDescriptionUsesID(t *testing.T) {
	w := httptest.NewRecorder()
	jsonResponse(w, 200, []oauthserver.ScopeDescription{{ID: "User.Read", Description: "auth.oauth.scope.user.read"}})
	var scopes []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &scopes); err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 1 || scopes[0].ID != "User.Read" || scopes[0].Name != "" {
		t.Fatalf("Passport scope id missing from production JSON: %s", w.Body.String())
	}
}

// The consent page restores the auth layout and both form actions carry
// the BaseURL prefix, including for a subpath deployment.
func TestCompatConsentTemplateSubpathAndLayout(t *testing.T) {
	for _, base := range []string{"https://skin.example.invalid", "https://skin.example.invalid/skin"} {
		t.Run(strings.TrimPrefix(base, "https://"), func(t *testing.T) {
			var body bytes.Buffer
			view := consentView{
				ClientName:   "reference-client",
				CSRF:         "synthetic-csrf",
				AuthToken:    "synthetic-pending",
				BaseURL:      base,
				SiteName:     "Example",
				Title:        "Authorization",
				Introduction: "A 3rd-party application \"reference-client\" is requesting permission to access your account.",
				Permissions:  "Permissions",
				Approve:      "Authorize",
				Cancel:       "Cancel",
				Scopes:       []oauthserver.ScopeDisplay{{Name: "User.Read", Description: "Sign you in and read your profile"}},
			}
			if err := consentTemplate.ExecuteTemplate(&body, "authorize", view); err != nil {
				t.Fatal(err)
			}
			text := body.String()
			for _, want := range []string{"login-box", "login-box-msg", "Authorize", "Cancel", "Permissions", "Sign you in and read your profile", `name="auth_token"`} {
				if !strings.Contains(text, want) {
					t.Errorf("consent page missing %q", want)
				}
			}
			doc, err := html.Parse(&body)
			if err != nil {
				t.Fatal(err)
			}
			page, _ := url.Parse(base + "/oauth/authorize")
			baseURL, _ := url.Parse(base)
			forms := 0
			var visit func(*html.Node)
			visit = func(n *html.Node) {
				if n.Type == html.ElementNode && n.Data == "form" {
					forms++
					for _, a := range n.Attr {
						if a.Key != "action" {
							continue
						}
						ref, err := url.Parse(a.Val)
						if err != nil {
							t.Fatal(err)
						}
						resolved := page.ResolveReference(ref)
						wantPrefix := baseURL.Path + "/oauth/authorize"
						if !strings.HasPrefix(resolved.Path, wantPrefix) {
							t.Errorf("action=%q resolves to %q; registered route prefix is %q", a.Val, resolved.Path, wantPrefix)
						}
					}
				}
				for child := n.FirstChild; child != nil; child = child.NextSibling {
					visit(child)
				}
			}
			visit(doc)
			if forms != 2 {
				t.Fatalf("form count=%d, want approve and deny", forms)
			}
		})
	}
}
