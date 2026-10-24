package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"blessing-skin-go/internal/legacy/users"
)

// TestAPIUserRequiresUserReadScope covers R03. A token without User.Read must be
// refused before any account data is read, using the frozen HTTP 200 + business
// code 403 contract.
func TestAPIUserRequiresUserReadScope(t *testing.T) {
	env := newTestEnv(t)
	env.server.cfg.Users = &fakeUsers{user: &users.User{
		UID: 1, Email: "member@example.invalid", Nickname: "Member", Verified: true,
	}}
	env.server.cfg.Bearer = func(_ context.Context, token string) (*BearerIdentity, error) {
		switch token {
		case "user-read":
			return &BearerIdentity{UID: 1, ClientID: "1", Scopes: []string{"User.Read"}}, nil
		case "user-read-plus":
			return &BearerIdentity{UID: 1, ClientID: "1", Scopes: []string{"User.Read", "Player.Read"}}, nil
		case "player-read":
			return &BearerIdentity{UID: 1, ClientID: "1", Scopes: []string{"Player.Read"}}, nil
		case "wildcard":
			return &BearerIdentity{UID: 1, ClientID: "1", Scopes: []string{"*"}}, nil
		case "empty":
			return &BearerIdentity{UID: 1, ClientID: "1"}, nil
		case "wrong-case":
			return &BearerIdentity{UID: 1, ClientID: "1", Scopes: []string{"user.read"}}, nil
		}
		return nil, errors.New("invalid token")
	}

	call := func(t *testing.T, authorization string) *http.Response {
		t.Helper()
		r := request(http.MethodGet, "/api/user", "")
		if authorization != "" {
			r.Header.Set("Authorization", authorization)
		}
		return do(t, env, r).Result()
	}

	for name, authorization := range map[string]string{
		"missing":   "",
		"malformed": "Token abc",
		"invalid":   "Bearer nope",
	} {
		t.Run(name, func(t *testing.T) {
			if status := call(t, authorization).StatusCode; status != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", status)
			}
		})
	}

	for name, token := range map[string]string{
		"player-read": "player-read",
		"empty":       "empty",
		"wrong-case":  "wrong-case",
	} {
		t.Run(name, func(t *testing.T) {
			response := call(t, "Bearer "+token)
			if response.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", response.StatusCode)
			}
			var body jsonBody
			if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Code != 403 || body.Message != msgMissingScope || body.Data != nil {
				t.Fatalf("body = %+v, want code 403 and %q", body, msgMissingScope)
			}
		})
	}

	for name, token := range map[string]string{
		"user-read":      "user-read",
		"user-read-plus": "user-read-plus",
		"wildcard":       "wildcard",
	} {
		t.Run(name, func(t *testing.T) {
			response := call(t, "Bearer "+token)
			if response.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", response.StatusCode)
			}
			var body map[string]any
			if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["uid"] != float64(1) {
				t.Fatalf("body = %v", body)
			}
		})
	}
}

// TestMissingScopeDoesNotLeakProfile guards the ordering: the scope check runs
// before the handler reads the user.
func TestMissingScopeDoesNotLeakProfile(t *testing.T) {
	env := newTestEnv(t)
	env.server.cfg.Users = &fakeUsers{user: &users.User{
		UID: 1, Email: "secret@example.invalid", Nickname: "Secret",
	}}
	env.server.cfg.Bearer = func(context.Context, string) (*BearerIdentity, error) {
		return &BearerIdentity{UID: 1, Scopes: []string{"Player.Read"}}, nil
	}
	r := request(http.MethodGet, "/api/user", "")
	r.Header.Set("Authorization", "Bearer anything")
	rec := do(t, env, r)
	if strings.Contains(rec.Body.String(), "secret@example.invalid") {
		t.Fatalf("denied response leaked account data: %s", rec.Body.String())
	}
}
