package oauthserver

import (
	"encoding/json"
	"testing"
)

// Focused frozen-contract JSON checks; no database is needed. DB-backed
// client/scope/PAT behaviour is covered by the httpapp passport tests
// when a DSN is available (skipped otherwise, never counted as pass).

func TestCompatClientRowRedirectStringJSON(t *testing.T) {
	body, err := json.Marshal(ClientRow{ID: 1, Name: "c", Redirect: "https://a.example.invalid/,https://b.example.invalid/"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Redirect string `json:"redirect"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("redirect string contract: %v body=%s", err, body)
	}
	if decoded.Redirect != "https://a.example.invalid/,https://b.example.invalid/" {
		t.Fatalf("redirect=%q body=%s", decoded.Redirect, body)
	}
}

func TestCompatScopeDescriptionIDJSON(t *testing.T) {
	body, err := json.Marshal(ScopeDescription{ID: "Player.Read", Description: "auth.oauth.scope.player.read"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		ID          string `json:"id"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ID != "Player.Read" || decoded.Description != "auth.oauth.scope.player.read" {
		t.Fatalf("scope body=%s", body)
	}
}

func TestCompatPersonalTokenIDJSON(t *testing.T) {
	body, err := json.Marshal(PersonalToken{ID: "request-id", AccessToken: "opaque", Name: "pat"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ID != "request-id" {
		t.Fatalf("personal token id body=%s", body)
	}
}
