package httpapp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAdminScoreChange(t *testing.T) {
	h, id := appFixture(t)
	admin, csrf := credentials(t, h, true)
	user, userCSRF := credentials(t, h, false)
	if _, err := id.Store.DB.Exec("INSERT INTO " + id.Store.Table("users") + " (uid,email,nickname,password,permission,verified,score) VALUES (3,'peer@example.invalid','Peer','',2,1,90)"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		body string
		want int64
	}{
		{"positive", `{"score":321}`, 321},
		{"zero", `{"score":0}`, 0},
		{"negative", `{"score":-23}`, -23},
		{"integer-string", `{"score":"42"}`, 42},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request(t, h, "PUT", "/admin/users/1/score", tc.body, csrf, admin)
			var response struct{ Code int }
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Code != 0 {
				t.Fatalf("score response: %d %s", w.Code, w.Body.String())
			}
			if got := score(t, id, 1); got != tc.want {
				t.Fatalf("score = %d, want %d", got, tc.want)
			}
		})
	}
	for _, body := range []string{`{}`, `{"score":null}`, `{"score":""}`, `{"score":false}`, `{"score":1.5}`, `{"score":"oops"}`} {
		t.Run("invalid/"+body, func(t *testing.T) {
			w := request(t, h, "PUT", "/admin/users/1/score", body, csrf, admin)
			if w.Code != 422 || !strings.Contains(w.Body.String(), `"errors":{"score"`) {
				t.Fatalf("validation response: %d %s", w.Code, w.Body.String())
			}
			if got := score(t, id, 1); got != 42 {
				t.Fatalf("invalid request changed score to %d", got)
			}
		})
	}
	if w := request(t, h, "PUT", "/admin/users/2/score", `{"score":-9}`, csrf, admin); w.Code != 200 || score(t, id, 2) != -9 {
		t.Fatalf("self score change failed: %d %s", w.Code, w.Body.String())
	}
	if w := request(t, h, "PUT", "/admin/users/3/score", `{"score":7}`, csrf, admin); w.Code != 403 || score(t, id, 3) != 90 {
		t.Fatalf("peer permission/state: %d %s", w.Code, w.Body.String())
	}
	if w := request(t, h, "PUT", "/admin/users/1/score", `{"score":7}`, userCSRF, user); w.Code != 403 || score(t, id, 1) != 42 {
		t.Fatalf("ordinary user permission/state: %d %s", w.Code, w.Body.String())
	}
	if w := request(t, h, "PUT", "/admin/users/9999/score", `{"score":7}`, csrf, admin); w.Code != 404 {
		t.Fatalf("missing user: %d %s", w.Code, w.Body.String())
	}
}
