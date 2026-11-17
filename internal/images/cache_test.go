package images

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/site"
)

func TestDerivedCacheLifetime(t *testing.T) {
	for _, option := range []string{"enable_avatar_cache", "enable_preview_cache"} {
		for _, enabled := range []bool{false, true} {
			t.Run(option+"/"+map[bool]string{false: "minute", true: "year"}[enabled], func(t *testing.T) {
				now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
				value := "false"
				if enabled {
					value = "true"
				}
				s := New(nil, &site.Service{OptionSnapshot: map[string]string{option: value}}, nil, func() time.Time { return now })
				renders := 0
				render := func() ([]byte, error) { renders++; return []byte{byte(renders)}, nil }
				key := cacheKey{Name: "synthetic"}
				first, err := s.cached(context.Background(), key, option, render)
				if err != nil {
					t.Fatal(err)
				}
				expires := now.Add(time.Minute)
				if enabled {
					expires = now.AddDate(1, 0, 0)
				}
				now = expires.Add(-time.Nanosecond)
				hit, err := s.cached(context.Background(), key, option, render)
				if err != nil {
					t.Fatal(err)
				}
				if string(first) != string(hit) || renders != 1 {
					t.Fatal("cache expired early")
				}
				now = expires
				refreshed, err := s.cached(context.Background(), key, option, render)
				if err != nil {
					t.Fatal(err)
				}
				if string(first) == string(refreshed) || renders != 2 {
					t.Fatal("expired representation reused")
				}
			})
		}
	}
}

func TestConditionalResponsesAndZeroMaxAge(t *testing.T) {
	s := New(nil, &site.Service{OptionSnapshot: map[string]string{"cache_expire_time": "0"}}, nil, nil)
	modified := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	payload := []byte("synthetic image")
	for _, tc := range []struct {
		name, method, etag, since string
		status                    int
	}{
		{"head", "HEAD", "", "", 200},
		{"etag-list", "GET", `"other", ` + etag(payload), "", 304},
		{"weak-etag", "GET", "W/" + etag(payload), "", 304},
		{"etag-precedence", "GET", `"other"`, modified.Format("Mon, 02 Jan 2006 15:04:05 GMT"), 200},
		{"modified", "GET", "", modified.Format("Mon, 02 Jan 2006 15:04:05 GMT"), 304},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://localhost/preview/1", nil)
			if tc.etag != "" {
				r.Header.Set("If-None-Match", tc.etag)
			}
			if tc.since != "" {
				r.Header.Set("If-Modified-Since", tc.since)
			}
			w := httptest.NewRecorder()
			if err := s.ServeBytes(w, r, payload, "image/png", modified); err != nil {
				t.Fatal(err)
			}
			if w.Code != tc.status {
				t.Fatalf("status=%d want %d", w.Code, tc.status)
			}
			if (tc.method == "HEAD" || tc.status == 304) && w.Body.Len() != 0 {
				t.Fatal("unexpected response body")
			}
			if w.Header().Get("Cache-Control") != "public, max-age=0" {
				t.Fatal("zero max-age replaced")
			}
		})
	}
}
