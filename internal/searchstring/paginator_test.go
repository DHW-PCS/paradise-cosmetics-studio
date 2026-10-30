package searchstring

import (
	"encoding/json"
	"os"
	"testing"
)

// Frozen expectations from oracle/paginator_probe.php (Laravel 8.75 runtime in
// the 6.0.2 vendor tree). Regenerate with the probe; never derive them here.
const frozenPaginatorFixture = "testdata/paginator_oracle.json"

type paginatorOracle struct {
	Current      int        `json:"current"`
	Total        int        `json:"total"`
	PerPage      int        `json:"per_page"`
	LastPage     int        `json:"last_page"`
	From         *int       `json:"from"`
	To           *int       `json:"to"`
	FirstPageURL string     `json:"first_page_url"`
	LastPageURL  string     `json:"last_page_url"`
	NextPageURL  *string    `json:"next_page_url"`
	PrevPageURL  *string    `json:"prev_page_url"`
	Path         string     `json:"path"`
	Links        []PageLink `json:"links"`
}

func TestPaginatorMatchesFrozenLaravel(t *testing.T) {
	raw, err := os.ReadFile(frozenPaginatorFixture)
	if err != nil {
		t.Fatal(err)
	}
	var cases []paginatorOracle
	if err = json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, want := range cases {
		items := make([]string, want.PerPage)
		got := NewPaginator(items, want.Current, want.PerPage, want.Total, want.Path)
		if got.LastPage != want.LastPage {
			t.Errorf("current=%d total=%d: last_page=%d, want %d", want.Current, want.Total, got.LastPage, want.LastPage)
		}
		if !equalIntPtr(got.From, want.From) || !equalIntPtr(got.To, want.To) {
			t.Errorf("current=%d total=%d: from/to=%v/%v, want %v/%v", want.Current, want.Total, got.From, got.To, want.From, want.To)
		}
		if got.FirstPageURL == nil || *got.FirstPageURL != want.FirstPageURL {
			t.Errorf("current=%d total=%d: first=%v, want %s", want.Current, want.Total, got.FirstPageURL, want.FirstPageURL)
		}
		if got.LastPageURL == nil || *got.LastPageURL != want.LastPageURL {
			t.Errorf("current=%d total=%d: last=%v, want %s", want.Current, want.Total, got.LastPageURL, want.LastPageURL)
		}
		if !equalStringPtr(got.NextPageURL, want.NextPageURL) {
			t.Errorf("current=%d total=%d: next=%v, want %v", want.Current, want.Total, got.NextPageURL, want.NextPageURL)
		}
		if !equalStringPtr(got.PrevPageURL, want.PrevPageURL) {
			t.Errorf("current=%d total=%d: prev=%v, want %v", want.Current, want.Total, got.PrevPageURL, want.PrevPageURL)
		}
		if len(got.Links) != len(want.Links) {
			t.Errorf("current=%d total=%d: %d links, want %d (%v vs %v)", want.Current, want.Total, len(got.Links), len(want.Links), labelsOf(got.Links), labelsOf(want.Links))
			continue
		}
		for index := range got.Links {
			a, b := got.Links[index], want.Links[index]
			if a.Label != b.Label || a.Active != b.Active || !equalStringPtr(a.URL, b.URL) {
				t.Errorf("current=%d total=%d link %d: %+v, want %+v", want.Current, want.Total, index, a, b)
			}
		}
	}
}

func labelsOf(links []PageLink) []string {
	out := make([]string, len(links))
	for index, link := range links {
		out[index] = link.Label
	}
	return out
}

func equalStringPtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
