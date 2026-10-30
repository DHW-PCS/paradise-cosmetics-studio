// Package searchstring also owns the Laravel-shaped paginator shared by every
// management list. The JSON keys, the link window and the untranslated labels
// mirror Illuminate\Pagination\LengthAwarePaginator with the framework defaults
// (onEachSide = 3, no pagination.php language file in the frozen app).
package searchstring

import (
	"reflect"
	"strconv"
)

// PageLink is one entry of the frozen paginator's links array.
type PageLink struct {
	URL    *string `json:"url"`
	Label  string  `json:"label"`
	Active bool    `json:"active"`
}

// Paginator mirrors Laravel's LengthAwarePaginator JSON shape.
type Paginator struct {
	Data         any        `json:"data"`
	CurrentPage  int        `json:"current_page"`
	FirstPageURL *string    `json:"first_page_url"`
	From         *int       `json:"from"`
	LastPage     int        `json:"last_page"`
	LastPageURL  *string    `json:"last_page_url"`
	Links        []PageLink `json:"links"`
	NextPageURL  *string    `json:"next_page_url"`
	Path         string     `json:"path"`
	PerPage      int        `json:"per_page"`
	PrevPageURL  *string    `json:"prev_page_url"`
	To           *int       `json:"to"`
	Total        int        `json:"total"`
}

// Labels are taken verbatim from LengthAwarePaginator::linkCollection(), which
// falls back to the raw key because the frozen app ships no pagination.php.
const (
	previousLabel = "pagination.previous"
	nextLabel     = "pagination.next"
)

// NewPaginator fills a paginator exactly like LengthAwarePaginator does for a
// plain paginate() call: the path carries no query string (frozen controllers
// never call withQueryString) and pages are addressed as "<path>?page=N".
func NewPaginator(data any, current, perPage, total int, path string) *Paginator {
	if current < 1 {
		current = 1
	}
	if perPage < 1 {
		perPage = 1
	}
	last := 1
	if total > 0 {
		// Computed this way to avoid overflowing for legitimate MaxInt page
		// sizes (M3 remediation finding; the frozen paginate() would divide by
		// the same value).
		last = (total-1)/perPage + 1
	}
	out := &Paginator{
		Data:        data,
		CurrentPage: current,
		LastPage:    last,
		PerPage:     perPage,
		Total:       total,
		Path:        path,
	}
	pageURL := func(page int) *string {
		value := pageAddress(path, page)
		return &value
	}
	out.FirstPageURL = pageURL(1)
	out.LastPageURL = pageURL(last)
	if current < last && current <= last {
		out.NextPageURL = pageURL(current + 1)
	}
	if current > 1 {
		out.PrevPageURL = pageURL(current - 1)
	}
	if count := itemCount(data); count > 0 && total > 0 {
		from := (current-1)*perPage + 1
		to := from + count - 1
		if to > total {
			to = total
		}
		out.From, out.To = &from, &to
	}
	out.Links = PageLinks(current, last, path)
	return out
}

// WindowRanges returns the UrlWindow element groups for one page: the leading
// range, an optional ellipsis marker, the sliding range and the trailing range.
// The second return value reports whether a "..." separator precedes each group.
func WindowRanges(current, last int) [][]int {
	const onEachSide = 3
	window := onEachSide + 4
	rangeOf := func(from, to int) []int {
		if to < from {
			return nil
		}
		out := make([]int, 0, to-from+1)
		for page := from; page <= to; page++ {
			out = append(out, page)
		}
		return out
	}
	if last < onEachSide*2+8 {
		return [][]int{rangeOf(1, last)}
	}
	switch {
	case current <= window:
		return [][]int{rangeOf(1, window+onEachSide), rangeOf(last-1, last)}
	case current > last-window:
		return [][]int{rangeOf(1, 2), rangeOf(last-(window+onEachSide-1), last)}
	}
	return [][]int{
		rangeOf(1, 2),
		rangeOf(current-onEachSide, current+onEachSide),
		rangeOf(last-1, last),
	}
}

// PageLinks reproduces linkCollection(): one Previous entry, the UrlWindow
// elements with "..." separators, then one Next entry.
func PageLinks(current, last int, path string) []PageLink {
	pageURL := func(page int) *string {
		value := pageAddress(path, page)
		return &value
	}
	links := []PageLink{{Label: previousLabel}}
	if current > 1 {
		links[0].URL = pageURL(current - 1)
	}
	for index, group := range WindowRanges(current, last) {
		if index > 0 {
			links = append(links, PageLink{Label: "..."})
		}
		for _, page := range group {
			links = append(links, PageLink{URL: pageURL(page), Label: strconv.Itoa(page), Active: page == current})
		}
	}
	next := PageLink{Label: nextLabel}
	if current < last {
		next.URL = pageURL(current + 1)
	}
	return append(links, next)
}

func pageAddress(base string, page int) string {
	return base + "?page=" + strconv.Itoa(page)
}

// itemCount reports how many rows a concrete page actually carries.
func itemCount(data any) int {
	value := reflect.ValueOf(data)
	if !value.IsValid() {
		return 0
	}
	if value.Kind() == reflect.Slice || value.Kind() == reflect.Array {
		return value.Len()
	}
	return 0
}
