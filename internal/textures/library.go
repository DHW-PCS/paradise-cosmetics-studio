package textures

import (
	"context"
	"strconv"

	"paradise-cosmetics-studio/internal/identity"
)

const libraryPerPage = 20

type LibraryParams struct {
	Filter, Keyword string
	Uploader        int64
	Sort            string
	Page            int
}

type LibraryItem struct {
	TID      int64  `json:"tid"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Uploader int64  `json:"uploader"`
	Public   bool   `json:"public"`
	Likes    int64  `json:"likes"`
	Nickname string `json:"nickname"`
}

type LibraryPage struct {
	Data         []LibraryItem `json:"data"`
	CurrentPage  int           `json:"current_page"`
	FirstPageURL *string       `json:"first_page_url"`
	From         *int          `json:"from"`
	LastPage     int           `json:"last_page"`
	LastPageURL  *string       `json:"last_page_url"`
	Links        []PageLink    `json:"links"`
	NextPageURL  *string       `json:"next_page_url"`
	Path         string        `json:"path"`
	PerPage      int           `json:"per_page"`
	PrevPageURL  *string       `json:"prev_page_url"`
	To           *int          `json:"to"`
	Total        int           `json:"total"`
}

type PageLink struct {
	URL    *string `json:"url"`
	Label  string  `json:"label"`
	Active bool    `json:"active"`
}

func libraryLink(base string, page int) string { return base + strconv.Itoa(page) }

// Library implements the frozen skinlib list query: type filter, keyword LIKE,
// uploader, time/likes sort, public-or-own visibility and 20 per page.
func (s *Service) Library(ctx context.Context, viewer *identity.User, params LibraryParams, path, base string) (*LibraryPage, error) {
	if params.Page < 1 {
		params.Page = 1
	}
	where := " WHERE 1=1"
	args := []any{}
	switch params.Filter {
	case "steve", "alex", "cape":
		where += " AND t.type=?"
		args = append(args, params.Filter)
	case "skin":
		where += " AND t.type IN ('steve','alex')"
	default:
		where += " AND t.type IN ('steve','alex')"
	}
	if params.Keyword != "" {
		where += " AND t.name LIKE ?"
		args = append(args, "%"+params.Keyword+"%")
	}
	if params.Uploader != 0 {
		where += " AND t.uploader=?"
		args = append(args, params.Uploader)
	}
	if viewer == nil {
		where += " AND t.public=1"
	} else if viewer.Permission < 1 {
		where += " AND (t.public=1 OR t.uploader=?)"
		args = append(args, viewer.UID)
	}
	order := "t.upload_at DESC"
	if params.Sort == "likes" {
		order = "t.likes DESC"
	}
	out := &LibraryPage{CurrentPage: params.Page, LastPage: 1, PerPage: libraryPerPage, Path: path, Links: []PageLink{}}
	if err := s.Store.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("textures")+" t JOIN "+s.Store.Table("users")+" u ON u.uid=t.uploader"+where, args...).Scan(&out.Total); err != nil {
		return nil, err
	}
	if out.Total > 0 {
		out.LastPage = (out.Total + libraryPerPage - 1) / libraryPerPage
	}
	rows, err := s.Store.DB.QueryContext(ctx, "SELECT t.tid,t.name,t.type,t.uploader,t.public,t.likes,u.nickname FROM "+s.Store.Table("textures")+" t JOIN "+s.Store.Table("users")+" u ON u.uid=t.uploader"+where+" ORDER BY "+order+" LIMIT ? OFFSET ?",
		append(args, libraryPerPage, (params.Page-1)*libraryPerPage)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out.Data = []LibraryItem{}
	for rows.Next() {
		var item LibraryItem
		if err = rows.Scan(&item.TID, &item.Name, &item.Type, &item.Uploader, &item.Public, &item.Likes, &item.Nickname); err != nil {
			return nil, err
		}
		out.Data = append(out.Data, item)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(out.Data) > 0 {
		from := (params.Page-1)*libraryPerPage + 1
		to := from + len(out.Data) - 1
		out.From, out.To = &from, &to
	}
	first := libraryLink(base, 1)
	last := libraryLink(base, out.LastPage)
	out.FirstPageURL, out.LastPageURL = &first, &last
	if params.Page < out.LastPage {
		next := libraryLink(base, params.Page+1)
		out.NextPageURL = &next
	}
	if params.Page > 1 {
		prev := libraryLink(base, params.Page-1)
		out.PrevPageURL = &prev
	}
	links := []PageLink{{Label: "&laquo; Previous"}}
	if out.PrevPageURL != nil {
		url := *out.PrevPageURL
		links[0].URL = &url
	}
	numbers := []int{}
	if out.LastPage <= 7 {
		for page := 1; page <= out.LastPage; page++ {
			numbers = append(numbers, page)
		}
	} else {
		numbers = append(numbers, 1)
		start, end := params.Page-1, params.Page+1
		if start < 2 {
			start = 2
		}
		if end > out.LastPage-1 {
			end = out.LastPage - 1
		}
		if start > 2 {
			links = append(links, PageLink{Label: "..."})
		}
		for page := start; page <= end; page++ {
			numbers = append(numbers, page)
		}
		if end < out.LastPage-1 {
			links = append(links, PageLink{Label: "..."})
		}
		numbers = append(numbers, out.LastPage)
	}
	for _, page := range numbers {
		url := libraryLink(base, page)
		links = append(links, PageLink{URL: &url, Label: strconv.Itoa(page), Active: page == params.Page})
	}
	next := PageLink{Label: "Next &raquo;"}
	if out.NextPageURL != nil {
		url := *out.NextPageURL
		next.URL = &url
	}
	links = append(links, next)
	out.Links = links
	return out, nil
}
