package players

import (
	"context"
	"database/sql"

	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/searchstring"
)

// PageLink and Paginator are the shared Laravel-shaped paginator.
type PageLink = searchstring.PageLink

type Paginator = searchstring.Paginator

const perPage = 10

func (s *Service) schema() searchstring.Schema {
	return searchstring.Schema{
		Columns: []searchstring.Column{
			{Name: "pid"},
			{Name: "uid"},
			{Name: "tid_skin", Pattern: `^(?:tid_)?skin$`},
			{Name: "tid_cape", Pattern: `^(?:tid_)?cape$`},
			{Name: "name", Searchable: true},
			{Name: "last_modified", Date: true, Boolean: true},
		},
		Location: s.Site.Location,
		Now:      s.Now,
	}
}

// AdminList returns the frozen admin players paginator for ?q=&page=.
// It is the browser page entry; authorization is enforced by the
// browser admin route, as before. Core API callers must use
// AdminListActor, which rechecks the actor in-transaction.
func (s *Service) AdminList(ctx context.Context, page int, query, path string) (*Paginator, error) {
	return s.adminList(ctx, s.Store.DB, page, query, path)
}

// AdminListActor returns the full players paginator (every account,
// never the actor's own list) after rechecking the actor in the same
// transaction with PlayersManagement.Read or PlayersManagement.ReadWrite
// and requiring current permission >= admin. Pagination, search and
// ordering are the frozen AdminList semantics.
func (s *Service) AdminListActor(ctx context.Context, actor identity.Actor, page int, query, path string) (*Paginator, error) {
	var out *Paginator
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		current, _, err := s.recheckActor(ctx, tx, actor, playersAdminReadScope)
		if err != nil {
			return err
		}
		if current.Permission < 1 {
			return ErrNoPermission
		}
		value, err := s.adminList(ctx, tx, page, query, path)
		if err != nil {
			return err
		}
		out = value
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) adminList(ctx context.Context, q queryer, page int, query, path string) (*Paginator, error) {
	if page < 1 {
		page = 1
	}
	resolved := searchstring.Build(query, s.schema())
	if resolved.Err != nil {
		return nil, resolved.Err
	}
	where := ""
	var args []any
	if !resolved.Invalid && resolved.Where != "" {
		where = " WHERE " + resolved.Where
		args = resolved.Args
	}
	var total int
	if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("players")+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	order := ""
	if !resolved.Invalid && len(resolved.Order) > 0 {
		order = " ORDER BY "
		for i, entry := range resolved.Order {
			if i > 0 {
				order += ", "
			}
			order += entry.Column
			if entry.Desc {
				order += " DESC"
			} else {
				order += " ASC"
			}
		}
	}
	limitArgs := append(append([]any{}, args...), perPage, (page-1)*perPage)
	rows, err := q.QueryContext(ctx, "SELECT pid,uid,name,tid_skin,tid_cape,last_modified FROM "+s.Store.Table("players")+where+order+" LIMIT ? OFFSET ?", limitArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	players := []Player{}
	for rows.Next() {
		var player Player
		var modified sql.NullTime
		if err = rows.Scan(&player.PID, &player.UID, &player.Name, &player.TIDSkin, &player.TIDCape, &modified); err != nil {
			return nil, err
		}
		if modified.Valid {
			player.LastModified = modified.Time.In(s.Site.Location).Format("2006-01-02 15:04:05")
		}
		players = append(players, player)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(resolved.Select) > 0 && !resolved.Invalid {
		selected := make([]map[string]any, 0, len(players))
		for _, player := range players {
			row := map[string]any{}
			for _, column := range resolved.Select {
				switch column {
				case "pid":
					row["pid"] = player.PID
				case "uid":
					row["uid"] = player.UID
				case "tid_skin":
					row["tid_skin"] = player.TIDSkin
				case "tid_cape":
					row["tid_cape"] = player.TIDCape
				case "name":
					row["name"] = player.Name
				case "last_modified":
					row["last_modified"] = player.LastModified
				}
			}
			selected = append(selected, row)
		}
		return searchstring.NewPaginator(selected, page, perPage, total, path), nil
	}
	return searchstring.NewPaginator(players, page, perPage, total, path), nil
}
