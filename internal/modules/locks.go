package modules

import (
	"context"
	"database/sql"
	"sort"
)

// lockModuleRows point-locks the discovered rows by ascending id and then
// re-reads their current values under the same lock suffix, verifying the
// id-to-key-name plan still holds. It never re-scans the unindexed option
// name inside a locking read.
func (m *Manager) lockModuleRows(ctx context.Context, tx *sql.Tx, plan map[string]optionsRow, mode string) (map[string]optionsRow, error) {
	ids := make([]int64, 0, 2)
	for _, key := range stateKeys {
		ids = append(ids, plan[key].id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, "SELECT id FROM "+m.Store.Table("options")+" WHERE id=? "+mode, id); err != nil {
			return nil, err
		}
	}
	current := map[string]optionsRow{}
	rows, err := tx.QueryContext(ctx, "SELECT id,option_name,option_value FROM "+m.Store.Table("options")+" WHERE id IN ("+placeholders(len(ids))+") ORDER BY id "+mode, idsValues(ids)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var row optionsRow
		if err = rows.Scan(&row.id, &row.name, &row.value); err != nil {
			return nil, err
		}
		locked, ok := plan[row.name]
		if !ok || locked.id != row.id {
			return nil, ErrStatePlanConflict
		}
		current[row.name] = row
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(current) != len(plan) {
		return nil, ErrStatePlanConflict
	}
	return current, nil
}

func placeholders(count int) string {
	list := ""
	for i := 0; i < count; i++ {
		if i > 0 {
			list += ","
		}
		list += "?"
	}
	return list
}

func keysValues(keys []string) []any {
	values := make([]any, 0, len(keys))
	for _, key := range keys {
		values = append(values, key)
	}
	return values
}

func idsValues(ids []int64) []any {
	values := make([]any, 0, len(ids))
	for _, id := range ids {
		values = append(values, id)
	}
	return values
}
