package site

import (
	"context"
	"encoding/json"
	"strings"
)

// Translations builds a request-owned table: fallback files, locale files and
// persisted language_lines. No request mutates the embedded shared messages.
func (s *Service) Translations(ctx context.Context, locale, fallback string, files map[string]map[string]any) (map[string]any, error) {
	result := map[string]any{}
	mergeMessages(result, files[fallback])
	mergeMessages(result, files[locale])
	rows, err := s.Store.DB.QueryContext(ctx, "SELECT `group`,`key`,text FROM "+s.Store.Table("language_lines")+" ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var group, key, raw string
		if err = rows.Scan(&group, &key, &raw); err != nil {
			return nil, err
		}
		var values map[string]*string
		if err = json.Unmarshal([]byte(raw), &values); err != nil {
			return nil, err
		}
		value := values[locale]
		if value == nil {
			value = values[fallback]
		}
		if value == nil {
			continue
		}
		setMessage(result, strings.Split(group+"."+key, "."), *value)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
func mergeMessages(destination, source map[string]any) {
	for key, value := range source {
		if child, ok := value.(map[string]any); ok {
			next, ok := destination[key].(map[string]any)
			if !ok {
				next = map[string]any{}
				destination[key] = next
			}
			mergeMessages(next, child)
		} else {
			destination[key] = value
		}
	}
}
func setMessage(destination map[string]any, path []string, value string) {
	for _, key := range path[:len(path)-1] {
		next, ok := destination[key].(map[string]any)
		if !ok {
			next = map[string]any{}
			destination[key] = next
		}
		destination = next
	}
	destination[path[len(path)-1]] = value
}
