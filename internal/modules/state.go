package modules

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"blessing-skin-go/internal/database"
)

// Entry is one item of the two state arrays. Object entries keep name/version;
// original string entries ride along verbatim and carry no module facts.
type Entry struct {
	Name    string
	Version string
	Legacy  string
	// Raw keeps the unchanged stored item bytes; rewriting entries re-encodes
	// exactly the original saveEnabled() object shape.
	Raw string
}

func decodeEntries(raw string) ([]Entry, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return nil, fmt.Errorf("%w: plugin state array", ErrStateInvalid)
	}
	entries := make([]Entry, 0, len(items))
	first := map[string]int{}
	for _, item := range items {
		var text string
		var object struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if err := json.Unmarshal(item, &text); err == nil {
			// The original PluginManager rejected string entries without
			// touching them; they stay out of the module map but every rewrite
			// must keep them.
			entries = append(entries, Entry{Legacy: text, Raw: string(item)})
			continue
		}
		if err := json.Unmarshal(item, &object); err != nil || object.Name == "" {
			return nil, fmt.Errorf("%w: module entry", ErrStateInvalid)
		}
		if slot, ok := first[object.Name]; ok {
			// The original collect() keys entries by name: a repeated name
			// keeps its position and the latest stored value wins.
			entries[slot] = Entry{Name: object.Name, Version: object.Version, Raw: string(item)}
			continue
		}
		first[object.Name] = len(entries)
		entries = append(entries, Entry{Name: object.Name, Version: object.Version, Raw: string(item)})
	}
	return entries, nil
}

// encodeEntries rebuilds the array; unchanged items re-emit their stored bytes
// and items added in this runtime use the original object shape.
func encodeEntries(entries []Entry) (string, error) {
	items := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Raw != "" {
			items = append(items, entry.Raw)
			continue
		}
		switch {
		case entry.Legacy != "" && entry.Name == "":
			items = append(items, jsonText(entry.Legacy))
		case entry.Name != "":
			items = append(items, jsonText(map[string]string{"name": entry.Name, "version": entry.Version}))
		default:
			return "", fmt.Errorf("%w: empty module entry", ErrStateInvalid)
		}
	}
	return "[" + strings.Join(items, ",") + "]", nil
}

func jsonText(value any) string {
	b, _ := json.Marshal(value)
	return string(b)
}

// State is the parsed module facts of one consistent read. Relying callers
// must hold the read inside the transaction that performed it.
type State struct {
	Enabled   []Entry
	Installed []Entry
}

// HasEnabled reports whether an enable entry exists for the name.
func (s *State) HasEnabled(name string) bool { return hasEntry(s.Enabled, name) }

// HasInstalled reports whether the module is registered at this station.
// Names outside the supported set exist as out-of-scope entries but never
// acquire execution capability.
func (s *State) HasInstalled(name string) bool {
	if !hasEntry(s.Installed, name) {
		return false
	}
	_, ok := meta(name)
	return ok
}

func hasEntry(entries []Entry, name string) bool {
	for _, entry := range entries {
		if entry.Name == name {
			return true
		}
	}
	return false
}

// EnabledEligibilities lists registration-restricting module names with an
// enable entry. Each one must be consulted by a connected consumer inside the
// registration transaction.
func (s *State) EnabledEligibilities() []string {
	enabled := make([]string, 0, 1)
	for _, name := range EligibilityConsumers {
		if s.HasEnabled(name) {
			enabled = append(enabled, name)
		}
	}
	return enabled
}

type optionsRow struct {
	id    int64
	name  string
	value string
}

func (r optionsRow) entry() ([]Entry, error) { return decodeEntries(r.value) }

type rowSet map[string][]optionsRow

// discoverRows reads the rows of the given option keys without locking. Name
// scanning is discovery only; decisions must stand on locked current reads.
func discoverRows(ctx context.Context, store *database.Store, reader rowsReader, keys ...string) (rowSet, error) {
	found := rowSet{}
	query := "SELECT id,option_name,option_value FROM " + store.Table("options") + " WHERE option_name IN (" + placeholders(len(keys)) + ")"
	rows, err := reader.QueryContext(ctx, query, keysValues(keys)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var row optionsRow
		if err = rows.Scan(&row.id, &row.name, &row.value); err != nil {
			return nil, err
		}
		known, ok := found[row.name]
		if !ok {
			known = []optionsRow{}
		}
		found[row.name] = append(known, row)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return found, nil
}

type rowsReader interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

var stateKeys = []string{enableOptionKey, installOptionKey}

// plan collects the two module-state rows for transactional work. Duplicate
// rows and missing rows are state errors kept as historical facts.
func (m *Manager) plan(ctx context.Context, reader rowsReader) (map[string]optionsRow, error) {
	rows, err := discoverRows(ctx, m.Store, reader, stateKeys...)
	if err != nil {
		return nil, err
	}
	found := map[string]optionsRow{}
	for _, key := range stateKeys {
		many := rows[key]
		if len(many) > 1 {
			return nil, fmt.Errorf("%w: %s", ErrStateAmbiguous, key)
		}
		if len(many) == 0 {
			return nil, fmt.Errorf("%w: %s", ErrStateMissing, key)
		}
		found[key] = many[0]
	}
	return found, nil
}

func parseState(found map[string]optionsRow) (*State, error) {
	enabled, err := found[enableOptionKey].entry()
	if err != nil {
		return nil, err
	}
	installed, err := found[installOptionKey].entry()
	if err != nil {
		return nil, err
	}
	return &State{Enabled: enabled, Installed: installed}, nil
}

// RequestState provides the module facts of one consistent statement for
// display assembly. Writes always recheck the current rows inside their own
// transaction.
func (m *Manager) RequestState(ctx context.Context) (*State, error) {
	found, err := m.plan(ctx, m.Store.DB)
	if err != nil {
		return nil, err
	}
	return parseState(found)
}

// RequestValues provides the raw stored values of the two module-state keys
// from one consistent statement. Display assembly uses them to keep menus and
// pages aligned with served routes while the option snapshot contract stays
// unchanged for every other key.
func (m *Manager) RequestValues(ctx context.Context) (map[string]string, error) {
	plan, err := m.plan(ctx, m.Store.DB)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		enableOptionKey:  plan[enableOptionKey].value,
		installOptionKey: plan[installOptionKey].value,
	}, nil
}

// LockStateTx installs the shared current read for dependency-module business
// writes inside an existing transaction. Discovery, per-id point locks in
// ascending order and re-verified key names bind the state to that commit.
func (m *Manager) LockStateTx(ctx context.Context, tx *sql.Tx) (*State, error) {
	plan, err := m.plan(ctx, tx)
	if err != nil {
		return nil, err
	}
	current, err := m.lockModuleRows(ctx, tx, plan, "LOCK IN SHARE MODE")
	if err != nil {
		return nil, err
	}
	return parseState(current)
}
