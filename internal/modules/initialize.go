package modules

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"paradise-cosmetics-studio/internal/database"
)

// Manifest declares the original installed module set for the first offline
// takeover. The statement is explicit: no module gains installation facts just
// because the Go binary contains the four declarations.
type Manifest struct {
	Installed []Entry `json:"installed"`
}

// LoadManifest parses the declared module manifest file; an empty file path
// declares nothing, which leaves an absent install ledger impossible to
// create.
func LoadManifest(path string) (*Manifest, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read declared module manifest")
	}
	var manifest struct {
		Installed []Entry `json:"installed"`
	}
	if err = json.Unmarshal(b, &manifest); err != nil {
		return nil, errors.New("declared module manifest must be a JSON object")
	}
	seen := map[string]bool{}
	for _, entry := range manifest.Installed {
		if entry.Legacy != "" || entry.Name == "" || entry.Version == "" {
			return nil, errors.New("declared module manifest entries need non-empty name and version")
		}
		if _, ok := meta(entry.Name); !ok {
			return nil, fmt.Errorf("declared module manifest lists unsupported module %s", entry.Name)
		}
		if seen[entry.Name] {
			return nil, fmt.Errorf("declared module manifest repeats module %s", entry.Name)
		}
		seen[entry.Name] = true
	}
	return &Manifest{Installed: manifest.Installed}, nil
}

// Initialize runs during the explicit offline takeover only. Missing rows are
// created from the declared facts inside one transaction; existing rows stay
// untouched so repeated takeovers and runtime module operations never lose
// state. Duplicate option rows keep their history and fail reads.
func Initialize(ctx context.Context, store *database.Store, snapshot map[string]string, manifest *Manifest) error {
	rows, err := discoverRows(ctx, store, store.DB, stateKeys...)
	if err != nil {
		return err
	}
	var missing []string
	for _, key := range stateKeys {
		switch {
		case len(rows[key]) > 1:
			return fmt.Errorf("%w: %s", ErrStateAmbiguous, key)
		case len(rows[key]) == 0:
			missing = append(missing, key)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	if contains(missing, installOptionKey) && manifest == nil {
		return errors.New("declared module manifest required to initialize go_module_installations")
	}
	return store.Transaction(ctx, func(tx *sql.Tx) error {
		// Recheck inside the transaction; another offline process could have
		// inserted the rows between the outer discovery and this commit.
		racing, err := discoverRows(ctx, store, tx, stateKeys...)
		if err != nil {
			return err
		}
		if err != nil {
			return err
		}
		for _, key := range missing {
			if len(racing[key]) != 0 {
				// Someone else won; do not rewrite their initialization.
				continue
			}
			value, err := initialValue(key, snapshot, manifest)
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO "+store.Table("options")+" (option_name,option_value) VALUES (?,?)", key, value); err != nil {
				return err
			}
		}
		return nil
	})
}

func initialValue(key string, snapshot map[string]string, manifest *Manifest) (string, error) {
	if key == enableOptionKey {
		return snapshot[key], nil
	}
	value, err := encodeEntries(manifest.Installed)
	if err != nil {
		return "", err
	}
	return value, nil
}

func contains(list []string, key string) bool {
	for _, item := range list {
		if item == key {
			return true
		}
	}
	return false
}
