// Package vectors loads and checks the cross-implementation vector files
// produced by tools/m1_session_vectors.php.
package vectors

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Schema is the only vector schema this package understands.
const Schema = "m1-cross-vectors/1"

// File is a generated vector bundle.
type File struct {
	Schema      string            `json:"schema"`
	GeneratedAt string            `json:"generated_at"`
	Source      map[string]string `json:"source"`
	Config      Config            `json:"config"`
	Users       []UserRow         `json:"users"`
	Vectors     []Vector          `json:"vectors"`
}

// Config captures the frozen runtime settings a vector was produced under.
type Config struct {
	AppKey       string         `json:"app_key"`
	AppKeySHA256 string         `json:"app_key_sha256"`
	Cipher       string         `json:"cipher"`
	Session      SessionConfig  `json:"session"`
	Guard        GuardConfig    `json:"guard"`
	Password     PasswordConfig `json:"password"`
	CSRF         CSRFConfig     `json:"csrf"`
}

type SessionConfig struct {
	Cookie          string  `json:"cookie"`
	Driver          string  `json:"driver"`
	LifetimeMinutes int     `json:"lifetime_minutes"`
	Encrypt         bool    `json:"encrypt"`
	Path            string  `json:"path"`
	Domain          *string `json:"domain"`
	Secure          bool    `json:"secure"`
	HTTPOnly        bool    `json:"http_only"`
	SameSite        string  `json:"same_site"`
	Files           string  `json:"files"`
}

type GuardConfig struct {
	Name            string `json:"name"`
	Class           string `json:"class"`
	LoginKey        string `json:"login_key"`
	RecallerName    string `json:"recaller_name"`
	RememberMinutes int    `json:"remember_minutes"`
}

type PasswordConfig struct {
	Method string `json:"method"`
	Salt   string `json:"salt"`
}

type CSRFConfig struct {
	Cookie string `json:"cookie"`
	Header string `json:"header"`
}

// UserRow is a captured legacy user fixture.
type UserRow struct {
	UID           int64  `json:"uid"`
	Email         string `json:"email"`
	Nickname      string `json:"nickname"`
	Permission    int    `json:"permission"`
	Verified      bool   `json:"verified"`
	Password      string `json:"password"`
	RememberToken string `json:"remember_token"`
	Plaintext     string `json:"plaintext"`
}

// Vector is one cross-implementation case. Domain-specific payloads stay as
// raw JSON so each checker owns its schema.
type Vector struct {
	ID             string          `json:"id"`
	Domain         string          `json:"domain"`
	Input          json.RawMessage `json:"input"`
	Expect         json.RawMessage `json:"expect"`
	Observed       json.RawMessage `json:"observed"`
	Classification string          `json:"classification"`
}

// LoadPath accepts either a directory of vector files or a single file.
func LoadPath(path string) (*File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return Load(path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var current File
	if err := json.Unmarshal(data, &current); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if current.Schema != Schema {
		return nil, fmt.Errorf("%s: unsupported schema %q", path, current.Schema)
	}
	return &current, nil
}

// Load reads every *.json file in dir and merges their vectors.
func Load(dir string) (*File, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	merged := &File{Schema: Schema}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var current File
		if err := json.Unmarshal(data, &current); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if current.Schema != Schema {
			return nil, fmt.Errorf("%s: unsupported schema %q", path, current.Schema)
		}
		if merged.Config.AppKey == "" {
			merged.Config = current.Config
			merged.Users = current.Users
			merged.Source = current.Source
			merged.GeneratedAt = current.GeneratedAt
		}
		merged.Vectors = append(merged.Vectors, current.Vectors...)
	}
	if len(merged.Vectors) == 0 {
		return nil, fmt.Errorf("%s: no vectors found", dir)
	}
	seen := map[string]bool{}
	for _, v := range merged.Vectors {
		if v.ID == "" {
			return nil, fmt.Errorf("%s: vector without id", dir)
		}
		if seen[v.ID] {
			return nil, fmt.Errorf("%s: duplicate vector id %q", dir, v.ID)
		}
		seen[v.ID] = true
	}
	return merged, nil
}

// Result is the outcome for one vector.
type Result struct {
	ID             string `json:"id"`
	Domain         string `json:"domain"`
	Passed         bool   `json:"passed"`
	Classification string `json:"classification"`
	Detail         string `json:"detail,omitempty"`
	Error          string `json:"error,omitempty"`
}

// Report is a machine-readable verification result.
type Report struct {
	Schema      string   `json:"schema"`
	GeneratedAt string   `json:"generated_at"`
	Source      string   `json:"source,omitempty"`
	Total       int      `json:"total"`
	Passed      int      `json:"passed"`
	Failed      int      `json:"failed"`
	Skipped     int      `json:"skipped"`
	Results     []Result `json:"results"`
}
