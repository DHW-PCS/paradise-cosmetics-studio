package media

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"regexp"
)

// Legacy is the original direct PNG contract, including private textures.
// Read requests do not delete missing rows or consult the raw-download option.
func Legacy(ctx context.Context, db *sql.DB, prefix, root, name, slot string) ([]byte, int, error) {
	if !regexp.MustCompile(`^[A-Za-z0-9_]*$`).MatchString(prefix) || (slot != "skin" && slot != "cape") {
		return nil, 404, nil
	}
	var permission int
	var hash sql.NullString
	e := db.QueryRowContext(ctx, "SELECT u.permission,t.hash FROM "+prefix+"players p JOIN "+prefix+"users u ON u.uid=p.uid LEFT JOIN "+prefix+"textures t ON t.tid=p.tid_"+slot+" WHERE p.name=? LIMIT 1", name).Scan(&permission, &hash)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, 404, nil
	}
	if e != nil {
		return nil, 500, e
	}
	if permission < 0 {
		return nil, 403, nil
	}
	if !hash.Valid || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(hash.String) {
		return nil, 404, nil
	}
	b, e := os.ReadFile(filepath.Join(root, hash.String))
	if errors.Is(e, os.ErrNotExist) {
		return nil, 404, nil
	}
	if e != nil {
		return nil, 500, e
	}
	return b, 200, nil
}
