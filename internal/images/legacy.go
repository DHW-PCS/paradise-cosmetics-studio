package images

import (
	"context"
	"database/sql"
	"errors"
)

// PlayerTexture returns the texture hash currently equipped in the given
// slot ("skin" or "cape") for the named player. The owning account's ban
// state resolves before any missing-texture outcome, following the same
// permission<0 rule as Player. A missing player, cleared slot, or missing
// texture row maps to ErrNotFound; other database errors propagate.
func (s *Service) PlayerTexture(ctx context.Context, name, slot string) (string, error) {
	var uid, tidSkin, tidCape int64
	err := s.Store.DB.QueryRowContext(ctx, "SELECT uid,tid_skin,tid_cape FROM "+s.Store.Table("players")+" WHERE name=?", name).Scan(&uid, &tidSkin, &tidCape)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	var permission int
	if err = s.Store.DB.QueryRowContext(ctx, "SELECT permission FROM "+s.Store.Table("users")+" WHERE uid=?", uid).Scan(&permission); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if permission < 0 {
		return "", ErrForbidden
	}
	tid := tidSkin
	if slot == "cape" {
		tid = tidCape
	}
	if tid <= 0 {
		return "", ErrNotFound
	}
	texture, err := s.textureByTID(ctx, tid)
	if err != nil {
		return "", err
	}
	return texture.Hash, nil
}

// Original returns the exact stored bytes for a texture hash without
// re-encoding. A missing file maps to ErrNotFound via readOriginal; other
// file errors propagate.
func (s *Service) Original(hash string) ([]byte, error) {
	payload, _, err := s.readOriginal(hash)
	if err != nil {
		return nil, err
	}
	return payload, nil
}
