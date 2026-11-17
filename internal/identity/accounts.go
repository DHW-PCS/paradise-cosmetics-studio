package identity

import (
	"context"
	"database/sql"
	"paradise-cosmetics-studio/internal/legacy/users"
)

type account struct {
	User
	Password string
}
type accountRow interface{ Scan(...any) error }

func scanAccount(row accountRow) (*account, error) {
	u := &account{}
	err := row.Scan(&u.UID, &u.Email, &u.Nickname, &u.Permission, &u.Verified, &u.Locale, &u.DarkMode, &u.Password)
	return u, err
}

const accountColumns = "u.uid,u.email,u.nickname,u.permission,u.verified,COALESCE(u.locale,''),u.is_dark_mode,u.password"

func (s *Service) lookupAccount(ctx context.Context, identification string, lookup Lookup) (*account, error) {
	query := "SELECT " + accountColumns + " FROM " + s.Store.Table("users") + " u"
	if lookup == EmailOnly || users.EmailLooksLikeEmail(identification) {
		query += " WHERE u.email=? LIMIT 1"
	} else {
		query += " JOIN " + s.Store.Table("players") + " p ON p.uid=u.uid WHERE p.name=? LIMIT 1"
	}
	return scanAccount(s.LoginStore.DB.QueryRowContext(ctx, query, identification))
}

func (s *Service) accountForUpdate(ctx context.Context, tx *sql.Tx, uid int64) (*account, error) {
	return scanAccount(tx.QueryRowContext(ctx, "SELECT "+accountColumns+" FROM "+s.Store.Table("users")+" u WHERE u.uid=? FOR UPDATE", uid))
}
