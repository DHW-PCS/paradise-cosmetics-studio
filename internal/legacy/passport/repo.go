package passport

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Client is the subset of oauth_clients Passport uses for grant checks.
type Client struct {
	ID             int64
	Name           string
	Secret         string
	Redirect       []string
	PersonalAccess bool
	Password       bool
	Revoked        bool
	Provider       string
}

func (c Client) Confidential() bool { return c.Secret != "" }
func (c Client) FirstParty() bool   { return c.PersonalAccess || c.Password }
func (c Client) Identifier() string { return strconv.FormatInt(c.ID, 10) }

func (c Client) AllowsRedirect(uri string) bool {
	for _, allowed := range c.Redirect {
		if allowed == uri {
			return true
		}
	}
	return false
}

// AccessTokenRow mirrors the columns M1-02 needs.
type AccessTokenRow struct {
	ID        string
	UserID    int64
	ClientID  string
	Scopes    []string
	Revoked   bool
	ExpiresAt time.Time
}

type RefreshTokenRow struct {
	ID            string
	AccessTokenID string
	Revoked       bool
	ExpiresAt     time.Time
}

type AuthCodeRow struct {
	ID        string
	UserID    int64
	ClientID  string
	Scopes    []string
	Revoked   bool
	ExpiresAt time.Time
}

// tokenDB lets a grant use one transaction for consumption and issuance.
type tokenDB interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Repo reads and writes the frozen oauth_* tables. No schema changes are made.
type Repo struct {
	db       tokenDB
	prefix   string
	location *time.Location
}

func NewRepo(db *sql.DB, prefix string, location *time.Location) *Repo {
	return &Repo{db: db, prefix: prefix, location: location}
}

func (r *Repo) table(name string) string { return r.prefix + name }

func (r *Repo) stamp(t time.Time) string {
	return t.In(r.location).Format("2006-01-02 15:04:05")
}

// FindClient returns an active client or nil.
func (r *Repo) FindClient(ctx context.Context, id int64) (*Client, error) {
	query := fmt.Sprintf(`SELECT id, COALESCE(name,''), COALESCE(secret,''), redirect,
		personal_access_client, password_client, revoked, COALESCE(provider,'')
		FROM %s WHERE id = ? LIMIT 1`, r.table("oauth_clients"))
	var client Client
	var redirect string
	var personal, password, revoked int
	err := r.db.QueryRowContext(ctx, query, id).Scan(&client.ID, &client.Name, &client.Secret,
		&redirect, &personal, &password, &revoked, &client.Provider)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	client.PersonalAccess = personal != 0
	client.Password = password != 0
	client.Revoked = revoked != 0
	for _, uri := range strings.Split(redirect, ",") {
		if uri != "" {
			client.Redirect = append(client.Redirect, uri)
		}
	}
	return &client, nil
}

// CreateClient inserts a synthetic client for the isolated reference database.
func (r *Repo) CreateClient(ctx context.Context, client Client) error {
	now := r.stamp(time.Now())
	query := fmt.Sprintf(`INSERT INTO %s (id, user_id, name, secret, provider, redirect,
		personal_access_client, password_client, revoked, created_at, updated_at)
		VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, r.table("oauth_clients"))
	_, err := r.db.ExecContext(ctx, query, client.ID, client.Name, nullable(client.Secret), nullable(client.Provider),
		strings.Join(client.Redirect, ","), boolInt(client.PersonalAccess),
		boolInt(client.Password), boolInt(client.Revoked), now, now)
	return err
}

func (r *Repo) CreateAccessToken(ctx context.Context, row AccessTokenRow) error {
	now := time.Now()
	query := fmt.Sprintf(`INSERT INTO %s (id, user_id, client_id, name, scopes, revoked,
		created_at, updated_at, expires_at) VALUES (?, ?, ?, NULL, ?, 0, ?, ?, ?)`,
		r.table("oauth_access_tokens"))
	_, err := r.db.ExecContext(ctx, query, row.ID, row.UserID, row.ClientID,
		encodeScopes(row.Scopes), r.stamp(now), r.stamp(now), r.stamp(row.ExpiresAt))
	return err
}

func (r *Repo) CreateRefreshToken(ctx context.Context, row RefreshTokenRow) error {
	query := fmt.Sprintf(`INSERT INTO %s (id, access_token_id, revoked, expires_at)
		VALUES (?, ?, 0, ?)`, r.table("oauth_refresh_tokens"))
	_, err := r.db.ExecContext(ctx, query, row.ID, row.AccessTokenID, r.stamp(row.ExpiresAt))
	return err
}

func (r *Repo) CreateAuthCode(ctx context.Context, row AuthCodeRow) error {
	query := fmt.Sprintf(`INSERT INTO %s (id, user_id, client_id, scopes, revoked, expires_at)
		VALUES (?, ?, ?, ?, 0, ?)`, r.table("oauth_auth_codes"))
	_, err := r.db.ExecContext(ctx, query, row.ID, row.UserID, row.ClientID,
		encodeScopes(row.Scopes), r.stamp(row.ExpiresAt))
	return err
}

func (r *Repo) AccessTokenRevoked(ctx context.Context, id string) (bool, error) {
	var revoked int
	query := fmt.Sprintf(`SELECT revoked FROM %s WHERE id = ?`, r.table("oauth_access_tokens"))
	err := r.db.QueryRowContext(ctx, query, id).Scan(&revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return revoked != 0, nil
}

func (r *Repo) RefreshTokenRevoked(ctx context.Context, id string) (bool, error) {
	var revoked int
	query := fmt.Sprintf(`SELECT revoked FROM %s WHERE id = ?`, r.table("oauth_refresh_tokens"))
	err := r.db.QueryRowContext(ctx, query, id).Scan(&revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return revoked != 0, nil
}

func (r *Repo) AuthCodeRevoked(ctx context.Context, id string) (bool, error) {
	var revoked int
	query := fmt.Sprintf(`SELECT revoked FROM %s WHERE id = ?`, r.table("oauth_auth_codes"))
	err := r.db.QueryRowContext(ctx, query, id).Scan(&revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return revoked != 0, nil
}

func (r *Repo) RevokeAccessToken(ctx context.Context, id string) error {
	_, err := r.RevokeAccessTokenIfActive(ctx, id)
	return err
}

// RevokeAccessTokenIfActive revokes exactly once. The bool reports whether this
// call performed the transition.
func (r *Repo) RevokeAccessTokenIfActive(ctx context.Context, id string) (bool, error) {
	query := fmt.Sprintf(`UPDATE %s SET revoked = 1, updated_at = ? WHERE id = ? AND revoked = 0`,
		r.table("oauth_access_tokens"))
	result, err := r.db.ExecContext(ctx, query, r.stamp(time.Now()), id)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}

func (r *Repo) RevokeRefreshToken(ctx context.Context, id string) error {
	_, err := r.RevokeRefreshTokenIfActive(ctx, id)
	return err
}

// RevokeRefreshTokenIfActive is the single-winner primitive for refresh
// rotation.
func (r *Repo) RevokeRefreshTokenIfActive(ctx context.Context, id string) (bool, error) {
	query := fmt.Sprintf(`UPDATE %s SET revoked = 1 WHERE id = ? AND revoked = 0`,
		r.table("oauth_refresh_tokens"))
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}

func (r *Repo) RevokeAuthCode(ctx context.Context, id string) error {
	_, err := r.RevokeAuthCodeIfActive(ctx, id)
	return err
}

// RevokeAuthCodeIfActive is the single-winner primitive for code consumption.
func (r *Repo) RevokeAuthCodeIfActive(ctx context.Context, id string) (bool, error) {
	query := fmt.Sprintf(`UPDATE %s SET revoked = 1 WHERE id = ? AND revoked = 0`,
		r.table("oauth_auth_codes"))
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}

func (r *Repo) AccessToken(ctx context.Context, id string) (*AccessTokenRow, error) {
	query := fmt.Sprintf(`SELECT id, COALESCE(user_id,0), client_id, COALESCE(scopes,''), revoked, expires_at
		FROM %s WHERE id = ?`, r.table("oauth_access_tokens"))
	var row AccessTokenRow
	var scopes string
	var revoked int
	err := r.db.QueryRowContext(ctx, query, id).Scan(&row.ID, &row.UserID, &row.ClientID,
		&scopes, &revoked, &row.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	row.Scopes = decodeScopes(scopes)
	row.Revoked = revoked != 0
	return &row, nil
}

func (r *Repo) RefreshTokenRow(ctx context.Context, id string) (*RefreshTokenRow, error) {
	query := fmt.Sprintf(`SELECT id, access_token_id, revoked, expires_at
		FROM %s WHERE id = ?`, r.table("oauth_refresh_tokens"))
	var row RefreshTokenRow
	var revoked int
	err := r.db.QueryRowContext(ctx, query, id).Scan(&row.ID, &row.AccessTokenID, &revoked, &row.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	row.Revoked = revoked != 0
	return &row, nil
}

// Reset deletes the synthetic oauth rows for the given user and clients.
func (r *Repo) Reset(ctx context.Context, uid int64, clients []int64) error {
	tables := []string{"oauth_refresh_tokens", "oauth_access_tokens", "oauth_auth_codes"}
	for _, table := range tables {
		query := fmt.Sprintf("DELETE FROM %s WHERE user_id = ?", r.table(table))
		if table == "oauth_refresh_tokens" {
			query = fmt.Sprintf(`DELETE FROM %s WHERE access_token_id IN
				(SELECT id FROM %s WHERE user_id = ?)`, r.table(table), r.table("oauth_access_tokens"))
		}
		if _, err := r.db.ExecContext(ctx, query, uid); err != nil {
			return err
		}
	}
	for _, id := range clients {
		if _, err := r.db.ExecContext(ctx,
			fmt.Sprintf("DELETE FROM %s WHERE id = ?", r.table("oauth_clients")), id); err != nil {
			return err
		}
	}
	return nil
}

func encodeScopes(scopes []string) string {
	if len(scopes) == 0 {
		return "[]"
	}
	data, _ := json.Marshal(scopes)
	return string(data)
}

func decodeScopes(value string) []string {
	var scopes []string
	if err := json.Unmarshal([]byte(value), &scopes); err == nil {
		return scopes
	}
	return strings.Fields(value)
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
