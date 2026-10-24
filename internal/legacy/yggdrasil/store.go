package yggdrasil

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Store is additive. Tombstones and UID bindings are never reconstructed from
// an email index. The global row serializes import, rotation, revoke and join.
type Store struct {
	DB                   *sql.DB
	Prefix               string
	Key                  []byte
	ValidTTL, RefreshTTL int64
	Limit                int
	Now                  func() time.Time
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
func (s *Store) Setup(ctx context.Context) error {
	if !regexp.MustCompile(`^[A-Za-z0-9_]*$`).MatchString(s.Prefix) || s.DB == nil || len(s.Key) == 0 || s.ValidTTL <= 0 || s.RefreshTTL < s.ValidTTL || s.Limit < 1 {
		return ErrDenied
	}
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS %sgo_ygg_lock (id INT PRIMARY KEY) ENGINE=InnoDB`,
		`INSERT IGNORE INTO %sgo_ygg_lock VALUES (1)`,
		`CREATE TABLE IF NOT EXISTS %sgo_ygg_users (uid BIGINT PRIMARY KEY, revoked_before BIGINT NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS %sgo_ygg_tokens (sequence BIGINT UNSIGNED NOT NULL AUTO_INCREMENT UNIQUE, fingerprint CHAR(64) PRIMARY KEY, uid BIGINT NOT NULL, payload LONGTEXT NOT NULL, expires_at BIGINT NOT NULL, revoked BOOLEAN NOT NULL DEFAULT 0, INDEX(uid)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS %sgo_yggdrasil_revocations (fingerprint CHAR(64) PRIMARY KEY, revoked_at BIGINT NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS %sgo_ygg_joins (server_hash CHAR(64), profile_id VARCHAR(64), payload LONGTEXT NOT NULL, expires_at BIGINT NOT NULL, PRIMARY KEY(server_hash,profile_id)) ENGINE=InnoDB`,
	} {
		if _, e := s.DB.ExecContext(ctx, fmt.Sprintf(q, s.Prefix)); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) locked(ctx context.Context, f func(*sql.Tx) error) error {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var id int
	if e = tx.QueryRowContext(ctx, "SELECT id FROM "+s.Prefix+"go_ygg_lock WHERE id=1 FOR UPDATE").Scan(&id); e != nil {
		return e
	}
	if e = f(tx); e != nil {
		return e
	}
	return tx.Commit()
}

// tombstoned reports whether this exact token was revoked, including a token
// that was never imported into the ledger.
func (s *Store) tombstoned(ctx context.Context, tx *sql.Tx, fingerprint string) (bool, error) {
	var n int
	if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Prefix+"go_yggdrasil_revocations WHERE fingerprint=?", fingerprint).Scan(&n); e != nil {
		return false, e
	}
	return n > 0, nil
}

func (s *Store) load(ctx context.Context, tx *sql.Tx, raw string) (Token, error) {
	var t Token
	fingerprint := hash(raw)
	revoked, e := s.tombstoned(ctx, tx, fingerprint)
	if e != nil {
		return t, e
	}
	if revoked {
		return t, ErrDenied
	}
	var data string
	var rowRevoked bool
	e = tx.QueryRowContext(ctx, "SELECT payload,revoked FROM "+s.Prefix+"go_ygg_tokens WHERE fingerprint=?", fingerprint).Scan(&data, &rowRevoked)
	if errors.Is(e, sql.ErrNoRows) || rowRevoked {
		return t, ErrDenied
	}
	if e != nil {
		return t, e
	}
	if json.Unmarshal([]byte(data), &t) != nil || t.AccessToken != raw {
		return t, ErrDenied
	}
	return t, nil
}
func (s *Store) owner(ctx context.Context, tx *sql.Tx, t Token) error {
	var permission int
	var email string
	if e := tx.QueryRowContext(ctx, "SELECT permission,email FROM "+s.Prefix+"users WHERE uid=?", t.UID).Scan(&permission, &email); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return ErrDenied
		}
		return e
	}
	if permission < 0 {
		return ErrDenied
	}
	return nil // historical owner/sub remains immutable after email changes
}
func (s *Store) profile(ctx context.Context, tx *sql.Tx, uid int64, id, name string) error {
	var owner int64
	var actual string
	var count int
	e := tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(MIN(p.uid),0),COALESCE(MIN(p.name),'') FROM "+s.Prefix+"players p JOIN "+s.Prefix+"uuid u ON u.name=p.name WHERE u.uuid=?", id).Scan(&count, &owner, &actual)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrDenied
	}
	if e != nil {
		return e
	}
	if count != 1 || owner != uid || (name != "" && name != actual) {
		return ErrDenied
	}
	return nil
}
func (s *Store) insert(ctx context.Context, tx *sql.Tx, t Token) error {
	fingerprint := hash(t.AccessToken)
	revoked, e := s.tombstoned(ctx, tx, fingerprint)
	if e != nil {
		return e
	}
	if revoked {
		return ErrDenied
	}
	b, e := json.Marshal(t)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO "+s.Prefix+"go_ygg_tokens(fingerprint,uid,payload,expires_at) VALUES(?,?,?,?)", fingerprint, t.UID, string(b), t.ExpiresAt)
	return e
}

// Import is insert-once, including a revoked or expired record. A repeated
// snapshot can never overwrite a rotation, tombstone or original expiry.
func (s *Store) Import(ctx context.Context, t Token) error {
	return s.locked(ctx, func(tx *sql.Tx) error {
		var n int
		if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Prefix+"go_ygg_tokens WHERE fingerprint=?", hash(t.AccessToken)).Scan(&n); e != nil {
			return e
		}
		if n > 0 {
			return ErrDenied
		}
		var watermark int64
		if e := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(revoked_before),0) FROM "+s.Prefix+"go_ygg_users WHERE uid=?", t.UID).Scan(&watermark); e != nil {
			return e
		}
		if watermark > 0 && t.CreatedAt <= watermark {
			return ErrDenied
		}
		if e := t.Check(s.Key, s.now(), s.ValidTTL, s.RefreshTTL, true); e != nil {
			return e
		}
		if e := s.owner(ctx, tx, t); e != nil {
			return e
		}
		var email string
		var count int
		if e := tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(MIN(email),'') FROM "+s.Prefix+"users WHERE email=?", t.Owner).Scan(&count, &email); e != nil {
			return e
		}
		if count != 1 {
			return ErrDenied
		}
		var uid int64
		if e := tx.QueryRowContext(ctx, "SELECT uid FROM "+s.Prefix+"users WHERE email=?", t.Owner).Scan(&uid); e != nil {
			return e
		}
		if uid != t.UID {
			return ErrDenied
		}
		return s.insert(ctx, tx, t)
	})
}
func (s *Store) Validate(ctx context.Context, raw, client string) (Token, error) {
	var t Token
	e := s.locked(ctx, func(tx *sql.Tx) error {
		var e error
		t, e = s.load(ctx, tx, raw)
		if e != nil {
			return e
		}
		if client != "" && client != t.ClientToken {
			return ErrDenied
		}
		if e = t.Check(s.Key, s.now(), s.ValidTTL, s.RefreshTTL, false); e != nil {
			return e
		}
		return s.owner(ctx, tx, t)
	})
	return t, e
}
func (s *Store) Refresh(ctx context.Context, raw, client, id, name string) (Token, error) {
	var out Token
	e := s.locked(ctx, func(tx *sql.Tx) error {
		t, e := s.load(ctx, tx, raw)
		if e != nil {
			return e
		}
		if client != "" && client != t.ClientToken {
			return ErrDenied
		}
		if e = t.Check(s.Key, s.now(), s.ValidTTL, s.RefreshTTL, true); e != nil {
			return e
		}
		if e = s.owner(ctx, tx, t); e != nil {
			return e
		}
		selected := t.ProfileID
		if id != "" {
			if selected != "" && selected != id {
				return ErrDenied
			}
			selected = id
		}
		if selected != "" {
			if e = s.profile(ctx, tx, t.UID, selected, name); e != nil {
				return e
			}
		}
		out, e = Mint(t.UID, t.Owner, selected, t.ClientToken, s.Key, s.now(), s.ValidTTL, s.RefreshTTL)
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE "+s.Prefix+"go_ygg_tokens SET revoked=1 WHERE fingerprint=?", hash(raw)); e != nil {
			return e
		}
		return s.insert(ctx, tx, out)
	})
	return out, e
}

// Revoke records a tombstone for the exact token and revokes its ledger row.
// The tombstone makes a successful revoke of an unknown or not-yet-imported
// token durable, so a later snapshot import cannot bring it back. No automatic
// expiry is applied: the token's real window is unknown here.
func (s *Store) Revoke(ctx context.Context, raw string) error {
	fingerprint := hash(raw)
	return s.locked(ctx, func(tx *sql.Tx) error {
		if _, e := tx.ExecContext(ctx, "INSERT INTO "+s.Prefix+"go_yggdrasil_revocations(fingerprint,revoked_at) VALUES(?,?) ON DUPLICATE KEY UPDATE revoked_at=GREATEST(revoked_at,VALUES(revoked_at))", fingerprint, s.now().Unix()); e != nil {
			return e
		}
		_, e := tx.ExecContext(ctx, "UPDATE "+s.Prefix+"go_ygg_tokens SET revoked=1 WHERE fingerprint=?", fingerprint)
		return e
	})
}
func (s *Store) Signout(ctx context.Context, uid int64) error {
	return s.locked(ctx, func(tx *sql.Tx) error {
		if _, e := tx.ExecContext(ctx, "INSERT INTO "+s.Prefix+"go_ygg_users(uid,revoked_before) VALUES(?,?) ON DUPLICATE KEY UPDATE revoked_before=GREATEST(revoked_before,VALUES(revoked_before))", uid, s.now().Unix()); e != nil {
			return e
		}
		_, e := tx.ExecContext(ctx, "UPDATE "+s.Prefix+"go_ygg_tokens SET revoked=1 WHERE uid=?", uid)
		return e
	})
}

type Join struct {
	Profile   string `json:"profile"`
	IP        string `json:"ip"`
	UID       int64  `json:"uid"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
	Legacy    bool   `json:"legacy"`
}

func (s *Store) putJoin(ctx context.Context, tx *sql.Tx, server string, j Join) error {
	b, _ := json.Marshal(j)
	_, e := tx.ExecContext(ctx, "INSERT INTO "+s.Prefix+"go_ygg_joins VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE payload=VALUES(payload),expires_at=VALUES(expires_at)", hash(server), j.Profile, string(b), j.ExpiresAt)
	return e
}
func (s *Store) Join(ctx context.Context, raw, profile, server, ip string) error {
	if server == "" || profile == "" {
		return ErrDenied
	}
	return s.locked(ctx, func(tx *sql.Tx) error {
		t, e := s.load(ctx, tx, raw)
		if e != nil {
			return e
		}
		if e = t.Check(s.Key, s.now(), s.ValidTTL, s.RefreshTTL, false); e != nil {
			return e
		}
		if e = s.owner(ctx, tx, t); e != nil {
			return e
		}
		if t.ProfileID != profile {
			return ErrDenied
		}
		if e = s.profile(ctx, tx, t.UID, profile, ""); e != nil {
			return e
		}
		return s.putJoin(ctx, tx, server, Join{profile, ip, t.UID, raw, s.now().Unix() + 120, false})
	})
}

// ImportJoin preserves a native pre-switch 120s window. Legacy joins cannot
// prove issuer/revocation; allowLegacy must be an explicit cutover policy.
func (s *Store) ImportJoin(ctx context.Context, server string, j Join, allowLegacy bool) error {
	if !allowLegacy || j.ExpiresAt <= s.now().Unix() || j.ExpiresAt > s.now().Unix()+120 {
		return ErrDenied
	}
	j.Legacy = true
	j.Token = ""
	j.UID = 0
	return s.locked(ctx, func(tx *sql.Tx) error {
		var n int
		if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Prefix+"go_ygg_joins WHERE server_hash=? AND profile_id=?", hash(server), j.Profile).Scan(&n); e != nil {
			return e
		}
		if n > 0 {
			return ErrDenied
		}
		return s.putJoin(ctx, tx, server, j)
	})
}
func (s *Store) HasJoined(ctx context.Context, server, name, ip string) (string, error) {
	var profile string
	e := s.locked(ctx, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, "SELECT payload FROM "+s.Prefix+"go_ygg_joins WHERE server_hash=? AND expires_at>?", hash(server), s.now().Unix())
		if e != nil {
			return e
		}
		var js []Join
		for rows.Next() {
			var b string
			if e = rows.Scan(&b); e != nil {
				rows.Close()
				return e
			}
			var j Join
			if json.Unmarshal([]byte(b), &j) != nil {
				rows.Close()
				return ErrDenied
			}
			js = append(js, j)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for _, j := range js {
			if ip != "" && ip != j.IP {
				continue
			}
			var uid int64
			var actual string
			var permission int
			e = tx.QueryRowContext(ctx, "SELECT p.uid,p.name,u.permission FROM "+s.Prefix+"players p JOIN "+s.Prefix+"uuid x ON x.name=p.name JOIN "+s.Prefix+"users u ON u.uid=p.uid WHERE x.uuid=?", j.Profile).Scan(&uid, &actual, &permission)
			if errors.Is(e, sql.ErrNoRows) {
				continue
			}
			if e != nil {
				return e
			}
			if actual != name || permission < 0 {
				continue
			}
			if !j.Legacy {
				if uid != j.UID {
					continue
				}
				t, e := s.load(ctx, tx, j.Token)
				if errors.Is(e, ErrDenied) {
					continue
				}
				if e != nil {
					return e
				}
				if t.Check(s.Key, s.now(), s.ValidTTL, s.RefreshTTL, false) != nil {
					continue
				}
			}
			profile = j.Profile
			return nil
		}
		return ErrDenied
	})
	return profile, e
}

// Issue enforces the native per-user FIFO limit using live ledger rows only.
func (s *Store) Issue(ctx context.Context, uid int64, owner, profile, client string) (Token, error) {
	var out Token
	e := s.locked(ctx, func(tx *sql.Tx) error {
		var e error
		out, e = Mint(uid, owner, profile, client, s.Key, s.now(), s.ValidTTL, s.RefreshTTL)
		if e != nil {
			return e
		}
		if e = s.owner(ctx, tx, out); e != nil {
			return e
		}
		var email string
		if e = tx.QueryRowContext(ctx, "SELECT email FROM "+s.Prefix+"users WHERE uid=?", uid).Scan(&email); e != nil {
			return e
		}
		if owner != email {
			return ErrDenied
		}
		if profile != "" {
			if e = s.profile(ctx, tx, uid, profile, ""); e != nil {
				return e
			}
		}
		rows, e := tx.QueryContext(ctx, "SELECT fingerprint FROM "+s.Prefix+"go_ygg_tokens WHERE uid=? AND revoked=0 AND expires_at>? ORDER BY sequence", uid, s.now().Unix())
		if e != nil {
			return e
		}
		var ids []string
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return e
			}
			ids = append(ids, id)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for len(ids) >= s.Limit {
			if _, e = tx.ExecContext(ctx, "UPDATE "+s.Prefix+"go_ygg_tokens SET revoked=1 WHERE fingerprint=?", ids[0]); e != nil {
				return e
			}
			ids = ids[1:]
		}
		return s.insert(ctx, tx, out)
	})
	return out, e
}

// LockTx acquires the global Yggdrasil writer lock for the caller's
// transaction. Callers that also lock a user row must take this first.
func (s *Store) LockTx(ctx context.Context, tx *sql.Tx) error {
	var id int
	return tx.QueryRowContext(ctx, "SELECT id FROM "+s.Prefix+"go_ygg_lock WHERE id=1 FOR UPDATE").Scan(&id)
}

// AuthorizeTx keeps the Yggdrasil revoke fence locked through the caller's commit.
func (s *Store) AuthorizeTx(ctx context.Context, tx *sql.Tx, raw string) (int64, error) {
	if e := s.LockTx(ctx, tx); e != nil {
		return 0, e
	}
	t, e := s.load(ctx, tx, raw)
	if e != nil {
		return 0, e
	}
	if e = t.Check(s.Key, s.now(), s.ValidTTL, s.RefreshTTL, false); e != nil {
		return 0, e
	}
	if e = s.owner(ctx, tx, t); e != nil {
		return 0, e
	}
	return t.UID, nil
}
