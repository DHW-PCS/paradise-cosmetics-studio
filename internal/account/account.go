package account

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/legacy/password"
	"blessing-skin-go/internal/outbox"
	"blessing-skin-go/internal/players"
	"blessing-skin-go/internal/site"
)

var (
	ErrEmailUsed            = errors.New("account: email already exists")
	ErrPlayerUsed           = errors.New("account: player name already exists")
	ErrIPQuota              = errors.New("account: registration IP quota reached")
	ErrForbidden            = errors.New("account: operation forbidden")
	ErrNotFound             = errors.New("account: object not found")
	ErrTooSoon              = errors.New("account: operation not due")
	ErrModuleUnavailable    = errors.New("account: registration module unavailable")
	ErrInvalidChallenge     = errors.New("account: invalid challenge")
	ErrAlreadyVerified      = errors.New("account: already verified")
	ErrVerificationDisabled = errors.New("account: verification disabled")
)

type Service struct {
	Store    *database.Store
	Identity *identity.Service
	Site     *site.Service
	Outbox   *outbox.Store
	Mail     *Mail
	Now      func() time.Time
	// Award is replaceable for fixed-input checks; production uses crypto/rand.
	Award func(min, max int64) int64
}

func New(s *database.Store, id *identity.Service, view *site.Service, mail *Mail) *Service {
	return &Service{Store: s, Identity: id, Site: view, Mail: mail, Outbox: &outbox.Store{Database: s, Now: id.Now}, Now: id.Now, Award: randomAward}
}
func randomAward(min, max int64) int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(max-min+1))
	if err != nil {
		panic(err)
	}
	return min + n.Int64()
}
func (s *Service) hash(ctx context.Context, raw string) (string, error) {
	release, err := s.Identity.Admission.Acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	return s.Identity.Passwords.Hash(raw)
}

// Registration names and IP are HTTP-validated; eligibility still belongs to
// this transaction and cannot be disabled by supplying an HTTP flag.
type Registration struct{ Email, Nickname, PlayerName, Password, IP, Locale, Guest string }

func (s *Service) Register(ctx context.Context, in Registration) (*identity.BrowserSession, error) {
	if err := password.ValidateRegistration(in.Password); err != nil {
		return nil, err
	}
	options, err := s.Site.Options(ctx)
	if err != nil {
		return nil, err
	}
	if raw, _ := options["plugins_enabled"].(string); raw != "" {
		var plugins []struct {
			Name string `json:"name"`
		}
		// PluginManager ignores string entries. Preserve that shape while refusing
		// an enabled eligibility module until its transaction consumer is installed.
		var entries []json.RawMessage
		if err = json.Unmarshal([]byte(raw), &entries); err != nil {
			return nil, ErrModuleUnavailable
		}
		for _, entry := range entries {
			var p struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(entry, &p) == nil {
				plugins = append(plugins, p)
			}
		}
		for _, p := range plugins {
			if p.Name == "invitation-codes" || p.Name == "disable-registration" || p.Name == "restricted-email-domains" {
				return nil, ErrModuleUnavailable
			}
		}
	}
	hash, err := s.hash(ctx, in.Password)
	if err != nil {
		return nil, err
	}
	var result *identity.BrowserSession
	err = s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if err := database.LockNamespaces(ctx, tx, s.Store, "email", "mail", "player-name", "registration", "uuid"); err != nil {
			return err
		}
		if err := s.emailAvailable(ctx, tx, in.Email, 0); err != nil {
			return err
		}
		withPlayer := site.Truth(options["register_with_player_name"])
		var count int64
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("users")+" WHERE ip=?", in.IP).Scan(&count); err != nil {
			return err
		}
		if count >= site.Number(options["regs_per_ip"]) {
			return ErrIPQuota
		}
		now := s.Now().In(s.Site.Location)
		nickname := in.Nickname
		if withPlayer {
			nickname = in.PlayerName
		}
		row, err := tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("users")+" (email,nickname,password,score,avatar,ip,permission,verified,register_at,last_sign_at) VALUES (?,?,?,?,?,?,0,0,?,?)", in.Email, nickname, hash, site.Number(options["user_initial_score"]), 0, in.IP, now, now.AddDate(0, 0, -1))
		if err != nil {
			return err
		}
		uid, err := row.LastInsertId()
		if err != nil {
			return err
		}
		if withPlayer {
			lifecycle := players.New(s.Store, s.Identity, s.Site, s.Now)
			if _, err = lifecycle.AddTx(ctx, tx, uid, in.PlayerName, true); err != nil {
				if errors.Is(err, players.ErrPlayerUsed) {
					return ErrPlayerUsed
				}
				return err
			}
		}
		result, err = s.Identity.RegisterSession(ctx, tx, uid, in.Guest)
		if err != nil {
			return err
		}
		if site.Truth(options["require_verification"]) {
			if s.Mail == nil {
				return ErrModuleUnavailable
			}
			if err = s.issueChallenge(ctx, tx, result.User, result.Version, "verify", in.Locale); err != nil {
				return err
			}
		}
		return nil
	})
	return result, err
}
func (s *Service) emailAvailable(ctx context.Context, tx *sql.Tx, email string, ignore int64) error {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.Store.Table("users")+" WHERE email=? AND uid<>?", email, ignore).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return ErrEmailUsed
	}
	return nil
}
func (s *Service) BindEmail(ctx context.Context, b *identity.BrowserSession, email string) error {
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if err := database.LockNamespaces(ctx, tx, s.Store, "email"); err != nil {
			return err
		}
		u, err := s.Identity.CheckBrowserTx(ctx, tx, b)
		if err != nil {
			return err
		}
		if u.Email != "" {
			return ErrForbidden
		}
		if err = s.emailAvailable(ctx, tx, email, 0); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET email=? WHERE uid=?", email, u.UID)
		return err
	})
}
func (s *Service) Nickname(ctx context.Context, b *identity.BrowserSession, name string) error {
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		u, err := s.Identity.CheckBrowserTx(ctx, tx, b)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET nickname=? WHERE uid=?", name, u.UID)
		return err
	})
}

// ChangeProfile verifies the current account outside the write transaction,
// then rechecks both the browser credential and password proof before writing.
func (s *Service) ChangeProfile(ctx context.Context, b *identity.BrowserSession, action, current, value string) error {
	var hash string
	var err error
	if action == "password" {
		if err = password.ValidateRegistration(value); err != nil {
			return err
		}
		hash, err = s.hash(ctx, value)
		if err != nil {
			return err
		}
	}
	return s.Identity.WithUserPassword(ctx, b.User.UID, current, func(proof *identity.PasswordProof) error {
		return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
			switch action {
			case "email":
				if err := database.LockNamespaces(ctx, tx, s.Store, "email"); err != nil {
					return err
				}
			case "delete":
				if err := database.LockNamespaces(ctx, tx, s.Store, "email", "mail", "player-name", "registration", "uuid"); err != nil {
					return err
				}
			}
			u, err := s.Identity.CheckBrowserTx(ctx, tx, b)
			if err != nil {
				return err
			}
			if proof.UID() != u.UID {
				return identity.ErrStale
			}
			if _, err = s.Identity.RecheckPassword(ctx, tx, proof); err != nil {
				return err
			}
			switch action {
			case "password":
				if err = s.Identity.RevokeUID(ctx, tx, u.UID); err != nil {
					return err
				}
				_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET password=? WHERE uid=?", hash, u.UID)
			case "email":
				if err = s.emailAvailable(ctx, tx, value, 0); err != nil {
					return err
				}
				if err = s.Identity.RevokeUID(ctx, tx, u.UID); err != nil {
					return err
				}
				_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET email=?,verified=0 WHERE uid=?", value, u.UID)
			case "delete":
				if u.Permission >= 1 {
					return ErrForbidden
				}
				err = s.deleteUser(ctx, tx, u.UID)
			default:
				return ErrForbidden
			}
			return err
		})
	})
}
func (s *Service) deleteUser(ctx context.Context, tx *sql.Tx, uid int64) error {
	if err := s.Identity.RevokeUID(ctx, tx, uid); err != nil {
		return err
	}
	lifecycle := players.New(s.Store, s.Identity, s.Site, s.Now)
	if err := lifecycle.DeleteAllTx(ctx, tx, uid); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("users")+" WHERE uid=?", uid)
	return err
}

type SignResult struct{ Award, Score int64 }

func (s *Service) Sign(ctx context.Context, b *identity.BrowserSession) (SignResult, error) {
	options, err := s.Site.Options(ctx)
	if err != nil {
		return SignResult{}, err
	}
	var min, max int64
	parts := strings.Split(optionString(options["sign_score"]), ",")
	if len(parts) != 2 {
		return SignResult{}, errors.New("account: invalid sign_score")
	}
	min, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return SignResult{}, err
	}
	max, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil || max < min {
		return SignResult{}, errors.New("account: invalid sign_score")
	}
	var out SignResult
	err = s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		u, err := s.Identity.CheckBrowserTx(ctx, tx, b)
		if err != nil {
			return err
		}
		var last time.Time
		if err = tx.QueryRowContext(ctx, "SELECT score,last_sign_at FROM "+s.Store.Table("users")+" WHERE uid=? FOR UPDATE", u.UID).Scan(&out.Score, &last); err != nil {
			return err
		}
		now := s.Now().In(s.Site.Location)
		last = last.In(s.Site.Location)
		if site.Truth(options["sign_after_zero"]) {
			today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, s.Site.Location)
			if !last.Before(today) {
				return ErrTooSoon
			}
		} else if last.Add(time.Duration(site.Number(options["sign_gap_time"])) * time.Hour).After(now) {
			return ErrTooSoon
		}
		out.Award = s.Award(min, max)
		out.Score += out.Award
		_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=?,last_sign_at=? WHERE uid=?", out.Score, now, u.UID)
		return err
	})
	return out, err
}
func optionString(v any) string { s, _ := v.(string); return s }

func (s *Service) Avatar(ctx context.Context, b *identity.BrowserSession, tid int64) error {
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		u, err := s.Identity.CheckBrowserTx(ctx, tx, b)
		if err != nil {
			return err
		}
		if tid != 0 {
			var kind string
			var public bool
			var owner int64
			err = tx.QueryRowContext(ctx, "SELECT type,public,uploader FROM "+s.Store.Table("textures")+" WHERE tid=? FOR UPDATE", tid).Scan(&kind, &public, &owner)
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			if err != nil {
				return err
			}
			if kind == "cape" {
				return ErrAvatarType
			}
			if !public && owner != u.UID && u.Permission < 1 {
				return ErrPrivateTexture
			}
		}
		_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET avatar=? WHERE uid=?", tid, u.UID)
		return err
	})
}

var ErrAvatarType = errors.New("account: cape cannot be an avatar")
var ErrPrivateTexture = errors.New("account: private texture")

// AdminChange rechecks actor and target under ascending UID locks before
// rechecking the browser credential. It owns every account revocation entry.
func (s *Service) AdminChange(ctx context.Context, b *identity.BrowserSession, target int64, action, value string) error {
	var hash string
	var err error
	if action == "password" {
		if err = password.ValidateAdminReset(value); err != nil {
			return err
		}
		hash, err = s.hash(ctx, value)
		if err != nil {
			return err
		}
	}
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		switch action {
		case "email":
			if err := database.LockNamespaces(ctx, tx, s.Store, "email"); err != nil {
				return err
			}
		case "delete":
			if err := database.LockNamespaces(ctx, tx, s.Store, "email", "mail", "player-name", "registration", "uuid"); err != nil {
				return err
			}
		}
		ids := []int64{b.User.UID}
		if target != b.User.UID {
			ids = append(ids, target)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		var permission int
		for _, uid := range ids {
			var p int
			if err := tx.QueryRowContext(ctx, "SELECT permission FROM "+s.Store.Table("users")+" WHERE uid=? FOR UPDATE", uid).Scan(&p); errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			} else if err != nil {
				return err
			}
			if uid == target {
				permission = p
			}
		}
		actor, err := s.Identity.CheckBrowserTx(ctx, tx, b)
		if err != nil {
			return err
		}
		if actor.Permission < 1 || (target != actor.UID && permission >= actor.Permission) {
			return ErrForbidden
		}
		switch action {
		case "password":
			if err = s.Identity.RevokeUID(ctx, tx, target); err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET password=? WHERE uid=?", hash, target)
		case "permission":
			p, parseErr := strconv.ParseInt(value, 10, 64)
			if parseErr != nil || (p != -1 && p != 0 && p != 1) {
				return ErrForbidden
			}
			if target == actor.UID || (p == 1 && actor.Permission < 2) {
				return ErrForbidden
			}
			if p == -1 {
				if err = s.Identity.RevokeUID(ctx, tx, target); err != nil {
					return err
				}
				// Keep the profile Last-Modified visible to clients when the
				// owner is banned (M3 design: ban updates player timestamps).
				if _, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("players")+" SET last_modified=? WHERE uid=?", s.Now().In(s.Site.Location), target); err != nil {
					return err
				}
			}
			_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET permission=? WHERE uid=?", p, target)
		case "delete":
			err = s.deleteUser(ctx, tx, target)
		case "email":
			if err = s.emailAvailable(ctx, tx, value, target); err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET email=? WHERE uid=?", value, target)
		case "score":
			score, parseErr := strconv.ParseInt(value, 10, 64)
			if parseErr != nil {
				return parseErr
			}
			_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET score=? WHERE uid=?", score, target)
		case "nickname":
			_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET nickname=? WHERE uid=?", value, target)
		case "verification":
			_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET verified=NOT verified WHERE uid=?", target)
		default:
			return ErrForbidden
		}
		return err
	})
}

// SetLocale persists the language link preference for the current browser
// account. An empty value clears the nullable legacy preference.
func (s *Service) SetLocale(ctx context.Context, b *identity.BrowserSession, locale string) error {
	return s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		u, err := s.Identity.CheckBrowserTx(ctx, tx, b)
		if err != nil {
			return err
		}
		var value any = locale
		if locale == "" {
			value = nil
		}
		_, err = tx.ExecContext(ctx, "UPDATE "+s.Store.Table("users")+" SET locale=? WHERE uid=?", value, u.UID)
		return err
	})
}
