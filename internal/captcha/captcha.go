// Package captcha owns session-bound, single-attempt image challenges.
package captcha

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/identity"
)

type Service struct {
	Store    *database.Store
	Identity *identity.Service
	Client   *http.Client
}

var ErrUnavailable = errors.New("captcha: verification unavailable")

func niceize(s string) string {
	return strings.NewReplacer("0", "o", "1", "l").Replace(strings.ToLower(s))
}
func random(n int64) int {
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		panic(err)
	}
	return int(v.Int64())
}

const charset = "abcdefghijklmnpqrstuvwxyz123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

//go:embed fonts/captcha*.ttf
var captchaFonts embed.FS

var bundledFonts = sync.OnceValues(func() ([][]byte, error) {
	fonts := make([][]byte, 0, 6)
	for index := 0; index < 6; index++ {
		data, err := captchaFonts.ReadFile("fonts/captcha" + strconv.Itoa(index) + ".ttf")
		if err != nil {
			return nil, err
		}
		fonts = append(fonts, data)
	}
	return fonts, nil
})

func render() (string, []byte, error) {
	fonts, err := bundledFonts()
	if err != nil {
		return "", nil, err
	}
	phrase := make([]byte, 5)
	for i := range phrase {
		phrase[i] = charset[random(int64(len(charset)))]
	}
	seed, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return "", nil, err
	}
	img, err := buildImage(seed.Int64(), string(phrase), fonts, func(fontData []byte, size float64) (glyphFace, error) {
		return newGlyphFace(fontData, size)
	})
	if err != nil {
		return "", nil, err
	}
	pixels, err := encodeJPEG(img)
	return string(phrase), pixels, err
}

func (s *Service) Generate(ctx context.Context, b *identity.BrowserSession) ([]byte, error) {
	phrase, pixels, err := render()
	if err != nil {
		return nil, err
	}
	err = s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if b.User != nil {
			if _, err := s.Identity.CheckBrowserTx(ctx, tx, b); err != nil {
				return err
			}
		}
		// Credential validation and challenge replacement use the same lock. A reset
		// or logout cannot leave a usable challenge bound only to an old snapshot.
		var expires int64
		if err := tx.QueryRowContext(ctx, "SELECT expires_at FROM "+s.Store.Table("go_web_sessions")+" WHERE digest=? FOR UPDATE", identity.Digest(b.Token)).Scan(&expires); errors.Is(err, sql.ErrNoRows) {
			return identity.ErrSession
		} else if err != nil {
			return err
		}
		if expires <= s.Identity.Now().Unix() {
			return identity.ErrSession
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("go_captchas")+" (session_digest,answer_digest,expires_at) VALUES (?,?,?) ON DUPLICATE KEY UPDATE answer_digest=VALUES(answer_digest),expires_at=VALUES(expires_at)", identity.Digest(b.Token), identity.Digest(niceize(phrase)), expires)
		return err
	})
	return pixels, err
}
func (s *Service) Check(ctx context.Context, b *identity.BrowserSession, answer, secret string) (bool, error) {
	// Resolve current session instead of trusting the caller's snapshot. The
	// local answer is consumed under the session row lock below.
	if _, err := s.Identity.Session(ctx, b.Token); err != nil {
		return false, err
	}
	if secret != "" {
		req, err := http.NewRequestWithContext(ctx, "POST", "https://www.recaptcha.net/recaptcha/api/siteverify", strings.NewReader(url.Values{"secret": {secret}, "response": {answer}}.Encode()))
		if err != nil {
			return false, ErrUnavailable
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := s.Client.Do(req)
		if err != nil {
			return false, ErrUnavailable
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			return false, ErrUnavailable
		}
		var data struct {
			Success *bool `json:"success"`
		}
		if err = json.NewDecoder(response.Body).Decode(&data); err != nil || data.Success == nil {
			return false, ErrUnavailable
		}
		return *data.Success, nil
	}
	valid := false
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		if b.User != nil {
			if _, err := s.Identity.CheckBrowserTx(ctx, tx, b); err != nil {
				return err
			}
		}
		var expires int64
		if err := tx.QueryRowContext(ctx, "SELECT expires_at FROM "+s.Store.Table("go_web_sessions")+" WHERE digest=? FOR UPDATE", identity.Digest(b.Token)).Scan(&expires); errors.Is(err, sql.ErrNoRows) {
			return identity.ErrSession
		} else if err != nil {
			return err
		}
		if expires <= s.Identity.Now().Unix() {
			return identity.ErrSession
		}
		var digest []byte
		var expiry int64
		err := tx.QueryRowContext(ctx, "SELECT answer_digest,expires_at FROM "+s.Store.Table("go_captchas")+" WHERE session_digest=? FOR UPDATE", identity.Digest(b.Token)).Scan(&digest, &expiry)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM "+s.Store.Table("go_captchas")+" WHERE session_digest=?", identity.Digest(b.Token)); err != nil {
			return err
		}
		valid = expiry > s.Identity.Now().Unix() && subtle.ConstantTimeCompare(digest, identity.Digest(niceize(answer))) == 1
		return nil
	})
	return valid, err
}

// LoginFailures keeps the original sliding one-hour IP window. Only the HTTP
// credential-error branch increments it; missing accounts do not increment.
func (s *Service) LoginFailures(ctx context.Context, ip string) (int64, error) {
	var count int64
	err := s.Store.DB.QueryRowContext(ctx, "SELECT count FROM "+s.Store.Table("go_browser_limits")+" WHERE digest=? AND expires_at>?", identity.Digest("login:"+ip), s.Identity.Now().Unix()).Scan(&count)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return count, err
}
func (s *Service) Failed(ctx context.Context, ip string) (int64, error) {
	var count int64
	err := s.Store.Transaction(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO "+s.Store.Table("go_browser_limits")+" (digest,count,expires_at) VALUES (?,1,?) ON DUPLICATE KEY UPDATE count=IF(expires_at>?,count+1,1),expires_at=VALUES(expires_at)", identity.Digest("login:"+ip), s.Identity.Now().Add(time.Hour).Unix(), s.Identity.Now().Unix())
		if err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, "SELECT count FROM "+s.Store.Table("go_browser_limits")+" WHERE digest=? FOR UPDATE", identity.Digest("login:"+ip)).Scan(&count)
	})
	return count, err
}
func (s *Service) Succeeded(ctx context.Context, ip string) error {
	_, err := s.Store.DB.ExecContext(ctx, "DELETE FROM "+s.Store.Table("go_browser_limits")+" WHERE digest=?", identity.Digest("login:"+ip))
	return err
}
