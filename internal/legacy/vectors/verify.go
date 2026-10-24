package vectors

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"blessing-skin-go/internal/legacy/laravel"
	"blessing-skin-go/internal/legacy/password"
	"blessing-skin-go/internal/legacy/php"
	"blessing-skin-go/internal/legacy/remember"
	"blessing-skin-go/internal/legacy/session"
	"blessing-skin-go/internal/legacy/users"
)

// Options controls verification side effects and external lookups.
type Options struct {
	// SessionsDir overrides config.session.files (needed when the vectors were
	// produced inside a container with a different mount path).
	SessionsDir string
	// Repo is required for identity and remember-token checks.
	Repo *users.Repo
	Now  time.Time
}

type checker struct {
	file  *File
	enc   *laravel.Encrypter
	store *session.Store
	opts  Options
}

// Verify runs every vector and returns a deterministic report.
func Verify(file *File, opts Options) (*Report, error) {
	enc, err := laravel.NewEncrypter(laravel.ParseAppKey(file.Config.AppKey), file.Config.Cipher)
	if err != nil {
		return nil, err
	}
	dir := opts.SessionsDir
	if dir == "" {
		dir = file.Config.Session.Files
	}
	store, err := session.NewStore(dir, time.Duration(file.Config.Session.LifetimeMinutes)*time.Minute)
	if err != nil {
		return nil, err
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	store.Now = func() time.Time { return opts.Now }
	c := &checker{file: file, enc: enc, store: store, opts: opts}

	report := &Report{Schema: "m1-vectors-report/1", GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	for _, v := range file.Vectors {
		result := c.check(v)
		report.Total++
		report.Results = append(report.Results, result)
		switch {
		case result.Detail == "skipped":
			report.Skipped++
		case result.Passed:
			report.Passed++
		default:
			report.Failed++
		}
	}
	return report, nil
}

func (c *checker) check(v Vector) Result {
	result := Result{ID: v.ID, Domain: v.Domain, Classification: v.Classification}
	passed, detail, err := c.dispatch(v)
	result.Passed = passed
	result.Detail = detail
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func (c *checker) dispatch(v Vector) (bool, string, error) {
	switch v.Domain {
	case "session":
		return c.checkSession(v)
	case "csrf":
		return c.checkCSRF(v)
	case "remember":
		return c.checkRemember(v)
	case "password":
		return c.checkPassword(v)
	case "identify":
		return c.checkIdentify(v)
	case "email-syntax":
		return c.checkEmailSyntax(v)
	default:
		return false, "unknown domain", fmt.Errorf("vectors: unknown domain %q", v.Domain)
	}
}

type sessionInput struct {
	Cookie          string `json:"cookie"`
	SID             string `json:"sid"`
	SessionID       string `json:"session_id"`
	SessionsDir     string `json:"sessions_dir"`
	LifetimeMinutes int    `json:"lifetime_minutes"`
	Note            string `json:"note"`
}

type sessionExpect struct {
	Authenticated bool  `json:"authenticated"`
	UID           int64 `json:"uid"`
	CSRFPresent   bool  `json:"csrf_present"`
	OldBefore     any   `json:"old_before"`
	NewBefore     any   `json:"new_before"`
}

func (c *checker) checkSession(v Vector) (bool, string, error) {
	var in sessionInput
	var expect sessionExpect
	if err := json.Unmarshal(v.Input, &in); err != nil {
		return false, "", err
	}
	if err := json.Unmarshal(v.Expect, &expect); err != nil {
		return false, "", err
	}
	if in.SessionID != "" && in.Cookie == "" {
		attrs, err := c.store.Read(in.SessionID)
		if err != nil {
			return false, "session unavailable", err
		}
		old, ok := attrs.GetPath("_flash.old")
		oldArr, isArr := old.(*php.Array)
		if !ok || !isArr || len(oldArr.Entries) != 0 {
			return false, "expected empty _flash.old", nil
		}
		status, ok := attrs.GetPath("_flash.new.status")
		if !ok || status != "ok" {
			return false, "expected _flash.new.status=ok", nil
		}
		return true, "flash payload matched", nil
	}

	id, err := session.SessionIDFromCookie(c.enc, c.file.Config.Session.Cookie, in.Cookie)
	if err != nil {
		if !expect.Authenticated {
			return true, "rejected: " + err.Error(), nil
		}
		return false, "cookie rejected", err
	}
	attrs, err := c.store.Read(id)
	if err != nil {
		if !expect.Authenticated {
			return true, "rejected: " + err.Error(), nil
		}
		return false, "session unavailable", err
	}
	uid, ok := session.LoginUID(attrs, c.file.Config.Guard.LoginKey)
	if ok != expect.Authenticated {
		return false, fmt.Sprintf("authenticated=%v want %v", ok, expect.Authenticated), nil
	}
	if ok && expect.UID != 0 && uid != expect.UID {
		return false, fmt.Sprintf("uid=%d want %d", uid, expect.UID), nil
	}
	if expect.CSRFPresent {
		if _, ok := session.CSRF(attrs); !ok {
			return false, "csrf token missing", nil
		}
	}
	return true, "uid matched", nil
}

type csrfInput struct {
	SessionID   string `json:"session_id"`
	SessionsDir string `json:"sessions_dir"`
	Token       string `json:"token"`
	Cookie      string `json:"cookie"`
}

type csrfExpect struct {
	Matches         bool `json:"matches"`
	DecryptsToToken bool `json:"decrypts_to_token"`
}

func (c *checker) checkCSRF(v Vector) (bool, string, error) {
	var in csrfInput
	var expect csrfExpect
	if err := json.Unmarshal(v.Input, &in); err != nil {
		return false, "", err
	}
	if err := json.Unmarshal(v.Expect, &expect); err != nil {
		return false, "", err
	}

	if in.Cookie != "" {
		decrypted, err := c.enc.DecryptCookie(c.file.Config.CSRF.Cookie, in.Cookie)
		if err != nil {
			return false, "xsrf cookie rejected", err
		}
		if expect.DecryptsToToken && decrypted != in.Token {
			return false, "xsrf token mismatch", nil
		}
		return true, "xsrf cookie decrypted", nil
	}

	attrs, err := c.store.Read(in.SessionID)
	if err != nil {
		return false, "session unavailable", err
	}
	stored, ok := session.CSRF(attrs)
	if !ok {
		return false, "no _token in session", nil
	}
	matches := subtle.ConstantTimeCompare([]byte(stored), []byte(in.Token)) == 1
	if matches != expect.Matches {
		return false, fmt.Sprintf("matches=%v want %v", matches, expect.Matches), nil
	}
	return true, "token compared", nil
}

type rememberInput struct {
	Cookie        string `json:"cookie"`
	RecallerValue string `json:"recaller_value"`
	RotatedToken  string `json:"rotated_token"`
	Minutes       int    `json:"minutes"`
}

type rememberExpect struct {
	UID           int64 `json:"uid"`
	Authenticated bool  `json:"authenticated"`
	Minutes       int   `json:"minutes"`
}

func (c *checker) checkRemember(v Vector) (bool, string, error) {
	var in rememberInput
	var expect rememberExpect
	if err := json.Unmarshal(v.Input, &in); err != nil {
		return false, "", err
	}
	if err := json.Unmarshal(v.Expect, &expect); err != nil {
		return false, "", err
	}
	if in.Minutes > 0 {
		if in.Minutes != expect.Minutes {
			return false, fmt.Sprintf("remember minutes=%d want %d", in.Minutes, expect.Minutes), nil
		}
		return true, "guard default matched", nil
	}
	if in.Cookie == "" {
		return false, "", errors.New("remember vector lacks a cookie")
	}
	r, err := remember.Cookie(c.enc, c.file.Config.Guard.RecallerName, in.Cookie)
	if err != nil {
		if !expect.Authenticated {
			return true, "rejected: " + err.Error(), nil
		}
		return false, "recaller rejected", err
	}
	if c.opts.Repo == nil {
		return false, "skipped", errors.New("remember check needs a database")
	}
	ctx := context.Background()
	user, ok, err := c.opts.Repo.ByUID(ctx, r.UID)
	if err != nil {
		return false, "db error", err
	}
	if !ok {
		if !expect.Authenticated {
			return true, "no such user", nil
		}
		return false, "no such user", nil
	}
	accepted := user.RememberToken != "" && subtle.ConstantTimeCompare([]byte(user.RememberToken), []byte(r.Token)) == 1
	if accepted != expect.Authenticated {
		return false, fmt.Sprintf("recaller accepted=%v want %v", accepted, expect.Authenticated), nil
	}
	if expect.UID != 0 && user.UID != expect.UID {
		return false, fmt.Sprintf("uid=%d want %d", user.UID, expect.UID), nil
	}
	return true, "token compared against users.remember_token", nil
}

type passwordInput struct {
	UID      int64  `json:"uid"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Input    string `json:"input"`
	Salt     string `json:"salt"`
	Method   string `json:"method"`
}

type passwordExpect struct {
	Valid bool `json:"valid"`
}

func (c *checker) checkPassword(v Vector) (bool, string, error) {
	var in passwordInput
	var expect passwordExpect
	if err := json.Unmarshal(v.Input, &in); err != nil {
		return false, "", err
	}
	if err := json.Unmarshal(v.Expect, &expect); err != nil {
		return false, "", err
	}
	if in.Method == "" {
		in.Method = c.file.Config.Password.Method
	}
	if in.Salt == "" {
		in.Salt = c.file.Config.Password.Salt
	}
	hasher, err := password.New(in.Method, in.Salt)
	if err != nil {
		return false, "unsupported method", err
	}
	got, err := hasher.Verify(in.Input, in.Password)
	if err != nil {
		return false, "verify error", err
	}
	if got != expect.Valid {
		return false, fmt.Sprintf("valid=%v want %v (method %s)", got, expect.Valid, hasher.Method()), nil
	}
	return true, "method " + string(hasher.Method()), nil
}

type identifyInput struct {
	Identification string `json:"identification"`
	Mode           string `json:"mode"`
}

type identifyExpect struct {
	Authenticated bool   `json:"authenticated"`
	UID           int64  `json:"uid"`
	Type          string `json:"type"`
}

func (c *checker) checkIdentify(v Vector) (bool, string, error) {
	var in identifyInput
	var expect identifyExpect
	if err := json.Unmarshal(v.Input, &in); err != nil {
		return false, "", err
	}
	if err := json.Unmarshal(v.Expect, &expect); err != nil {
		return false, "", err
	}
	if c.opts.Repo == nil {
		return false, "skipped", errors.New("identify check needs a database")
	}
	ctx := context.Background()
	isEmail := users.EmailLooksLikeEmail(in.Identification)
	if expect.Type != "" {
		wantEmail := expect.Type == "email"
		if isEmail != wantEmail {
			return false, fmt.Sprintf("email syntax=%v want %v", isEmail, wantEmail), nil
		}
	}
	var user *users.User
	var ok bool
	var err error
	if isEmail {
		user, ok, err = c.opts.Repo.ByEmail(ctx, in.Identification)
	} else {
		user, ok, err = c.opts.Repo.ByPlayerName(ctx, in.Identification)
	}
	if err != nil {
		return false, "db error", err
	}
	if ok != expect.Authenticated {
		return false, fmt.Sprintf("found=%v want %v", ok, expect.Authenticated), nil
	}
	if ok && expect.UID != 0 && user.UID != expect.UID {
		return false, fmt.Sprintf("uid=%d want %d", user.UID, expect.UID), nil
	}
	return true, "lookup matched", nil
}

type emailSyntaxInput struct {
	Value string `json:"value"`
}

type emailSyntaxExpect struct {
	Valid bool `json:"valid"`
}

func (c *checker) checkEmailSyntax(v Vector) (bool, string, error) {
	var in emailSyntaxInput
	var expect emailSyntaxExpect
	if err := json.Unmarshal(v.Input, &in); err != nil {
		return false, "", err
	}
	if err := json.Unmarshal(v.Expect, &expect); err != nil {
		return false, "", err
	}
	got := users.EmailLooksLikeEmail(in.Value)
	if got != expect.Valid {
		return false, fmt.Sprintf("valid=%v want %v", got, expect.Valid), nil
	}
	return true, "filter_var corpus matched", nil
}
