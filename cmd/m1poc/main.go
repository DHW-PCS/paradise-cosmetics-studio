// Command m1poc runs the M1 compatibility proof-of-concept checks.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"paradise-cosmetics-studio/internal/legacy/auth"
	"paradise-cosmetics-studio/internal/legacy/cache"
	"paradise-cosmetics-studio/internal/legacy/laravel"
	"paradise-cosmetics-studio/internal/legacy/password"
	"paradise-cosmetics-studio/internal/legacy/remember"
	"paradise-cosmetics-studio/internal/legacy/revocation"
	"paradise-cosmetics-studio/internal/legacy/session"
	"paradise-cosmetics-studio/internal/legacy/users"
	"paradise-cosmetics-studio/internal/legacy/vectors"
	"paradise-cosmetics-studio/internal/legacy/web"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "vectors":
		err = cmdVectors(os.Args[2:])
	case "session":
		err = cmdSession(os.Args[2:])
	case "remember":
		err = cmdRemember(os.Args[2:])
	case "auth":
		err = cmdAuth(os.Args[2:])
	case "revocation":
		err = cmdRevocation(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "risk":
		err = cmdRisk(os.Args[2:])
	case "passport":
		err = cmdPassport(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `m1poc <command>

commands:
  vectors verify --dir DIR [--sessions-dir DIR] [--dsn DSN] [--prefix P] [--out FILE]
  session inspect --vectors PATH --cookie VALUE [--sessions-dir DIR]
  session mint    --vectors PATH --uid N [--sessions-dir DIR] [--out FILE]
  remember mint    --vectors PATH --uid N --dsn DSN [--out FILE]
  remember inspect --vectors PATH --cookie VALUE [--cookie-name NAME]
  auth login      --vectors PATH --identification ID --password PW --dsn DSN [--remember] [--out FILE]
  auth validate   --vectors PATH --cookie VALUE --dsn DSN [--out FILE]
  auth logout     --vectors PATH --cookie VALUE --dsn DSN [--out FILE]
  auth revoke     --vectors PATH --uid N --dsn DSN [--out FILE]
  revocation setup --dsn DSN [--prefix P]
  serve           --vectors PATH --dsn DSN [--addr HOST:PORT] [--sessions-dir DIR]
                  [--cache-dir DIR] [--cache-prefix P] [--private-key FILE] [--public-key FILE]
  passport client-create --id N --name NAME --secret S --redirect URI [--password-client]
  passport reset  --uid N --clients ID[,ID]
  passport code   --client N --uid N --redirect-uri URI --scopes LIST [--challenge C --method M]
  passport exchange --code C --client N --secret S --redirect-uri URI [--verifier V]
  passport refresh  --refresh-token T --client N --secret S [--scopes LIST]
  passport issue    --client N --secret S --username EMAIL --password PW [--scopes LIST]
  passport validate --access-token JWT
  passport revoke   --access-token JWT | --refresh-token T`)
}

func cmdVectors(args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return fmt.Errorf("usage: m1poc vectors verify --dir DIR")
	}
	fs := flag.NewFlagSet("vectors verify", flag.ContinueOnError)
	dir := fs.String("dir", "", "vector directory or file")
	sessionsDir := fs.String("sessions-dir", "", "override session storage directory")
	dsn := fs.String("dsn", "", "MySQL DSN for identity/remember checks")
	prefix := fs.String("prefix", "", "legacy table prefix")
	out := fs.String("out", "", "write the JSON report here")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("--dir is required")
	}
	file, err := vectors.LoadPath(*dir)
	if err != nil {
		return err
	}

	opts := vectors.Options{SessionsDir: *sessionsDir}
	if *dsn != "" {
		repo, err := users.Open(*dsn, *prefix)
		if err != nil {
			return err
		}
		defer repo.Close()
		opts.Repo = repo
	}

	report, err := vectors.Verify(file, opts)
	if err != nil {
		return err
	}
	report.Source = file.Source["release"]
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if *out != "" {
		if err := os.WriteFile(*out, data, 0o600); err != nil {
			return err
		}
	}
	fmt.Println(string(data))
	if report.Failed > 0 {
		return fmt.Errorf("%d of %d vectors failed", report.Failed, report.Total)
	}
	return nil
}

func cmdSession(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: m1poc session inspect|mint")
	}
	switch args[0] {
	case "inspect":
		return sessionInspect(args[1:])
	case "mint":
		return sessionMint(args[1:])
	default:
		return fmt.Errorf("unknown session subcommand %q", args[0])
	}
}

// appKey returns the vector bundle's key, unless M1POC_APP_KEY_FILE points at
// a file containing a key. That keeps production key material out of the
// vector JSON while still exercising the real secret.
func appKey(file *vectors.File) (string, error) {
	path := os.Getenv("M1POC_APP_KEY_FILE")
	if path == "" {
		return file.Config.AppKey, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// decryptCookieValue accepts both the raw cookie value used by the CLI tools
// and the URL-encoded value Symfony puts on the HTTP wire.
func decryptCookieValue(enc *laravel.Encrypter, name, value string) (string, error) {
	plain, err := enc.DecryptCookie(name, value)
	if err == nil {
		return plain, nil
	}
	if decoded, decodeErr := url.QueryUnescape(value); decodeErr == nil {
		if plain, decodeErr := enc.DecryptCookie(name, decoded); decodeErr == nil {
			return plain, nil
		}
	}
	return "", err
}

func loadEncrypter(file *vectors.File) (*laravel.Encrypter, *session.Store, error) {
	key, err := appKey(file)
	if err != nil {
		return nil, nil, err
	}
	enc, err := laravel.NewEncrypter(laravel.ParseAppKey(key), file.Config.Cipher)
	if err != nil {
		return nil, nil, err
	}
	store, err := session.NewStore(file.Config.Session.Files, time.Duration(file.Config.Session.LifetimeMinutes)*time.Minute)
	if err != nil {
		return nil, nil, err
	}
	return enc, store, nil
}

func sessionInspect(args []string) error {
	fs := flag.NewFlagSet("session inspect", flag.ContinueOnError)
	vectorPath := fs.String("vectors", "", "vector file")
	cookie := fs.String("cookie", "", "BS_SESSION cookie value")
	xsrf := fs.String("xsrf-cookie", "", "XSRF-TOKEN cookie value to verify")
	sessionsDir := fs.String("sessions-dir", "", "override session storage directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vectorPath == "" || *cookie == "" {
		return fmt.Errorf("--vectors and --cookie are required")
	}
	file, err := vectors.LoadPath(*vectorPath)
	if err != nil {
		return err
	}
	enc, store, err := loadEncrypter(file)
	if err != nil {
		return err
	}
	if *sessionsDir != "" {
		store, err = session.NewStore(*sessionsDir, time.Duration(file.Config.Session.LifetimeMinutes)*time.Minute)
		if err != nil {
			return err
		}
	}
	out := map[string]any{"cookie_accepted": false}
	id, err := decryptCookieValue(enc, file.Config.Session.Cookie, *cookie)
	if err != nil || !session.ValidID(id) {
		if err == nil {
			err = session.ErrInvalidID
		}
		out["error"] = err.Error()
		return printJSON(out)
	}
	out["cookie_accepted"] = true
	out["sid"] = id
	if info, statErr := os.Stat(store.Dir + "/" + id); statErr == nil {
		out["mtime_unix"] = info.ModTime().Unix()
		out["size"] = info.Size()
	}
	attrs, err := store.Read(id)
	if err != nil {
		out["session_error"] = err.Error()
		return printJSON(out)
	}
	out["authenticated"] = false
	if uid, ok := session.LoginUID(attrs, file.Config.Guard.LoginKey); ok {
		out["authenticated"] = true
		out["uid"] = uid
	}
	token, hasToken := session.CSRF(attrs)
	if hasToken {
		out["csrf"] = token
	}
	if previous, ok := attrs.GetPath("_previous.url"); ok {
		out["previous_url"] = previous
	}
	if *xsrf != "" {
		if plain, decryptErr := decryptCookieValue(enc, file.Config.CSRF.Cookie, *xsrf); decryptErr == nil {
			out["xsrf_cookie_accepted"] = true
			out["xsrf_matches_session"] = hasToken && plain == token
		} else {
			out["xsrf_cookie_accepted"] = false
		}
	}
	if flash, ok := attrs.Get("_flash"); ok {
		out["flash"] = flash
	}
	return printJSON(out)
}

func sessionMint(args []string) error {
	fs := flag.NewFlagSet("session mint", flag.ContinueOnError)
	vectorPath := fs.String("vectors", "", "vector file with config")
	uid := fs.Int64("uid", 0, "user id to log in")
	sessionsDir := fs.String("sessions-dir", "", "override session storage directory")
	outFile := fs.String("out", "", "write {sid,cookie} JSON here")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vectorPath == "" || *uid <= 0 {
		return fmt.Errorf("--vectors and --uid are required")
	}
	file, err := vectors.LoadPath(*vectorPath)
	if err != nil {
		return err
	}
	enc, store, err := loadEncrypter(file)
	if err != nil {
		return err
	}
	if *sessionsDir != "" {
		store, err = session.NewStore(*sessionsDir, time.Duration(file.Config.Session.LifetimeMinutes)*time.Minute)
		if err != nil {
			return err
		}
	}
	sid, err := session.NewID()
	if err != nil {
		return err
	}
	token, err := randomToken(40)
	if err != nil {
		return err
	}
	attrs := session.NewPayload(file.Config.Guard.LoginKey, *uid, token, "http://127.0.0.1:18070/user")
	if err := store.Write(sid, attrs); err != nil {
		return err
	}
	cookie, err := session.SessionCookieValue(enc, file.Config.Session.Cookie, sid)
	if err != nil {
		return err
	}
	out := map[string]any{
		"sid":           sid,
		"cookie":        cookie,
		"wire_cookie":   url.QueryEscape(cookie),
		"csrf":          token,
		"cookie_name":   file.Config.Session.Cookie,
		"payload_attrs": len(attrs.Entries),
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if *outFile != "" {
		if err := os.WriteFile(*outFile, data, 0o600); err != nil {
			return err
		}
	}
	fmt.Println(string(data))
	return nil
}

func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	const charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	out := make([]byte, n)
	for i := range buf {
		out[i] = charset[int(buf[i])%len(charset)]
	}
	return string(out), nil
}

// cmdRemember mints or inspects a recaller cookie. Minting rotates
// users.remember_token, which is the Go -> legacy PHP direction.
func cmdRemember(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: m1poc remember mint|inspect")
	}
	switch args[0] {
	case "mint":
		return rememberMint(args[1:])
	case "inspect":
		return rememberInspect(args[1:])
	default:
		return fmt.Errorf("unknown remember subcommand %q", args[0])
	}
}

func rememberInspect(args []string) error {
	fs := flag.NewFlagSet("remember inspect", flag.ContinueOnError)
	vectorPath := fs.String("vectors", "", "vector file with config")
	cookie := fs.String("cookie", "", "recaller cookie value")
	cookieName := fs.String("cookie-name", "", "override recaller cookie name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vectorPath == "" || *cookie == "" {
		return fmt.Errorf("--vectors and --cookie are required")
	}
	file, err := vectors.LoadPath(*vectorPath)
	if err != nil {
		return err
	}
	name := *cookieName
	if name == "" {
		name = file.Config.Guard.RecallerName
	}
	enc, err := laravel.NewEncrypter(laravel.ParseAppKey(file.Config.AppKey), file.Config.Cipher)
	if err != nil {
		return err
	}
	plain, err := decryptCookieValue(enc, name, *cookie)
	if err != nil {
		return printJSON(map[string]any{"accepted": false, "error": err.Error()})
	}
	recaller, err := remember.Parse(plain)
	if err != nil {
		return printJSON(map[string]any{"accepted": false, "error": err.Error()})
	}
	sum := sha256.Sum256([]byte(recaller.Token))
	return printJSON(map[string]any{
		"accepted":         true,
		"uid":              recaller.UID,
		"token_sha256":     hex.EncodeToString(sum[:]),
		"token_len":        len(recaller.Token),
		"password_len":     len(recaller.Password),
		"cookie_name":      name,
		"remember_minutes": file.Config.Guard.RememberMinutes,
	})
}

func rememberMint(args []string) error {
	fs := flag.NewFlagSet("remember mint", flag.ContinueOnError)
	vectorPath := fs.String("vectors", "", "vector file with config")
	uid := fs.Int64("uid", 0, "user id")
	dsn := fs.String("dsn", "", "MySQL DSN")
	prefix := fs.String("prefix", "", "legacy table prefix")
	outFile := fs.String("out", "", "write the result JSON here")
	// The caller (cmdRemember) already removed the "mint" subcommand, so the
	// remaining arguments start with the first flag. Slicing again dropped the
	// leading --vectors and made the documented invocation unusable (R10).
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vectorPath == "" || *uid <= 0 || *dsn == "" {
		return fmt.Errorf("--vectors, --uid and --dsn are required")
	}
	file, err := vectors.LoadPath(*vectorPath)
	if err != nil {
		return err
	}
	enc, err := laravel.NewEncrypter(laravel.ParseAppKey(file.Config.AppKey), file.Config.Cipher)
	if err != nil {
		return err
	}
	repo, err := users.Open(*dsn, *prefix)
	if err != nil {
		return err
	}
	defer repo.Close()

	user, ok, err := repo.ByUID(context.Background(), *uid)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("uid %d not found", *uid)
	}
	token, err := randomToken(60)
	if err != nil {
		return err
	}
	if err := repo.UpdateRememberToken(context.Background(), *uid, token); err != nil {
		return err
	}
	value := remember.Format(user.UID, token, user.Password)
	cookie, err := remember.CookieValue(enc, file.Config.Guard.RecallerName, &remember.Recaller{
		UID: user.UID, Token: token, Password: user.Password,
	})
	if err != nil {
		return err
	}
	out := map[string]any{
		"uid":                user.UID,
		"recaller_value":     value,
		"cookie":             cookie,
		"cookie_name":        file.Config.Guard.RecallerName,
		"expires_in_minutes": file.Config.Guard.RememberMinutes,
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if *outFile != "" {
		if err := os.WriteFile(*outFile, data, 0o600); err != nil {
			return err
		}
	}
	fmt.Println(string(data))
	return nil
}

func printJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

type serviceSet struct {
	file   *vectors.File
	enc    *laravel.Encrypter
	store  *session.Store
	repo   *users.Repo
	svc    *auth.Service
	prefix string
}

func openService(vectorPath, dsn, prefix, sessionsDir string) (*serviceSet, error) {
	file, err := vectors.LoadPath(vectorPath)
	if err != nil {
		return nil, err
	}
	key, err := appKey(file)
	if err != nil {
		return nil, err
	}
	enc, err := laravel.NewEncrypter(laravel.ParseAppKey(key), file.Config.Cipher)
	if err != nil {
		return nil, err
	}
	dir := sessionsDir
	if dir == "" {
		dir = file.Config.Session.Files
	}
	store, err := session.NewStore(dir, time.Duration(file.Config.Session.LifetimeMinutes)*time.Minute)
	if err != nil {
		return nil, err
	}
	repo, err := users.Open(dsn, prefix)
	if err != nil {
		return nil, err
	}
	hasher, err := password.New(file.Config.Password.Method, file.Config.Password.Salt)
	if err != nil {
		repo.Close()
		return nil, err
	}
	svc := &auth.Service{
		Repo:     repo,
		Rev:      revocation.New(repo.DB(), prefix),
		Hasher:   hasher,
		Secret:   laravel.ParseAppKey(key),
		LoginKey: file.Config.Guard.LoginKey,
	}
	return &serviceSet{file: file, enc: enc, store: store, repo: repo, svc: svc, prefix: prefix}, nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:18080", "listen address")
	vectorPath := fs.String("vectors", "", "vector file")
	dsn := fs.String("dsn", "", "MySQL DSN")
	prefix := fs.String("prefix", "", "legacy table prefix")
	sessionsDir := fs.String("sessions-dir", "", "override session storage directory")
	cacheDir := fs.String("cache-dir", "", "override Laravel file cache directory")
	cachePrefix := fs.String("cache-prefix", "blessing_skin_cache", "Laravel cache key prefix")
	privateKeyPath := fs.String("private-key", "/bs/storage/oauth-private.key", "Passport RSA private key")
	publicKeyPath := fs.String("public-key", "/bs/storage/oauth-public.key", "Passport RSA public key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vectorPath == "" || *dsn == "" {
		return fmt.Errorf("--vectors and --dsn are required")
	}
	set, err := openService(*vectorPath, *dsn, *prefix, *sessionsDir)
	if err != nil {
		return err
	}
	defer set.repo.Close()

	dir := *cacheDir
	if dir == "" {
		dir = filepath.Join(filepath.Dir(set.store.Dir), "cache", "data")
	}
	cacheStore, err := cache.NewStore(dir, *cachePrefix)
	if err != nil {
		return err
	}
	passportService, err := openPassport(set, *privateKeyPath, *publicKeyPath)
	if err != nil {
		return err
	}

	sessionConfig := set.file.Config.Session
	domain := ""
	if sessionConfig.Domain != nil {
		domain = *sessionConfig.Domain
	}
	xsrfCookie := set.file.Config.CSRF.Cookie
	if xsrfCookie == "" {
		xsrfCookie = "XSRF-TOKEN"
	}
	guard := set.file.Config.Guard
	server, err := web.New(web.Config{
		Encrypter: set.enc,
		Sessions:  set.store,
		Cache:     cacheStore,
		Auth:      set.svc,
		Users:     set.repo,
		SessionCookie: laravel.CookieAttributes{
			Name:     sessionConfig.Cookie,
			Path:     sessionConfig.Path,
			Domain:   domain,
			Secure:   sessionConfig.Secure,
			HTTPOnly: sessionConfig.HTTPOnly,
			SameSite: sessionConfig.SameSite,
			Lifetime: time.Duration(sessionConfig.LifetimeMinutes) * time.Minute,
		},
		XSRFCookie:       xsrfCookie,
		RememberCookie:   guard.RecallerName,
		RememberLifetime: remember.Duration(guard.RememberMinutes),
		LoginKey:         guard.LoginKey,
		Bearer: func(ctx context.Context, token string) (*web.BearerIdentity, error) {
			identity, err := passportService.ValidateAccess(ctx, token)
			if err != nil {
				return nil, err
			}
			return &web.BearerIdentity{
				UID:      identity.UID,
				ClientID: identity.ClientID,
				Scopes:   identity.Scopes,
			}, nil
		},
	})
	if err != nil {
		return err
	}
	httpServer, err := server.Serve(*addr)
	if err != nil {
		return err
	}
	if err := printJSON(map[string]any{"listening": *addr}); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdown)
}

func cmdRevocation(args []string) error {
	if len(args) == 0 || (args[0] != "setup" && args[0] != "reset") {
		return fmt.Errorf("usage: m1poc revocation setup|reset --dsn DSN")
	}
	fs := flag.NewFlagSet("revocation "+args[0], flag.ContinueOnError)
	dsn := fs.String("dsn", "", "MySQL DSN")
	prefix := fs.String("prefix", "", "legacy table prefix")
	uid := fs.Int64("uid", 0, "user id (reset only)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *dsn == "" {
		return fmt.Errorf("--dsn is required")
	}
	repo, err := users.Open(*dsn, *prefix)
	if err != nil {
		return err
	}
	defer repo.Close()
	store := revocation.New(repo.DB(), *prefix)
	if args[0] == "setup" {
		if err := store.EnsureSchema(context.Background()); err != nil {
			return err
		}
		return printJSON(map[string]any{"table": *prefix + revocation.Table, "created": true})
	}
	if *uid <= 0 {
		return fmt.Errorf("--uid is required for reset")
	}
	if err := store.Reset(context.Background(), *uid); err != nil {
		return err
	}
	return printJSON(map[string]any{"table": *prefix + revocation.Table, "uid": *uid, "reset": true})
}

func cmdAuth(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: m1poc auth login|validate|logout|revoke")
	}
	switch args[0] {
	case "login":
		return authLogin(args[1:])
	case "validate":
		return authValidate(args[1:])
	case "logout":
		return authLogout(args[1:])
	case "revoke":
		return authRevoke(args[1:])
	default:
		return fmt.Errorf("unknown auth subcommand %q", args[0])
	}
}

func authLogin(args []string) error {
	fs := flag.NewFlagSet("auth login", flag.ContinueOnError)
	vectorPath := fs.String("vectors", "", "vector file")
	identification := fs.String("identification", "", "email or player name")
	raw := fs.String("password", "", "password")
	dsn := fs.String("dsn", "", "MySQL DSN")
	prefix := fs.String("prefix", "", "legacy table prefix")
	rememberMe := fs.Bool("remember", false, "issue a remember-me cookie")
	outFile := fs.String("out", "", "write the result JSON here")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vectorPath == "" || *identification == "" || *dsn == "" {
		return fmt.Errorf("--vectors, --identification and --dsn are required")
	}
	set, err := openService(*vectorPath, *dsn, *prefix, "")
	if err != nil {
		return err
	}
	defer set.repo.Close()

	ctx := context.Background()
	result, err := set.svc.Login(ctx, *identification, *raw, *rememberMe)
	if err != nil {
		return err
	}
	user, state := result.User, result.State
	token, err := randomToken(40)
	if err != nil {
		return err
	}
	sid, err := set.store.Rotate("")
	if err != nil {
		return err
	}
	attrs := set.svc.WritePayload(user, state, token, "http://127.0.0.1:18070/user")
	if err := set.store.Write(sid, attrs); err != nil {
		return err
	}
	cookie, err := session.SessionCookieValue(set.enc, set.file.Config.Session.Cookie, sid)
	if err != nil {
		return err
	}
	out := map[string]any{
		"uid":            user.UID,
		"permission":     user.Permission,
		"sid":            sid,
		"session_cookie": cookie,
		"cookie_name":    set.file.Config.Session.Cookie,
		"csrf":           token,
		"rev":            state.SessionVersion,
	}
	if result.Remember != "" {
		recallerCookie, err := remember.CookieValue(set.enc, set.file.Config.Guard.RecallerName, &remember.Recaller{
			UID: user.UID, Token: result.Remember, Password: user.Password,
		})
		if err != nil {
			return err
		}
		out["remember_cookie"] = recallerCookie
		out["remember_name"] = set.file.Config.Guard.RecallerName
	}
	return writeOutput(out, *outFile)
}

func authValidate(args []string) error {
	fs := flag.NewFlagSet("auth validate", flag.ContinueOnError)
	vectorPath := fs.String("vectors", "", "vector file")
	cookie := fs.String("cookie", "", "session cookie value")
	dsn := fs.String("dsn", "", "MySQL DSN")
	prefix := fs.String("prefix", "", "legacy table prefix")
	upgrade := fs.Bool("upgrade", false, "persist go_auth on an accepted legacy session")
	outFile := fs.String("out", "", "write the result JSON here")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vectorPath == "" || *cookie == "" || *dsn == "" {
		return fmt.Errorf("--vectors, --cookie and --dsn are required")
	}
	set, err := openService(*vectorPath, *dsn, *prefix, "")
	if err != nil {
		return err
	}
	defer set.repo.Close()

	out := map[string]any{"accepted": false}
	id, err := session.SessionIDFromCookie(set.enc, set.file.Config.Session.Cookie, *cookie)
	if err != nil {
		out["reason"] = "cookie_rejected"
		return writeOutput(out, *outFile)
	}
	out["sid"] = id
	attrs, err := set.store.Read(id)
	if err != nil {
		out["reason"] = "session_unavailable"
		return writeOutput(out, *outFile)
	}
	validation, err := set.svc.ValidateSession(context.Background(), attrs)
	switch {
	case errors.Is(err, auth.ErrBanned):
		out["reason"] = "banned"
	case errors.Is(err, auth.ErrStaleSession):
		out["reason"] = "revoked"
	case errors.Is(err, auth.ErrNoSession):
		out["reason"] = "no_session"
	case err != nil:
		out["reason"] = err.Error()
	default:
		out["accepted"] = true
		out["uid"] = validation.User.UID
		out["permission"] = validation.User.Permission
		out["legacy_session"] = validation.Legacy
		if validation.Legacy && *upgrade {
			state, err := set.svc.UpgradeLegacy(context.Background(), validation.User.UID)
			if err != nil {
				return err
			}
			set.svc.WriteGoAuth(attrs, validation.User.UID, state)
			if err := set.store.Write(id, attrs); err != nil {
				return err
			}
			out["upgraded"] = true
		}
	}
	return writeOutput(out, *outFile)
}

func authLogout(args []string) error {
	fs := flag.NewFlagSet("auth logout", flag.ContinueOnError)
	vectorPath := fs.String("vectors", "", "vector file")
	cookie := fs.String("cookie", "", "session cookie value")
	dsn := fs.String("dsn", "", "MySQL DSN")
	prefix := fs.String("prefix", "", "legacy table prefix")
	outFile := fs.String("out", "", "write the result JSON here")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vectorPath == "" || *cookie == "" || *dsn == "" {
		return fmt.Errorf("--vectors, --cookie and --dsn are required")
	}
	set, err := openService(*vectorPath, *dsn, *prefix, "")
	if err != nil {
		return err
	}
	defer set.repo.Close()

	ctx := context.Background()
	id, err := session.SessionIDFromCookie(set.enc, set.file.Config.Session.Cookie, *cookie)
	if err != nil {
		return err
	}
	attrs, err := set.store.Read(id)
	if err != nil {
		return err
	}
	uid, ok := session.LoginUID(attrs, set.file.Config.Guard.LoginKey)
	if !ok {
		return fmt.Errorf("session is not authenticated")
	}
	newID, err := set.store.Rotate(id)
	if err != nil {
		return err
	}
	attrs.Delete(set.file.Config.Guard.LoginKey)
	attrs.Delete("go_auth")
	if err := set.store.Write(newID, attrs); err != nil {
		return err
	}
	newCookie, err := session.SessionCookieValue(set.enc, set.file.Config.Session.Cookie, newID)
	if err != nil {
		return err
	}
	rememberToken, err := randomToken(60)
	if err != nil {
		return err
	}
	if err := set.repo.UpdateRememberToken(ctx, uid, rememberToken); err != nil {
		return err
	}
	return writeOutput(map[string]any{
		"uid": uid, "sid": newID, "session_cookie": newCookie,
		"cookie_name":      set.file.Config.Session.Cookie,
		"remember_rotated": true,
	}, *outFile)
}

func authRevoke(args []string) error {
	fs := flag.NewFlagSet("auth revoke", flag.ContinueOnError)
	vectorPath := fs.String("vectors", "", "vector file")
	uid := fs.Int64("uid", 0, "user id")
	dsn := fs.String("dsn", "", "MySQL DSN")
	prefix := fs.String("prefix", "", "legacy table prefix")
	outFile := fs.String("out", "", "write the result JSON here")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vectorPath == "" || *uid <= 0 || *dsn == "" {
		return fmt.Errorf("--vectors, --uid and --dsn are required")
	}
	set, err := openService(*vectorPath, *dsn, *prefix, "")
	if err != nil {
		return err
	}
	defer set.repo.Close()

	ctx := context.Background()
	state, _, err := set.svc.RevokeSessions(ctx, *uid)
	if err != nil {
		return err
	}
	return writeOutput(map[string]any{
		"uid": *uid, "rev": state.SessionVersion,
		"revoked_before": state.RevokedBefore, "remember_rotated": true,
	}, *outFile)
}

func writeOutput(v any, path string) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if path != "" {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return err
		}
	}
	fmt.Println(string(data))
	return nil
}
