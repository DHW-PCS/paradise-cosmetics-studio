package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"paradise-cosmetics-studio/internal/legacy/laravel"
	"paradise-cosmetics-studio/internal/legacy/passport"
)

const (
	passportAccessTTL  = 365 * 24 * time.Hour
	passportRefreshTTL = 365 * 24 * time.Hour
	passportCodeTTL    = 10 * time.Minute
)

type passportOptions struct {
	vectors    string
	dsn        string
	prefix     string
	privateKey string
	publicKey  string
}

func (o *passportOptions) bind(fs *flag.FlagSet) {
	fs.StringVar(&o.vectors, "vectors", "", "vector file")
	fs.StringVar(&o.dsn, "dsn", "", "MySQL DSN")
	fs.StringVar(&o.prefix, "prefix", "", "legacy table prefix")
	fs.StringVar(&o.privateKey, "private-key", "/bs/storage/oauth-private.key", "Passport private key")
	fs.StringVar(&o.publicKey, "public-key", "/bs/storage/oauth-public.key", "Passport public key")
}

type passportSet struct {
	*serviceSet
	svc *passport.Service
}

func (o passportOptions) open() (*passportSet, error) {
	if o.vectors == "" || o.dsn == "" {
		return nil, fmt.Errorf("--vectors and --dsn are required")
	}
	set, err := openService(o.vectors, o.dsn, o.prefix, "")
	if err != nil {
		return nil, err
	}
	svc, err := openPassport(set, o.privateKey, o.publicKey)
	if err != nil {
		set.repo.Close()
		return nil, err
	}
	return &passportSet{serviceSet: set, svc: svc}, nil
}

func openPassport(set *serviceSet, privateKeyPath, publicKeyPath string) (*passport.Service, error) {
	key, err := appKey(set.file)
	if err != nil {
		return nil, err
	}
	privateKey, err := passport.LoadPrivateKey(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	publicKey, err := passport.LoadPublicKey(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	return passport.New(passport.Config{
		DB:         set.repo.DB(),
		Prefix:     set.prefix,
		Users:      set.repo,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		AppKey:     laravel.ParseAppKey(key),
		AccessTTL:  passportAccessTTL,
		RefreshTTL: passportRefreshTTL,
		CodeTTL:    passportCodeTTL,
		Scopes:     passport.RegisteredScopes,
	})
}

func cmdPassport(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: m1poc passport <subcommand>")
	}
	switch args[0] {
	case "client-create":
		return passportClientCreate(args[1:])
	case "reset":
		return passportReset(args[1:])
	case "code":
		return passportCode(args[1:])
	case "exchange":
		return passportExchange(args[1:])
	case "refresh":
		return passportRefresh(args[1:])
	case "issue":
		return passportIssue(args[1:])
	case "validate":
		return passportValidate(args[1:])
	case "revoke":
		return passportRevoke(args[1:])
	default:
		return fmt.Errorf("unknown passport subcommand %q", args[0])
	}
}

func passportClientCreate(args []string) error {
	var opts passportOptions
	fs := flag.NewFlagSet("passport client-create", flag.ContinueOnError)
	opts.bind(fs)
	id := fs.Int64("id", 0, "client id")
	name := fs.String("name", "", "client name")
	secret := fs.String("secret", "", "client secret (empty for public)")
	redirect := fs.String("redirect", "", "comma-separated redirect URIs")
	password := fs.Bool("password-client", false, "password grant client")
	provider := fs.String("provider", "", "legacy user provider (users for password grant)")
	personal := fs.Bool("personal-client", false, "personal access client")
	revoked := fs.Bool("revoked", false, "mark revoked")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id <= 0 || *name == "" {
		return fmt.Errorf("--id and --name are required")
	}
	set, err := opts.open()
	if err != nil {
		return err
	}
	defer set.repo.Close()
	var redirects []string
	for _, uri := range strings.Split(*redirect, ",") {
		if uri != "" {
			redirects = append(redirects, uri)
		}
	}
	err = set.svc.ClientCreate(context.Background(), passport.Client{
		ID: *id, Name: *name, Secret: *secret, Redirect: redirects,
		Password: *password, PersonalAccess: *personal, Revoked: *revoked, Provider: *provider,
	})
	if err != nil {
		return err
	}
	return printJSON(map[string]any{"created": true, "id": *id, "name": *name})
}

func passportReset(args []string) error {
	var opts passportOptions
	fs := flag.NewFlagSet("passport reset", flag.ContinueOnError)
	opts.bind(fs)
	uid := fs.Int64("uid", 0, "user id")
	clients := fs.String("clients", "", "comma-separated client ids")
	if err := fs.Parse(args); err != nil {
		return err
	}
	set, err := opts.open()
	if err != nil {
		return err
	}
	defer set.repo.Close()
	var ids []int64
	for _, value := range strings.Split(*clients, ",") {
		if value == "" {
			continue
		}
		id, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid client id %q", value)
		}
		ids = append(ids, id)
	}
	if err := set.svc.Reset(context.Background(), *uid, ids); err != nil {
		return err
	}
	return printJSON(map[string]any{"reset": true, "uid": *uid, "clients": ids})
}

func passportCode(args []string) error {
	var opts passportOptions
	fs := flag.NewFlagSet("passport code", flag.ContinueOnError)
	opts.bind(fs)
	client := fs.Int64("client", 0, "client id")
	uid := fs.Int64("uid", 0, "user id")
	redirect := fs.String("redirect-uri", "", "redirect URI")
	scopes := fs.String("scopes", "", "space-separated scopes")
	challenge := fs.String("challenge", "", "PKCE challenge")
	method := fs.String("method", "", "PKCE method")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *client <= 0 || *uid <= 0 || *redirect == "" {
		return fmt.Errorf("--client, --uid and --redirect-uri are required")
	}
	set, err := opts.open()
	if err != nil {
		return err
	}
	defer set.repo.Close()
	ctx := context.Background()
	if _, found, err := set.repo.ByUID(ctx, *uid); err != nil {
		return err
	} else if !found {
		return fmt.Errorf("uid %d not found", *uid)
	}
	code, id, expires, err := set.svc.IssueCode(ctx, *client, *uid, *redirect,
		passport.ParseScopes(*scopes), *challenge, *method)
	if err != nil {
		return reportOAuth(err)
	}
	return printJSON(map[string]any{
		"code":         code,
		"auth_code_id": id,
		"expires_at":   expires.Unix(),
		"scopes":       passport.ParseScopes(*scopes),
	})
}

func passportExchange(args []string) error {
	var opts passportOptions
	fs := flag.NewFlagSet("passport exchange", flag.ContinueOnError)
	opts.bind(fs)
	code := fs.String("code", "", "authorization code")
	client := fs.Int64("client", 0, "client id")
	secret := fs.String("secret", "", "client secret")
	redirect := fs.String("redirect-uri", "", "redirect URI")
	verifier := fs.String("verifier", "", "PKCE verifier")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *code == "" || *client <= 0 {
		return fmt.Errorf("--code and --client are required")
	}
	set, err := opts.open()
	if err != nil {
		return err
	}
	defer set.repo.Close()
	response, err := set.svc.ExchangeCode(context.Background(), *code,
		strconv.FormatInt(*client, 10), *secret, *redirect, *verifier)
	if err != nil {
		return reportOAuth(err)
	}
	return printJSON(response)
}

func passportRefresh(args []string) error {
	var opts passportOptions
	fs := flag.NewFlagSet("passport refresh", flag.ContinueOnError)
	opts.bind(fs)
	token := fs.String("refresh-token", "", "refresh token")
	client := fs.Int64("client", 0, "client id")
	secret := fs.String("secret", "", "client secret")
	scopes := fs.String("scopes", "", "space-separated scopes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" || *client <= 0 {
		return fmt.Errorf("--refresh-token and --client are required")
	}
	set, err := opts.open()
	if err != nil {
		return err
	}
	defer set.repo.Close()
	response, err := set.svc.Refresh(context.Background(), *token,
		strconv.FormatInt(*client, 10), *secret, *scopes)
	if err != nil {
		return reportOAuth(err)
	}
	return printJSON(response)
}

func passportIssue(args []string) error {
	var opts passportOptions
	fs := flag.NewFlagSet("passport issue", flag.ContinueOnError)
	opts.bind(fs)
	client := fs.Int64("client", 0, "client id")
	secret := fs.String("secret", "", "client secret")
	username := fs.String("username", "", "email")
	password := fs.String("password", "", "password")
	scopes := fs.String("scopes", "", "space-separated scopes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *client <= 0 || *username == "" || *password == "" {
		return fmt.Errorf("--client, --username and --password are required")
	}
	set, err := opts.open()
	if err != nil {
		return err
	}
	defer set.repo.Close()
	response, err := set.svc.Password(context.Background(),
		strconv.FormatInt(*client, 10), *secret, *username, *password, *scopes)
	if err != nil {
		return reportOAuth(err)
	}
	return printJSON(response)
}

func passportValidate(args []string) error {
	var opts passportOptions
	fs := flag.NewFlagSet("passport validate", flag.ContinueOnError)
	opts.bind(fs)
	token := fs.String("access-token", "", "access token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" {
		return fmt.Errorf("--access-token is required")
	}
	set, err := opts.open()
	if err != nil {
		return err
	}
	defer set.repo.Close()
	identity, err := set.svc.ValidateAccess(context.Background(), *token)
	if err != nil {
		if errors.Is(err, passport.ErrInvalidToken) {
			return printJSON(map[string]any{"valid": false, "error": "invalid_token"})
		}
		return err
	}
	return printJSON(map[string]any{
		"valid":     true,
		"uid":       identity.UID,
		"client_id": identity.ClientID,
		"scopes":    identity.Scopes,
		"token_id":  identity.TokenID,
	})
}

func passportRevoke(args []string) error {
	var opts passportOptions
	fs := flag.NewFlagSet("passport revoke", flag.ContinueOnError)
	opts.bind(fs)
	access := fs.String("access-token", "", "access token")
	refresh := fs.String("refresh-token", "", "refresh token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *access == "" && *refresh == "" {
		return fmt.Errorf("--access-token or --refresh-token is required")
	}
	set, err := opts.open()
	if err != nil {
		return err
	}
	defer set.repo.Close()
	ctx := context.Background()
	if *access != "" {
		id, err := set.svc.AccessID(*access)
		if err != nil {
			return printJSON(map[string]any{"revoked": false, "error": "invalid_token"})
		}
		if err := set.svc.RevokeAccess(ctx, id); err != nil {
			return err
		}
		return printJSON(map[string]any{"revoked": true, "id": id})
	}
	id, err := set.svc.RefreshID(*refresh)
	if err != nil {
		return printJSON(map[string]any{"revoked": false, "error": "invalid_token"})
	}
	if err := set.svc.RevokeRefresh(ctx, id); err != nil {
		return err
	}
	return printJSON(map[string]any{"revoked": true, "id": id})
}

func reportOAuth(err error) error {
	var oauthErr *passport.Error
	if errors.As(err, &oauthErr) {
		return printJSON(map[string]any{
			"error":             oauthErr.Code,
			"error_description": oauthErr.Description,
			"status":            oauthErr.Status,
		})
	}
	return err
}
