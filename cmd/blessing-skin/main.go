// Command blessing-skin runs the HTTP service, worker and offline maintenance.
package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"blessing-skin-go/internal/account"
	"blessing-skin-go/internal/admission"
	"blessing-skin-go/internal/apilimits"
	"blessing-skin-go/internal/config"
	"blessing-skin-go/internal/database"
	"blessing-skin-go/internal/httpapp"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/invitation"
	"blessing-skin-go/internal/legacy/password"
	"blessing-skin-go/internal/maintenance"
	"blessing-skin-go/internal/modules"
	"blessing-skin-go/internal/oauthserver"
	"blessing-skin-go/internal/outbox"
	"blessing-skin-go/internal/processlock"
	"blessing-skin-go/internal/site"
	"blessing-skin-go/internal/textures"
	"blessing-skin-go/internal/yggdrasil"
	"blessing-skin-go/web"
)

// buildVersion is the Go build version reported to protocol clients
// (metadata implementationVersion) and the version command.
var buildVersion = "m2-dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("command failed", "reason", err.Error())
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: blessing-skin <serve|worker|migrate|auth-reset|outbox-retry|version> [-env declared.env]")
	}
	command := args[0]
	if command == "version" {
		fmt.Printf("blessing-skin-go %s (%s)\n", buildVersion, runtime.Version())
		return nil
	}
	if command != "serve" && command != "worker" && command != "migrate" && command != "auth-reset" && command != "outbox-retry" {
		return errors.New("unknown command")
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	envFile := flags.String("env", "", "explicit dotenv file (process environment overrides)")
	var taskID *int64
	if command == "outbox-retry" {
		taskID = flags.Int64("id", 0, "blocked outbox task ID")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if taskID != nil && *taskID <= 0 {
		return errors.New("outbox-retry requires a positive task ID")
	}
	c, err := config.FromEnvironment(*envFile)
	if err != nil {
		return err
	}
	offline := command == "migrate" || command == "auth-reset"
	lock, err := processlock.Acquire(c.LockFile, offline)
	if err != nil {
		return err
	}
	defer lock.Close()
	if command == "serve" {
		httpLock, err := processlock.Acquire(c.LockFile+".http", true)
		if err != nil {
			return errors.New("only one active HTTP instance is supported")
		}
		defer httpLock.Close()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	budget := c.BusinessConnections
	if command == "worker" {
		budget = c.WorkerConnections
	}
	store, err := database.Open(ctx, c.DSN(), c.Prefix, budget)
	if err != nil {
		return errors.New("database unavailable; check declared connection configuration")
	}
	defer store.DB.Close()
	if command == "migrate" {
		if err = store.Migrate(ctx); err != nil {
			return errors.New("migration failed; existing business schema and Go ledger require inspection")
		}
		if err = oauthserver.Migrate(ctx, store); err != nil {
			return errors.New("OAuth migration failed")
		}
		if err = oauthserver.MigrateConsents(ctx, store); err != nil {
			return errors.New("OAuth consent migration failed")
		}
		if err = oauthserver.MigrateAPIDigest(ctx, store); err != nil {
			return errors.New("API digest migration failed")
		}
		if err = outbox.Migrate(ctx, store); err != nil {
			return errors.New("outbox migration failed")
		}
		if err = database.MigrateAccounts(ctx, store); err != nil {
			return errors.New("account migration failed")
		}
		if err = database.MigratePlayers(ctx, store); err != nil {
			return errors.New("player migration failed")
		}
		if err = database.MigrateTextures(ctx, store); err != nil {
			return errors.New("texture migration failed")
		}
		if err = database.MigrateCloset(ctx, store); err != nil {
			return errors.New("closet migration failed")
		}
		if err = invitation.Migrate(ctx, store); err != nil {
			return errors.New("invitation migration failed")
		}
		if err = apilimits.New(store).Migrate(ctx); err != nil {
			return errors.New("API limiter migration failed")
		}
		if err = yggdrasil.Migrate(ctx, store); err != nil {
			return errors.New("Yggdrasil migration failed")
		}
		if err = initializeModules(ctx, store, c); err != nil {
			return err
		}
		slog.Info("Go additive migrations complete")
		return nil
	}
	if err = maintenance.CheckSchema(ctx, store); err != nil {
		return err
	}
	if command == "outbox-retry" {
		queue := &outbox.Store{Database: store, Now: time.Now}
		if err = queue.RetryBlocked(ctx, *taskID); err != nil {
			return err
		}
		slog.Info("blocked outbox task requeued", "task_id", *taskID)
		return nil
	}
	if command == "auth-reset" {
		if err = maintenance.ResetAuthentication(ctx, store); err != nil {
			return errors.New("authentication reset failed; keep service stopped")
		}
		slog.Info("Go transient authentication cleared; accounts and business tasks retained")
		return nil
	}
	if command == "worker" {
		return worker(ctx, c, store)
	}
	loginStore, err := database.Open(ctx, c.DSN(), c.Prefix, c.LoginConnections)
	if err != nil {
		return errors.New("login database pool unavailable")
	}
	defer loginStore.DB.Close()
	hasher, err := password.New(c.PasswordMethod, c.PasswordSalt)
	if err != nil {
		return errors.New("unsupported configured password method")
	}
	gate, err := admission.New(c.Login)
	if err != nil {
		return err
	}
	id := &identity.Service{Store: store, LoginStore: loginStore, Passwords: hasher, Admission: gate, SessionLifetime: c.SessionLifetime, RememberLifetime: c.RememberLifetime, Now: time.Now}
	key, err := readKey(c.PrivateKeyFile)
	if err != nil {
		return err
	}
	scopes, err := oauthserver.LoadScopes(ctx, store)
	if err != nil {
		return errors.New("cannot load installed OAuth scopes")
	}
	oauth, err := oauthserver.New(oauthserver.Config{Store: store, Identity: id, PrivateKey: key, Secret: c.AppKey, Issuer: c.BaseURL, Scopes: scopes, AccessLifetime: c.AccessLifetime, RefreshLifetime: c.RefreshLifetime, CodeLifetime: c.CodeLifetime})
	if err != nil {
		return err
	}
	overrides, err := site.LoadOptionSnapshot(c.OptionsFile)
	if err != nil {
		return err
	}
	moduleManager := modules.New(store, id)
	invitationService := invitation.New(store, id.Now)
	if err = moduleManager.RegisterConsumer("invitation-codes", invitationService.ReserveTx); err != nil {
		return err
	}
	if err = moduleManager.RegisterCheck("invitation-codes", invitationService.CheckReady); err != nil {
		return err
	}
	yggService := yggdrasil.New(store, id, overrides, c.AppKey, c.YggVerboseLog, time.Now)
	if err = moduleManager.RegisterCheck("yggdrasil-api", yggService.CheckReady); err != nil {
		return err
	}
	view := &site.Service{Store: store, Identity: id, OptionSnapshot: overrides, Location: c.Location, Modules: moduleManager}
	handler, err := httpapp.New(c, id, view, oauth, yggService, buildVersion)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: c.Address, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	finished := make(chan error, 1)
	go func() { finished <- server.ListenAndServe() }()
	slog.Info("HTTP service started", "address", c.Address)
	select {
	case err = <-finished:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("HTTP listener failed")
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err = server.Shutdown(shutdown); err != nil {
			return errors.New("HTTP shutdown did not drain before deadline")
		}
		return nil
	}
}

// initializeModules runs the module-state takeover inside the explicit offline
// migrate command: existing rows stay, missing rows are seeded from the
// declared original facts, and an undecidable install ledger fails the run.
func initializeModules(ctx context.Context, store *database.Store, c config.Config) error {
	snapshot, err := site.LoadOptionSnapshot(c.OptionsFile)
	if err != nil {
		return err
	}
	manifest, err := modules.LoadManifest(c.ModulesManifestFile)
	if err != nil {
		return err
	}
	if err = modules.Initialize(ctx, store, snapshot, manifest); err != nil {
		slog.Error("module state initialization failed", "reason", err.Error())
		return errors.New("module state initialization failed; inspect options rows and declared manifest")
	}
	return nil
}

func readKey(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read configured OAuth RSA private key")
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("OAuth key must be PEM-encoded RSA")
	}
	if block.Type == "RSA PRIVATE KEY" {
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid OAuth RSA private key")
		}
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid OAuth private key")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("OAuth private key must be RSA")
	}
	return key, nil
}
func worker(ctx context.Context, c config.Config, store *database.Store) error {
	queue := &outbox.Store{Database: store, Now: time.Now}
	handlers := map[string]outbox.Handler{}
	if c.Mail.Mailer != "" {
		assets, err := web.Load()
		if err != nil {
			return err
		}
		overrides, err := site.LoadOptionSnapshot(c.OptionsFile)
		if err != nil {
			return err
		}
		view := &site.Service{Store: store, OptionSnapshot: overrides, Location: c.Location}
		transport, err := account.DefaultTransport(c.Mail)
		if err != nil {
			return err
		}
		mail, err := account.NewMail(c.AppKey, c.BaseURL, c.FallbackLocale, view, assets.Messages, transport, c.Mail.RetryDelay)
		if err != nil {
			return err
		}
		id := &identity.Service{Store: store, Now: time.Now}
		accounts := account.New(store, id, view, mail)
		handlers[account.MailTopic] = mail.Handler(accounts)
	}
	overrides, err := site.LoadOptionSnapshot(c.OptionsFile)
	if err != nil {
		return err
	}
	view := &site.Service{Store: store, OptionSnapshot: overrides, Location: c.Location}
	texturesDir := c.TexturesDir
	if texturesDir == "" {
		texturesDir = "storage/textures"
	}
	texturesService := textures.New(store, &identity.Service{Store: store, Now: time.Now}, view, texturesDir, time.Now)
	handlers[textures.CollectTopic] = texturesService.Handler()
	cleanup := func() error { _, err := maintenance.Cleanup(ctx, store, time.Now(), c.CleanupBatch); return err }
	if err := cleanup(); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return errors.New("authentication cleanup failed")
	}
	ticker := time.NewTicker(c.CleanupInterval)
	defer ticker.Stop()
	poll := time.NewTimer(0)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := cleanup(); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return errors.New("authentication cleanup failed")
			}
		case <-poll.C:
			worked, err := queue.DeliverOne(ctx, handlers, time.Minute)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return errors.New("outbox delivery failed; inspect task state and domain handler")
			}
			wait := c.WorkerPollInterval
			if worked {
				wait = 0
			}
			poll.Reset(wait)
		}
	}
}
