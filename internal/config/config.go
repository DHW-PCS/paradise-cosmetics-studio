// Package config loads declared environment sources without running PHP code.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"paradise-cosmetics-studio/internal/admission"
)

type Config struct {
	Mail                                                                                              MailConfig
	YggdrasilPublicKeysEnabled                                                                        bool
	YggVerboseLog                                                                                     bool
	Address, BaseURL, Prefix, LockFile, PrivateKeyFile, OptionsFile                                   string
	ModulesManifestFile                                                                               string
	SessionDomain, PasswordMethod, PasswordSalt                                                       string
	Locale, FallbackLocale                                                                            string
	SecureCookie                                                                                      bool
	Location                                                                                          *time.Location
	TexturesDir                                                                                       string
	Login                                                                                             admission.Config
	LoginConnections, BusinessConnections, WorkerConnections                                          int
	CleanupBatch                                                                                      int
	SessionLifetime, RememberLifetime, AccessLifetime, RefreshLifetime, CodeLifetime, CleanupInterval time.Duration
	AppKey                                                                                            []byte
	WorkerPollInterval                                                                                time.Duration
	dsn                                                                                               string
}

type MailConfig struct {
	Mailer, Host, Encryption, Username, Password, FromAddress, FromName string
	Port                                                                int
	SendTimeout, RetryDelay                                             time.Duration
}

func (c Config) DSN() string { return c.dsn }

// Load preserves an explicitly empty value. Process environment overrides only
// the declared dotenv file; it does not execute PHP or mutate process environment.
func Load(file string, lookup func(string) (string, bool)) (Config, error) {
	values := map[string]string{}
	if file != "" {
		var err error
		values, err = godotenv.Read(file)
		if err != nil {
			return Config{}, errors.New("cannot read declared environment file")
		}
	}
	get := func(key, fallback string) string {
		if value, ok := lookup(key); ok {
			return value
		}
		if value, ok := values[key]; ok {
			return value
		}
		return fallback
	}
	var c Config
	driver := get("DB_CONNECTION", "mysql")
	if driver != "mysql" && driver != "mariadb" {
		return c, errors.New("only MySQL/MariaDB is supported")
	}
	c.Address = get("HTTP_ADDR", ":8080")
	c.BaseURL = strings.TrimRight(get("APP_URL", "http://localhost:8080"), "/")
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.RawQuery != "" || u.Fragment != "" {
		return c, errors.New("APP_URL must be an absolute HTTP(S) base URL")
	}
	c.Prefix = get("DB_PREFIX", "")
	c.LockFile = get("APP_LOCK_FILE", "storage/go-instance.lock")
	c.PrivateKeyFile = get("OAUTH_PRIVATE_KEY", "storage/oauth-private.key")
	c.OptionsFile = get("OPTIONS_SNAPSHOT_FILE", "")
	c.ModulesManifestFile = get("MODULES_MANIFEST_FILE", "")
	root := ""
	if file != "" {
		absolute, err := filepath.Abs(file)
		if err != nil {
			return c, errors.New("cannot resolve declared environment file")
		}
		root = filepath.Dir(absolute)
	}
	root = get("APP_ROOT", root)
	if !filepath.IsAbs(root) {
		return c, errors.New("APP_ROOT must be absolute when no declared environment file supplies the deployment root")
	}
	resolve := func(path string) string {
		if path == "" || filepath.IsAbs(path) {
			return path
		}
		return filepath.Join(root, path)
	}
	c.LockFile = resolve(c.LockFile)
	c.PrivateKeyFile = resolve(c.PrivateKeyFile)
	c.OptionsFile = resolve(c.OptionsFile)
	c.ModulesManifestFile = resolve(c.ModulesManifestFile)
	c.SessionDomain = get("SESSION_DOMAIN", "")
	if OptionValue(c.SessionDomain) == nil {
		c.SessionDomain = ""
	}
	if driver := get("FS_DRIVER", "local"); driver != "local" {
		return c, errors.New("only the local textures filesystem driver is supported")
	}
	resolvedTextures := resolve(get("TEXTURES_DIR", "storage/textures"))
	cleanTextures := filepath.Clean(resolvedTextures)
	cleanRoot := filepath.Clean(root)
	if cleanRoot == "." || cleanTextures == cleanRoot || !strings.HasPrefix(cleanTextures, cleanRoot+string(filepath.Separator)) {
		return c, errors.New("TEXTURES_DIR must stay inside APP_ROOT")
	}
	c.TexturesDir = cleanTextures
	c.PasswordMethod = get("PWD_METHOD", "BCRYPT")
	c.PasswordSalt = get("SALT", "")
	c.Locale = get("APP_LOCALE", "zh_CN")
	c.FallbackLocale = get("APP_FALLBACK_LOCALE", "en")
	c.Location, err = time.LoadLocation(get("APP_TIMEZONE", "Asia/Shanghai"))
	if err != nil {
		return c, errors.New("invalid APP_TIMEZONE")
	}
	c.SecureCookie = u.Scheme == "https"
	boolEnv := func(key string) (bool, error) {
		raw := get(key, "")
		if raw == "" {
			return false, nil
		}
		if raw == "0" || raw == "1" {
			return raw == "1", nil
		}
		if v := OptionValue(raw); v != nil {
			if b, ok := v.(bool); ok {
				return b, nil
			}
		}
		return false, fmt.Errorf("invalid %s", key)
	}
	c.YggdrasilPublicKeysEnabled, err = boolEnv("YGGDRASIL_PUBLICKEYS_ENABLED")
	if err != nil {
		return c, err
	}
	c.YggVerboseLog, err = boolEnv("YGG_VERBOSE_LOG")
	if err != nil {
		return c, err
	}
	if raw := get("SESSION_SECURE_COOKIE", ""); raw != "" && OptionValue(raw) != nil {
		v := OptionValue(raw)
		value, ok := v.(bool)
		if raw == "0" || raw == "1" {
			value = raw == "1"
			ok = true
		}
		if !ok {
			return c, errors.New("invalid SESSION_SECURE_COOKIE")
		}
		c.SecureCookie = value
	}
	integer := func(key, fallback string) (int, error) {
		value, err := strconv.Atoi(get(key, fallback))
		if err != nil {
			return 0, fmt.Errorf("invalid %s", key)
		}
		return value, nil
	}
	c.Login.Concurrency, err = integer("LOGIN_CONCURRENCY", "2")
	if err != nil {
		return c, err
	}
	c.Login.Queue, err = integer("LOGIN_QUEUE", "2")
	if err != nil {
		return c, err
	}
	c.LoginConnections, err = integer("DB_LOGIN_CONNECTIONS", "2")
	if err != nil {
		return c, err
	}
	c.BusinessConnections, err = integer("DB_BUSINESS_CONNECTIONS", "4")
	if err != nil {
		return c, err
	}
	c.WorkerConnections, err = integer("DB_WORKER_CONNECTIONS", "1")
	if err != nil {
		return c, err
	}
	c.Mail.Mailer = get("MAIL_MAILER", "smtp")
	c.Mail.Host = get("MAIL_HOST", "smtp.mailgun.org")
	c.Mail.Encryption = get("MAIL_ENCRYPTION", "tls")
	if OptionValue(c.Mail.Encryption) == nil {
		c.Mail.Encryption = ""
	}
	c.Mail.Username = get("MAIL_USERNAME", "")
	c.Mail.Password = get("MAIL_PASSWORD", "")
	c.Mail.FromAddress = get("MAIL_FROM_ADDRESS", "hello@example.com")
	c.Mail.FromName = get("MAIL_FROM_NAME", "Example")
	c.Mail.Port, err = integer("MAIL_PORT", "587")
	if err != nil {
		return c, err
	}
	// The deadline follows go-mail's default; retries retain the existing
	// worker's one-minute failed-lease cadence unless explicitly configured.
	c.Mail.SendTimeout, err = time.ParseDuration(get("MAIL_SEND_TIMEOUT", "15s"))
	if err != nil || c.Mail.SendTimeout <= 0 || c.Mail.SendTimeout >= time.Minute {
		return c, errors.New("MAIL_SEND_TIMEOUT must be positive and less than the one-minute worker lease")
	}
	c.Mail.RetryDelay, err = time.ParseDuration(get("MAIL_RETRY_DELAY", "1m"))
	if err != nil || c.Mail.RetryDelay <= 0 {
		return c, errors.New("MAIL_RETRY_DELAY must be positive")
	}
	c.CleanupBatch, err = integer("AUTH_CLEANUP_BATCH", "500")
	if err != nil || c.CleanupBatch < 1 {
		return c, errors.New("AUTH_CLEANUP_BATCH must be positive")
	}
	minutes, err := integer("SESSION_LIFETIME", "120")
	if err != nil || minutes <= 0 {
		return c, errors.New("SESSION_LIFETIME must be positive minutes")
	}
	c.SessionLifetime = time.Duration(minutes) * time.Minute
	for _, parameter := range []struct {
		key, defaultValue string
		target            *time.Duration
	}{
		{"LOGIN_WAIT", "100ms", &c.Login.Wait}, {"REMEMBER_LIFETIME", "9600h", &c.RememberLifetime}, {"OAUTH_ACCESS_LIFETIME", "8760h", &c.AccessLifetime}, {"OAUTH_REFRESH_LIFETIME", "8760h", &c.RefreshLifetime}, {"OAUTH_CODE_LIFETIME", "10m", &c.CodeLifetime}, {"AUTH_CLEANUP_INTERVAL", "1m", &c.CleanupInterval},
		{"WORKER_POLL_INTERVAL", "3s", &c.WorkerPollInterval},
	} {
		*parameter.target, err = time.ParseDuration(get(parameter.key, parameter.defaultValue))
		if err != nil || *parameter.target <= 0 {
			return c, fmt.Errorf("%s must be a positive duration", parameter.key)
		}
	}
	if _, err = admission.New(c.Login); err != nil {
		return c, err
	}
	if c.LoginConnections < 1 || c.BusinessConnections < 1 || c.WorkerConnections < 1 {
		return c, errors.New("database connection budgets must be positive")
	}
	key := get("APP_KEY", "")
	if strings.HasPrefix(key, "base64:") {
		c.AppKey, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(key, "base64:"))
		if err != nil {
			return c, errors.New("invalid APP_KEY encoding")
		}
	} else {
		c.AppKey = []byte(key)
	}
	if len(c.AppKey) < 32 {
		return c, errors.New("APP_KEY must supply at least 32 bytes")
	}
	db := mysql.NewConfig()
	db.User = get("DB_USERNAME", "root")
	db.Passwd = get("DB_PASSWORD", "")
	db.Net = "tcp"
	db.Addr = net.JoinHostPort(get("DB_HOST", "127.0.0.1"), get("DB_PORT", "3306"))
	db.DBName = get("DB_DATABASE", "")
	db.ParseTime = true
	db.Loc = c.Location
	if db.DBName == "" {
		return c, errors.New("DB_DATABASE is required")
	}
	c.dsn = db.FormatDSN()
	return c, nil
}

func FromEnvironment(file string) (Config, error) { return Load(file, os.LookupEnv) }

// OptionValue follows Option::get: other strings, including numbers and empty
// strings, remain strings until the owning business rule interprets them.
func OptionValue(value string) any {
	switch strings.ToLower(value) {
	case "true", "(true)":
		return true
	case "false", "(false)":
		return false
	case "null", "(null)":
		return nil
	default:
		return value
	}
}
