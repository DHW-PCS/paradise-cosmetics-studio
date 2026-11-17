// Package testsupport builds synthetic, disposable M2 databases.
package testsupport

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"paradise-cosmetics-studio/internal/admission"
	"paradise-cosmetics-studio/internal/apilimits"
	"paradise-cosmetics-studio/internal/database"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/invitation"
	"paradise-cosmetics-studio/internal/legacy/password"
	"paradise-cosmetics-studio/internal/modules"
	"paradise-cosmetics-studio/internal/outbox"
	"paradise-cosmetics-studio/internal/yggdrasil"
)

func Database(t *testing.T, prefix string) (*database.Store, *identity.Service) {
	t.Helper()
	dsn := os.Getenv("M2_TEST_DSN")
	if dsn == "" {
		t.Skip("M2_TEST_DSN is not set")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal("invalid synthetic database DSN")
	}
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		t.Fatal("test DSN requires loopback TCP")
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		t.Fatal("test DSN requires loopback TCP")
	}
	cfg.DBName = ""
	cfg.ParseTime = true
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	name := "pcs_m2_" + fmt.Sprintf("%x", identity.Digest(identity.Token())[:8])
	if _, err = admin.Exec("CREATE DATABASE `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg.DBName = name
	store, err := database.Open(t.Context(), cfg.FormatDSN(), prefix, 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.DB.Close(); admin.Exec("DROP DATABASE `" + name + "`"); admin.Close() })
	statements := []string{
		"CREATE TABLE " + store.Table("users") + ` (uid INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,email VARCHAR(100) NOT NULL,nickname VARCHAR(50) NOT NULL,avatar INT NOT NULL DEFAULT 0,ip VARCHAR(45) NOT NULL DEFAULT '127.0.0.1',password VARCHAR(255) NOT NULL,remember_token VARCHAR(100) NULL,permission INT NOT NULL,verified BOOLEAN NOT NULL,score INT NOT NULL,locale VARCHAR(255) NULL,is_dark_mode BOOLEAN NOT NULL DEFAULT 0,last_sign_at DATETIME NOT NULL DEFAULT '2020-01-01 00:00:00',register_at DATETIME NOT NULL DEFAULT '2020-01-01 00:00:00') ENGINE=InnoDB`,
		"CREATE TABLE " + store.Table("players") + ` (pid INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,uid INT NOT NULL,name VARCHAR(50) NOT NULL,tid_skin INT NOT NULL DEFAULT -1,tid_cape INT NOT NULL DEFAULT -1,last_modified DATETIME NOT NULL DEFAULT '2020-01-01 00:00:00') ENGINE=InnoDB`,

		"CREATE TABLE " + store.Table("options") + ` (id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,option_name VARCHAR(50) NOT NULL,option_value LONGTEXT NOT NULL) ENGINE=InnoDB`,
		"CREATE TABLE " + store.Table("language_lines") + " (id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,`group` VARCHAR(255) NOT NULL,`key` VARCHAR(255) NOT NULL,text TEXT NOT NULL) ENGINE=InnoDB",
		"CREATE TABLE " + store.Table("scopes") + " (id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,name VARCHAR(255) NOT NULL UNIQUE,description VARCHAR(255) NOT NULL) ENGINE=InnoDB",
		"CREATE TABLE " + store.Table("notifications") + " (id CHAR(36) PRIMARY KEY,notifiable_type VARCHAR(255) NOT NULL,notifiable_id BIGINT NOT NULL,data TEXT NOT NULL,read_at TIMESTAMP NULL,created_at TIMESTAMP NULL) ENGINE=InnoDB",
		"CREATE TABLE " + store.Table("oauth_clients") + ` (id INT UNSIGNED PRIMARY KEY,user_id INT NULL,name VARCHAR(255) NOT NULL,secret VARCHAR(255) NOT NULL,provider VARCHAR(255) NULL,redirect TEXT NOT NULL,personal_access_client BOOLEAN NOT NULL DEFAULT 0,password_client BOOLEAN NOT NULL DEFAULT 0,revoked BOOLEAN NOT NULL DEFAULT 0) ENGINE=InnoDB`,
		"CREATE TABLE " + store.Table("uuid") + ` (id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,name VARCHAR(255) NOT NULL,uuid VARCHAR(255) NOT NULL) ENGINE=InnoDB`,
		"CREATE TABLE " + store.Table("textures") + ` (tid INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,name VARCHAR(50) NOT NULL,type VARCHAR(10) NOT NULL,hash VARCHAR(64) NOT NULL,size INT NOT NULL,uploader INT NOT NULL,public TINYINT NOT NULL,likes INT NOT NULL DEFAULT 0,upload_at DATETIME NOT NULL DEFAULT '2020-01-01 00:00:00') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		"CREATE TABLE " + store.Table("user_closet") + ` (user_uid INT NOT NULL,texture_tid INT NOT NULL,item_name TEXT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		"CREATE TABLE " + store.Table("reports") + ` (id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,tid INT NOT NULL,uploader INT NOT NULL,reporter INT NOT NULL,reason LONGTEXT NOT NULL,status INT NOT NULL,report_at DATETIME NOT NULL) ENGINE=InnoDB`,
	}
	for _, statement := range statements {
		if _, err = store.DB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err = store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = database.MigrateAccounts(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err = outbox.Migrate(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err = invitation.Migrate(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err = apilimits.New(store).Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = yggdrasil.Migrate(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err = database.MigratePlayers(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err = database.MigrateTextures(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if err = database.MigrateCloset(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	hasher, _ := password.New("BCRYPT", "")
	hash, err := hasher.Hash("original-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.DB.Exec("INSERT INTO "+store.Table("users")+" (uid,email,nickname,password,permission,verified,score) VALUES (1,'user@example.invalid','User',?,0,1,71),(2,'admin@example.invalid','Admin',?,2,1,-10)", hash, hash); err != nil {
		t.Fatal(err)
	}
	if _, err = store.DB.Exec("INSERT INTO " + store.Table("go_auth_versions") + " VALUES (1,1),(2,1)"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.DB.Exec("INSERT INTO " + store.Table("players") + " (uid,name) VALUES (1,'PlayerOne')"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.DB.Exec("INSERT INTO " + store.Table("oauth_clients") + " (id,user_id,name,secret,redirect,password_client) VALUES (1,1,'synthetic','client-secret','https://client.example.invalid/callback',0),(2,1,'other','other-secret','https://other.example.invalid/callback',0),(3,NULL,'password','password-secret','https://client.example.invalid/callback',1)"); err != nil {
		t.Fatal(err)
	}
	// Module state rows are the takeover result of the declared synthetic
	// options: nothing enabled and no module registered. Tests that examine
	// other states update these rows explicitly.
	if _, err = store.DB.Exec("INSERT INTO " + store.Table("options") + " (option_name,option_value) VALUES ('plugins_enabled',''),('go_module_installations','[]')"); err != nil {
		t.Fatal(err)
	}
	gate, _ := admission.New(admission.Config{Concurrency: 2, Queue: 2, Wait: time.Second})
	return store, &identity.Service{Store: store, LoginStore: store, Passwords: hasher, Admission: gate, SessionLifetime: 2 * time.Hour, RememberLifetime: 400 * 24 * time.Hour, Now: time.Now}
}

// Modules builds the module manager over one synthetic database, wired the
// same way as the production composition root: the invitation codes consumer
// and its enable precondition are in place.
func Modules(store *database.Store, id *identity.Service) *modules.Manager {
	manager := modules.New(store, id)
	service := invitation.New(store, id.Now)
	if err := manager.RegisterConsumer("invitation-codes", service.ReserveTx); err != nil {
		panic("synthetic consumer registration failed: " + err.Error())
	}
	if err := manager.RegisterCheck("invitation-codes", service.CheckReady); err != nil {
		panic("synthetic check registration failed: " + err.Error())
	}
	yggService := yggdrasil.New(store, id, nil, []byte("synthetic-yggdrasil-hs256-key-32b"), false, id.Now)
	if err := manager.RegisterCheck("yggdrasil-api", yggService.CheckReady); err != nil {
		panic("synthetic yggdrasil check registration failed: " + err.Error())
	}
	return manager
}
