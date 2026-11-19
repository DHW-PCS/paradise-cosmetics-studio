// Command legacy-fixture prepares a private copy of the public legacy migration
// fixture. It does not start Docker or connect to a database.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"paradise-cosmetics-studio/internal/legacy/password"
)

//go:embed fixture
var assets embed.FS

func main() {
	dir, err := os.MkdirTemp("", "pcs-legacy-fixture-")
	if err == nil {
		err = prepare(dir)
		if err == nil {
			fmt.Println(dir)
			return
		}
		if cleanupErr := os.RemoveAll(dir); cleanupErr != nil {
			fmt.Fprintln(os.Stderr, cleanupErr)
		}
	}
	fmt.Fprintln(os.Stderr, "prepare legacy fixture:", err)
	os.Exit(1)
}

func prepare(dir string) error {
	for _, name := range []string{"compose.yaml", "modules.json"} {
		data, err := assets.ReadFile("fixture/" + name)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			return err
		}
	}
	textures, err := fs.Sub(assets, "fixture/storage/textures")
	if err != nil {
		return err
	}
	if err := os.CopyFS(filepath.Join(dir, "storage", "textures"), textures); err != nil {
		return err
	}

	passportKey, err := signingKey()
	if err != nil {
		return err
	}
	yggdrasilKey, err := signingKey()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "storage", "oauth-private.key"), passportKey, 0600); err != nil {
		return err
	}

	// Secret material lives only in the generated workspace.
	loginPassword, salt, databasePassword := rand.Text(), rand.Text(), rand.Text()
	codeSecret, personalSecret := rand.Text(), rand.Text()
	usedInvite, unusedInvite := rand.Text(), rand.Text()
	var sql bytes.Buffer
	for _, entry := range []struct {
		variable string
		method   password.Method
	}{
		{"bcrypt_hash", password.BCRYPT},
		{"salted2sha256_hash", password.SALTED2SHA256},
		{"md5_hash", password.MD5},
		{"sha256_hash", password.SHA256},
	} {
		hasher, err := password.New(string(entry.method), salt)
		if err != nil {
			return err
		}
		hash, err := hasher.Hash(loginPassword)
		if err != nil {
			return err
		}
		fmt.Fprintf(&sql, "SET @pcs_%s = X'%x';\n", entry.variable, hash)
	}
	fmt.Fprintf(&sql, "SET @pcs_oauth_code_secret = X'%x', @pcs_oauth_personal_secret = X'%x';\n", codeSecret, personalSecret)
	fmt.Fprintf(&sql, "SET @pcs_used_invite = X'%x', @pcs_unused_invite = X'%x';\n", usedInvite, unusedInvite)
	fmt.Fprintf(&sql, "SET @pcs_ygg_private_key = X'%x';\n", yggdrasilKey)
	snapshot, err := assets.ReadFile("fixture/legacy.sql")
	if err != nil {
		return err
	}
	sql.Write(snapshot)

	files := []struct{ name, contents string }{
		{"legacy.sql", sql.String()},
		{"db.env", fmt.Sprintf("MARIADB_DATABASE=legacy_fixture\nMARIADB_USER=fixture\nMARIADB_PASSWORD=%s\nMARIADB_ROOT_PASSWORD=%s\n", databasePassword, rand.Text())},
		{"pcs.env", fmt.Sprintf(`APP_URL=http://127.0.0.1:18080
HTTP_ADDR=127.0.0.1:18080
APP_KEY=base64:%s
APP_LOCALE=en
APP_FALLBACK_LOCALE=en
APP_TIMEZONE=Asia/Shanghai
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_DATABASE=legacy_fixture
DB_USERNAME=fixture
DB_PASSWORD=%s
DB_PREFIX=
PWD_METHOD=BCRYPT
SALT=%s
TEXTURES_DIR=storage/textures
OAUTH_PRIVATE_KEY=storage/oauth-private.key
MODULES_MANIFEST_FILE=modules.json
MAIL_MAILER=
`, base64.StdEncoding.EncodeToString(randBytes(32)), databasePassword, salt)},
		{"credentials.txt", fmt.Sprintf("Account password: %s\nUnused invitation code: %s\nOAuth authorization code client 1 secret: %s\n", loginPassword, unusedInvite, codeSecret)},
	}
	for _, file := range files {
		if err := os.WriteFile(filepath.Join(dir, file.name), []byte(file.contents), 0600); err != nil {
			return err
		}
	}
	return nil
}

func randBytes(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

func signingKey() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), nil
}
