package main

// R10 regression tests: the public remember mint command must parse the
// documented flag form, where --vectors is the first argument. The tests build
// and run the real command; vectors and credentials are synthetic and isolated.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/go-sql-driver/mysql"

	"paradise-cosmetics-studio/internal/legacy/testdb"
)

const (
	cliCipher      = "AES-256-CBC"
	cliRecaller    = "bs_remember"
	cliRememberMin = 43200
)

var (
	buildOnce sync.Once
	cliDir    string
	cliPath   string
	buildErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if cliDir != "" {
		_ = os.RemoveAll(cliDir)
	}
	os.Exit(code)
}

// cliBinary builds the real command once per test process.
func cliBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "m1poc-cli-")
		if err != nil {
			buildErr = err
			return
		}
		cliDir = dir
		cliPath = filepath.Join(dir, "m1poc")
		goBin, err := exec.LookPath("go")
		if err != nil {
			buildErr = err
			return
		}
		build := exec.Command(goBin, "build", "-o", cliPath, ".")
		if out, err := build.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("go build: %w: %s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatalf("build m1poc: %v", buildErr)
	}
	return cliPath
}

// syntheticVectors writes the minimal vector bundle the CLI needs. It uses a
// generated isolated key and no real token, session or production material.
func syntheticVectors(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte('a' + i%26)
	}
	bundle := map[string]any{
		"schema":       "m1-cross-vectors/1",
		"generated_at": "2026-10-24T00:00:00+00:00",
		"config": map[string]any{
			"app_key": "base64:" + base64.StdEncoding.EncodeToString(key),
			"cipher":  cliCipher,
			"guard": map[string]any{
				"name":             "web",
				"recaller_name":    cliRecaller,
				"remember_minutes": cliRememberMin,
			},
		},
	}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vectors.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type cliResult struct {
	stdout, stderr string
	code           int
}

func runCLI(t *testing.T, args ...string) cliResult {
	t.Helper()
	cmd := exec.Command(cliBinary(t), args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result := cliResult{stdout: stdout.String(), stderr: stderr.String()}
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("run m1poc %v: %v", args, err)
		}
		result.code = exit.ExitCode()
	}
	return result
}

// TestRememberMintCLIParsesDocumentedFlags covers R10 without a database: once
// the flags are parsed the command must reach the DSN/vector errors instead of
// the missing-flags error produced when the first --vectors argument is eaten.
func TestRememberMintCLIParsesDocumentedFlags(t *testing.T) {
	vectorsPath := syntheticVectors(t)
	badDSN := "not-a-dsn"
	t.Run("vectors-first", func(t *testing.T) {
		got := runCLI(t, "remember", "mint", "--vectors", vectorsPath, "--uid", "1", "--dsn", badDSN)
		if got.code != 1 {
			t.Fatalf("exit code = %d, want 1", got.code)
		}
		if strings.Contains(got.stderr, "required") {
			t.Fatalf("flags were not parsed: %s", got.stderr)
		}
		if !strings.Contains(got.stderr, "invalid DSN") {
			t.Fatalf("did not reach the DSN step: %s", got.stderr)
		}
	})
	t.Run("flag-order", func(t *testing.T) {
		got := runCLI(t, "remember", "mint", "--uid", "1", "--vectors", vectorsPath, "--dsn", badDSN)
		if got.code != 1 || strings.Contains(got.stderr, "required") || !strings.Contains(got.stderr, "invalid DSN") {
			t.Fatalf("flag order changed parsing: code=%d stderr=%s", got.code, got.stderr)
		}
	})
	t.Run("vectors-file-reached", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent.json")
		got := runCLI(t, "remember", "mint", "--vectors", missing, "--uid", "1", "--dsn", badDSN)
		if got.code != 1 || !strings.Contains(strings.ToLower(got.stderr), "no such file") {
			t.Fatalf("--vectors value not used: code=%d stderr=%s", got.code, got.stderr)
		}
	})
	t.Run("missing-required", func(t *testing.T) {
		got := runCLI(t, "remember", "mint", "--vectors", vectorsPath, "--uid", "1")
		if got.code != 1 || !strings.Contains(got.stderr, "--vectors, --uid and --dsn are required") {
			t.Fatalf("missing flags not reported: code=%d stderr=%s", got.code, got.stderr)
		}
	})
	t.Run("no-arguments", func(t *testing.T) {
		got := runCLI(t, "remember", "mint")
		if got.code != 1 || !strings.Contains(got.stderr, "--vectors, --uid and --dsn are required") {
			t.Fatalf("empty arguments: code=%d stderr=%s", got.code, got.stderr)
		}
	})
	t.Run("unknown-flag", func(t *testing.T) {
		got := runCLI(t, "remember", "mint", "--bogus", "x")
		if got.code != 1 || !strings.Contains(got.stderr, "flag provided but not defined") {
			t.Fatalf("unknown flag: code=%d stderr=%s", got.code, got.stderr)
		}
	})
	t.Run("help", func(t *testing.T) {
		got := runCLI(t, "remember", "mint", "--help")
		// The command reports flag.ErrHelp as a normal error and keeps exit 1.
		if got.code != 1 {
			t.Fatalf("help exit code = %d, want 1", got.code)
		}
		if !strings.Contains(got.stderr, "Usage of remember mint") || !strings.Contains(got.stderr, "-vectors") {
			t.Fatalf("help output missing usage: %s", got.stderr)
		}
		if got.stdout != "" {
			t.Fatalf("help wrote to stdout: %q", got.stdout)
		}
	})
}

// TestRememberMintCLISuccess runs the documented command end to end against the
// isolated test database and checks the Go -> legacy rotation.
func TestRememberMintCLISuccess(t *testing.T) {
	base := os.Getenv("M1_TEST_DSN")
	if base == "" {
		t.Skip("M1_TEST_DSN is not set; skipping the database-backed CLI mint")
	}
	db := testdb.Open(t)
	var name string
	if err := db.QueryRow("SELECT DATABASE()").Scan(&name); err != nil {
		t.Fatal(err)
	}
	cfg, err := mysql.ParseDSN(base)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DBName = name
	dsn := cfg.FormatDSN()
	result, err := db.Exec("INSERT INTO users(email,nickname,password,permission,verified) VALUES(?,?,?,0,1)", "cli-mint@example.invalid", "CLIMint", "$2y$04$cli-mint-hash")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	vectorsPath := syntheticVectors(t)
	outPath := filepath.Join(t.TempDir(), "mint.json")
	got := runCLI(t, "remember", "mint", "--vectors", vectorsPath, "--uid", fmt.Sprint(uid), "--dsn", dsn, "--out", outPath)
	if got.code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", got.code, got.stderr)
	}
	var minted map[string]any
	if err := json.Unmarshal([]byte(got.stdout), &minted); err != nil {
		t.Fatalf("stdout is not JSON: %v: %q", err, got.stdout)
	}
	var written map[string]any
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &written); err != nil {
		t.Fatalf("--out file is not JSON: %v", err)
	}
	if written["uid"] != float64(uid) || written["cookie_name"] != cliRecaller || written["expires_in_minutes"] != float64(cliRememberMin) {
		t.Fatalf("unexpected mint result: %v", written)
	}
	if written["cookie"] == "" || written["cookie"] == nil {
		t.Fatal("no recaller cookie minted")
	}
	recaller, ok := written["recaller_value"].(string)
	if !ok {
		t.Fatalf("recaller_value missing: %v", written)
	}
	parts := strings.Split(recaller, "|")
	if len(parts) != 3 || parts[0] != fmt.Sprint(uid) || parts[1] == "" {
		t.Fatalf("unexpected recaller value: %q", recaller)
	}
	var stored string
	if err := db.QueryRow("SELECT remember_token FROM users WHERE uid=?", uid).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != parts[1] {
		t.Fatalf("legacy remember_token was not rotated to the minted token")
	}
}
