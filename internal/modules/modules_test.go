package modules_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/database"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/modules"
	"paradise-cosmetics-studio/internal/testsupport"
)

type harness struct {
	store  *database.Store
	id     *identity.Service
	admin  *identity.BrowserSession
	member *identity.BrowserSession
}

func fixture(t *testing.T) harness {
	t.Helper()
	store, id := testsupport.Database(t, "modules-")
	admin, err := id.Login(t.Context(), "admin@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	member, err := id.Login(t.Context(), "user@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	return harness{store: store, id: id, admin: admin, member: member}
}

func (f harness) manager() *modules.Manager { return modules.New(f.store, f.id) }

func (f harness) rows(t *testing.T) (enabled string, installed string) {
	t.Helper()
	if err := f.store.DB.QueryRow("SELECT option_value FROM " + f.store.Table("options") + " WHERE option_name='plugins_enabled'").Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if err := f.store.DB.QueryRow("SELECT option_value FROM " + f.store.Table("options") + " WHERE option_name='go_module_installations'").Scan(&installed); err != nil {
		t.Fatal(err)
	}
	return enabled, installed
}

func (f harness) setState(t *testing.T, enabled, installed string) {
	t.Helper()
	if _, err := f.store.DB.Exec("UPDATE "+f.store.Table("options")+" SET option_value=? WHERE option_name='plugins_enabled'", enabled); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.Exec("UPDATE "+f.store.Table("options")+" SET option_value=? WHERE option_name='go_module_installations'", installed); err != nil {
		t.Fatal(err)
	}
}

func TestEnableAppendsInstallEntryAndKeepsOriginalState(t *testing.T) {
	f := fixture(t)
	m := f.manager()
	if err := m.Enable(t.Context(), f.admin, "invitation-codes"); !errors.Is(err, modules.ErrNotFound) {
		t.Fatal("uninstalled module enabled", err)
	}
	f.setState(t, `[{"name":"legacy-api","version":"1.1.3"}]`, `[{"name":"legacy-api","version":"1.1.3"},{"name":"invitation-codes","version":"3.1.2"}]`)
	if err := m.Enable(t.Context(), f.admin, "invitation-codes"); err != nil {
		t.Fatal(err)
	}
	enabled, installed := f.rows(t)
	if enabled != `[{"name":"legacy-api","version":"1.1.3"},{"name":"invitation-codes","version":"3.1.2"}]` {
		t.Fatalf("install entry lost the original array: %s", enabled)
	}
	if installed != `[{"name":"legacy-api","version":"1.1.3"},{"name":"invitation-codes","version":"3.1.2"}]` {
		t.Fatalf("install facts mutated: %s", installed)
	}
	if err := m.Enable(t.Context(), f.admin, "invitation-codes"); err != nil {
		t.Fatal("repeat enable failed", err)
	}
	if enabled, _ = f.rows(t); enabled != `[{"name":"legacy-api","version":"1.1.3"},{"name":"invitation-codes","version":"3.1.2"}]` {
		t.Fatalf("repeat enable rewrote state: %s", enabled)
	}
}

func TestEnableRunsRegisteredChecksInsideTheStateTransaction(t *testing.T) {
	f := fixture(t)
	m := f.manager()
	if err := m.RegisterCheck("unsupported", func(context.Context, *sql.Tx) ([]string, error) { return nil, nil }); !errors.Is(err, modules.ErrUnknownModule) {
		t.Fatal("unknown check accepted", err)
	}
	f.setState(t, "", `[{"name":"legacy-api","version":"1.1.3"}]`)
	failing := "legacy-api needs production schema"
	if err := m.RegisterCheck("legacy-api", func(context.Context, *sql.Tx) ([]string, error) { return []string{failing}, nil }); err != nil {
		t.Fatal(err)
	}
	if err := m.Enable(t.Context(), f.admin, "legacy-api"); modules.Reasons(err) == nil {
		t.Fatal("failing enable check accepted", err)
	} else if modules.Reasons(err)[0] != failing {
		t.Fatalf("check reasons lost: %v", modules.Reasons(err))
	}
	enabled, installed := f.rows(t)
	if enabled != "" || installed != `[{"name":"legacy-api","version":"1.1.3"}]` {
		t.Fatalf("refused enable touched state rows: %s / %s", enabled, installed)
	}
	// The check runs in the enable transaction: its own writes roll back too,
	// so a faulty probe never leaves half-generated state behind.
	if err := m.RegisterCheck("legacy-api", func(_ context.Context, tx *sql.Tx) ([]string, error) {
		if _, err := tx.ExecContext(context.Background(), "UPDATE "+f.store.Table("options")+" SET option_value='poisoned' WHERE option_name='plugins_enabled'"); err != nil {
			return nil, err
		}
		return []string{"kept synthetic fault"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Enable(t.Context(), f.admin, "legacy-api"); modules.Reasons(err) == nil {
		t.Fatal("check fault swallowed", err)
	}
	enabled, _ = f.rows(t)
	if enabled != "" {
		t.Fatalf("check write leaked past the rollback: %s", enabled)
	}
	if err := m.RegisterCheck("legacy-api", func(context.Context, *sql.Tx) ([]string, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if err := m.Enable(t.Context(), f.admin, "legacy-api"); err != nil {
		t.Fatal("clean enable failed", err)
	}
	if enabled, _ = f.rows(t); !strings.Contains(enabled, `"name":"legacy-api"`) {
		t.Fatalf("clean enable forgot the entry: %s", enabled)
	}
}

func TestDisableAndUninstallPreserveForeignEntries(t *testing.T) {
	f := fixture(t)
	m := f.manager()
	f.setState(t, `["disable-registration",{"name":"legacy-api","version":"1.1.3"},{"name":"yggdrasil-api","version":"5.2.1"}]`, `[{"name":"legacy-api","version":"1.1.3"},{"name":"yggdrasil-api","version":"5.2.1"}]`)
	if err := m.Disable(t.Context(), f.admin, "legacy-api"); err != nil {
		t.Fatal(err)
	}
	enabled, installed := f.rows(t)
	if enabled != `["disable-registration",{"name":"yggdrasil-api","version":"5.2.1"}]` {
		t.Fatalf("disable kept the disabled entry or broke legacy items: %s", enabled)
	}
	if installed != `[{"name":"legacy-api","version":"1.1.3"},{"name":"yggdrasil-api","version":"5.2.1"}]` {
		t.Fatalf("disable touched install registration: %s", installed)
	}
	before := enabled
	if err := m.Disable(t.Context(), f.admin, "legacy-api"); err != nil {
		t.Fatal("idempotent disable failed", err)
	}
	if enabled, _ = f.rows(t); enabled != before {
		t.Fatalf("idempotent disable rewrote the row: %s", enabled)
	}
	if err := m.Uninstall(t.Context(), f.admin, "legacy-api"); err != nil {
		t.Fatal(err)
	}
	enabled, installed = f.rows(t)
	if enabled != `["disable-registration",{"name":"yggdrasil-api","version":"5.2.1"}]` {
		t.Fatalf("uninstall damaged the enable row: %s", enabled)
	}
	if installed != `[{"name":"yggdrasil-api","version":"5.2.1"}]` {
		t.Fatalf("uninstall left the install registration: %s", installed)
	}
	if err := m.Disable(t.Context(), f.admin, "legacy-api"); !errors.Is(err, modules.ErrNotFound) {
		t.Fatal("unregistered module disabled", err)
	}
	if err := m.Uninstall(t.Context(), f.admin, "legacy-api"); !errors.Is(err, modules.ErrNotFound) {
		t.Fatal("unregistered module uninstalled", err)
	}
	if err := m.Disable(t.Context(), f.admin, "unsupported-name"); !errors.Is(err, modules.ErrUnknownModule) {
		t.Fatal("unsupported module accepted", err)
	}
}

func TestModuleStateWritesRequireCurrentAdministrator(t *testing.T) {
	f := fixture(t)
	m := f.manager()
	f.setState(t, "", `[{"name":"legacy-api","version":"1.1.3"}]`)
	if err := m.Enable(t.Context(), f.member, "legacy-api"); !errors.Is(err, modules.ErrForbidden) {
		t.Fatal("member enabled a module", err)
	}
	if err := m.Enable(t.Context(), &identity.BrowserSession{Token: f.admin.Token}, "legacy-api"); !errors.Is(err, identity.ErrSession) {
		t.Fatal("session without bound user accepted", err)
	}
	if enabled, _ := f.rows(t); enabled != "" {
		t.Fatalf("denied write landed: %s", enabled)
	}
	if err := f.store.Transaction(t.Context(), func(tx *sql.Tx) error {
		return f.id.RevokeUID(t.Context(), tx, f.admin.User.UID)
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Enable(t.Context(), f.admin, "legacy-api"); !errors.Is(err, identity.ErrSession) {
		t.Fatal("stale version accepted", err)
	}
}

func TestDuplicateOptionRowsStayHistoricalAndFail(t *testing.T) {
	f := fixture(t)
	if _, err := f.store.DB.Exec("INSERT INTO " + f.store.Table("options") + " (option_name,option_value) VALUES ('plugins_enabled','[]')"); err != nil {
		t.Fatal(err)
	}
	m := f.manager()
	if _, err := m.RequestState(t.Context()); !errors.Is(err, modules.ErrStateAmbiguous) {
		t.Fatal("duplicate rows read as authoritative", err)
	}
	if err := m.Enable(t.Context(), f.admin, "legacy-api"); !errors.Is(err, modules.ErrStateAmbiguous) {
		t.Fatal("duplicate rows allowed a write", err)
	}
	var count int
	if err := f.store.DB.QueryRow("SELECT COUNT(*) FROM " + f.store.Table("options") + " WHERE option_name='go_module_installations'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("module write rewrote history: count=%d err=%v", count, err)
	}
}

func TestStateRowsMissingFailReads(t *testing.T) {
	f := fixture(t)
	if _, err := f.store.DB.Exec("DELETE FROM " + f.store.Table("options") + " WHERE option_name='go_module_installations'"); err != nil {
		t.Fatal(err)
	}
	m := f.manager()
	if _, err := m.RequestState(t.Context()); !errors.Is(err, modules.ErrStateMissing) {
		t.Fatal("missing install row accepted", err)
	}
	if err := modules.CheckStateRows(t.Context(), f.store); err == nil {
		t.Fatal("CheckStateRows ignored the missing row")
	}
}

func TestInvalidEnableValuesFailWithoutChoosing(t *testing.T) {
	f := fixture(t)
	for _, state := range []string{"{", `["a",{"name":1}]`, `[{"name":"legacy-api"}]}`} {
		f.setState(t, state, "[]")
		m := f.manager()
		if _, err := m.RequestState(t.Context()); !errors.Is(err, modules.ErrStateInvalid) {
			t.Fatalf("invalid state %q read as valid", state)
		}
		if err := m.Enable(t.Context(), f.admin, "legacy-api"); !errors.Is(err, modules.ErrStateInvalid) {
			t.Fatalf("invalid state %q allowed a write", state)
		}
	}
	// Unsupported names are out-of-scope facts; they never gain execution but
	// must not block a valid enable and their exact bytes stay saved.
	f.setState(t, `["shiny-plugin",{"name":"another-plugin","version":"9"}]`, `[{"name":"legacy-api","version":"1.0.0"}]`)
	m := f.manager()
	if err := m.Enable(t.Context(), f.admin, "legacy-api"); err != nil {
		t.Fatal("legacy string entries blocked a valid enable", err)
	}
	enabled, _ := f.rows(t)
	if enabled != `["shiny-plugin",{"name":"another-plugin","version":"9"},{"name":"legacy-api","version":"1.1.3"}]` {
		t.Fatalf("legacy string entries were re-encoded: %s", enabled)
	}
}

func TestSharedCurrentReadHoldsUntilCommit(t *testing.T) {
	f := fixture(t)
	m := f.manager()
	f.setState(t, "", `[{"name":"legacy-api","version":"1.1.3"},{"name":"yggdrasil-api","version":"5.2.1"}]`)
	reader, err := f.store.DB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback()
	state, err := m.LockStateTx(t.Context(), reader)
	if err != nil {
		t.Fatal(err)
	}
	if !state.HasInstalled("yggdrasil-api") || state.HasEnabled("yggdrasil-api") {
		t.Fatalf("shared read facts drifted: %v", state)
	}
	done := make(chan error, 1)
	go func() {
		done <- m.Enable(t.Context(), f.admin, "yggdrasil-api")
	}()
	select {
	case err := <-done:
		t.Fatal("exclusive writer ignored the shared lock", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := reader.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("waited writer failed after the shared reader committed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exclusive writer did not resume after the shared commit")
	}
	enabled, _ := f.rows(t)
	if !strings.Contains(enabled, `"name":"yggdrasil-api"`) {
		t.Fatalf("waited enable missing: %s", enabled)
	}
}

func TestConcurrentMutationsKeepTheEntriesOnce(t *testing.T) {
	f := fixture(t)
	m := f.manager()
	f.setState(t, `[{"name":"legacy-api","version":"1.1.3"}]`, `[{"name":"legacy-api","version":"1.1.3"},{"name":"yggdrasil-api","version":"5.2.1"}]`)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.Enable(t.Context(), f.admin, "yggdrasil-api"); err != nil {
				t.Error("concurrent enable failed:", err)
			}
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reader, err := f.store.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := m.LockStateTx(context.Background(), reader); err != nil {
				t.Error("shared concurrent read failed:", err)
				reader.Rollback()
				return
			}
			reader.Commit()
		}()
	}
	wg.Wait()
	enabled, installed := f.rows(t)
	if enabled != `[{"name":"legacy-api","version":"1.1.3"},{"name":"yggdrasil-api","version":"5.2.1"}]` {
		t.Fatalf("concurrent enables diverged: %s", enabled)
	}
	if installed != `[{"name":"legacy-api","version":"1.1.3"},{"name":"yggdrasil-api","version":"5.2.1"}]` {
		t.Fatalf("install registration diverged: %s", installed)
	}
}

func TestTakeoverInitializeSeedsRowFactsOnce(t *testing.T) {
	f := fixture(t)
	if manifest, err := modules.LoadManifest(""); manifest != nil || err != nil {
		t.Fatal("empty manifest path declared nothing", manifest, err)
	}
	if _, err := f.store.DB.Exec("DELETE FROM " + f.store.Table("options") + " WHERE option_name IN ('plugins_enabled','go_module_installations')"); err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/modules.json"
	if err := os.WriteFile(path, []byte(`{"installed":[{"name":"legacy-api","version":"1.1.3"},{"name":"yggdrasil-api","version":"5.2.1"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := modules.LoadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := map[string]string{"plugins_enabled": `[{"name":"legacy-api","version":"1.1.3"}]`}
	if err = modules.Initialize(t.Context(), f.store, snapshot, nil); err == nil || !strings.Contains(err.Error(), "declared module manifest required") {
		t.Fatal("manifest absence did not fail the install ledger", err)
	}
	if err = modules.Initialize(t.Context(), f.store, snapshot, manifest); err != nil {
		t.Fatal(err)
	}
	enabled, installed := f.rows(t)
	if enabled != `[{"name":"legacy-api","version":"1.1.3"}]` {
		t.Fatalf("snapshot value not seeded: %s", enabled)
	}
	if installed != `[{"name":"legacy-api","version":"1.1.3"},{"name":"yggdrasil-api","version":"5.2.1"}]` {
		t.Fatalf("manifest value not seeded: %s", installed)
	}
	// A repeated takeover must not rewrite runtime state.
	if err = modules.Initialize(t.Context(), f.store, map[string]string{"plugins_enabled": "recomputed"}, manifest); err != nil {
		t.Fatal(err)
	}
	if enabled, _ = f.rows(t); enabled != `[{"name":"legacy-api","version":"1.1.3"}]` {
		t.Fatalf("repeat takeover rewrote runtime state: %s", enabled)
	}
}

func TestValidateManifestNameAndShape(t *testing.T) {
	path := t.TempDir() + "/modules.json"
	for name, body := range map[string]string{
		"unsupported":  `{"installed":[{"name":"shiny-plugin","version":"9"}]}`,
		"repeated":     `{"installed":[{"name":"legacy-api","version":"1.1.3"},{"name":"legacy-api","version":"1.1.3"}]}`,
		"emptyVersion": `{"installed":[{"name":"legacy-api","version":""}]}`,
		"legacyString": `{"installed":["disguised"]}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := modules.LoadManifest(path); err == nil {
			t.Fatalf("invalid manifest %s accepted", name)
		}
	}
}

func TestRequestValuesFeedDisplayRows(t *testing.T) {
	f := fixture(t)
	f.setState(t, `["disable-registration"]`, `[{"name":"legacy-api","version":"1.1.3"}]`)
	m := f.manager()
	state, err := m.RequestState(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if state.HasEnabled("invitation-codes") || state.HasInstalled("yggdrasil-api") {
		t.Fatal("state facts crossed rows")
	}
	values, err := m.RequestValues(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if values["plugins_enabled"] != `["disable-registration"]` || values["go_module_installations"] != `[{"name":"legacy-api","version":"1.1.3"}]` {
		t.Fatalf("display values drifted: %v", values)
	}
	data := m.Installed(t.Context(), "zh_CN", state)
	if len(data) != 1 || data[0].Name != "legacy-api" {
		t.Fatalf("uninstalled names leaked into the manage page: %v", data)
	}
	if title, description := modules.Metas()[0].Translations("zh_CN"); title != "注册邀请码" || description == "" {
		t.Fatalf("frozen plugin translations lost: %s / %s", title, description)
	}
}

func TestProductModuleNamespaces(t *testing.T) {
	for _, m := range modules.Metas() {
		if m.Name != "legacy-api" && m.Name != "oauth" {
			continue
		}
		for _, text := range []*modules.Trans{m.Title, m.Description} {
			if !strings.HasPrefix(text.Namespace, "ParadiseCosmeticsStudio\\") {
				t.Errorf("module %s namespace = %s", m.Name, text.Namespace)
			}
			for _, locale := range []string{"en", "zh_CN"} {
				if text.Localized(locale) == "" {
					t.Errorf("module %s missing %s translation", m.Name, locale)
				}
			}
		}
	}
	if modules.Message("ParadiseCosmeticsStudio\\DisableRegistration::general.title", "en") != "Disable Registration" {
		t.Fatal("registration restriction translation missing")
	}
	if modules.Message("Blessing\\DisableRegistration::general.title", "en") != "" {
		t.Fatal("old namespace still resolves")
	}
}
