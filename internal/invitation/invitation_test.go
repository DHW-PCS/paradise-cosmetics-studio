package invitation_test

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"paradise-cosmetics-studio/internal/database"
	"paradise-cosmetics-studio/internal/identity"
	"paradise-cosmetics-studio/internal/invitation"
	"paradise-cosmetics-studio/internal/modules"
	"paradise-cosmetics-studio/internal/testsupport"
)

type harness struct {
	store  *database.Store
	id     *identity.Service
	admin  *identity.BrowserSession
	module *modules.Manager
	code   *invitation.Service
}

func fixture(t *testing.T) harness {
	t.Helper()
	store, id := testsupport.Database(t, "inv-")
	admin, err := id.Login(t.Context(), "admin@example.invalid", "original-password", false, "")
	if err != nil {
		t.Fatal(err)
	}
	module := testsupport.Modules(store, id)
	code := invitation.New(store, id.Now)
	return harness{store: store, id: id, admin: admin, module: module, code: code}
}

func (f harness) countRows(t *testing.T, where string) int {
	t.Helper()
	var count int
	if err := f.store.DB.QueryRow("SELECT COUNT(*) FROM " + f.store.Table("invitation_codes") + " WHERE " + where).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func (f harness) seedCode(t *testing.T, code string, usedBy int64) {
	t.Helper()
	if _, err := f.store.DB.Exec("INSERT INTO "+f.store.Table("invitation_codes")+" (code,generated_at,used_by) VALUES (?,NOW(6),?)", code, usedBy); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateProducesFreshBatchShape(t *testing.T) {
	f := fixture(t)
	if err := f.code.Generate(t.Context(), f.store, 3); err != nil {
		t.Fatal(err)
	}
	if n := f.countRows(t, "used_by = 0"); n != 3 {
		t.Fatalf("batch rows=%d", n)
	}
	rows, err := f.store.DB.Query("SELECT code FROM " + f.store.Table("invitation_codes"))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			t.Fatal(err)
		}
		if len(code) != 32 || code != strings.ToLower(code) {
			t.Fatalf("generated code violated the original shape: %q", code)
		}
		if seen[code] {
			t.Fatal("two rows share one code")
		}
		seen[code] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateRejectsUnusableAmountWithoutInserts(t *testing.T) {
	f := fixture(t)
	for _, amount := range []int64{0, -1} {
		if err := f.code.Generate(t.Context(), f.store, amount); !errors.Is(err, invitation.ErrAmount) {
			t.Fatalf("amount %d accepted: %v", amount, err)
		}
	}
	if f.countRows(t, "used_by = 0") != 0 {
		t.Fatal("rejected amounts produced rows")
	}
}

func TestGenerateCollisionFailsTheWholeBatch(t *testing.T) {
	f := fixture(t)
	// The code generator seam only exists for fixed-input checks;
	// production always draws fresh crypto/rand bytes.
	poison := "0123456789abcdef0123456789abcdef"
	f.code.Codes = func(int) ([]string, error) {
		return []string{poison, "ffffffffffffffffffffffffffffffff"}, nil
	}
	f.seedCode(t, poison, 0)
	before := f.countRows(t, "used_by = 0")
	if err := f.code.Generate(t.Context(), f.store, 2); !errors.Is(err, invitation.ErrGeneration) {
		t.Fatalf("collision accepted: %v", err)
	}
	if f.countRows(t, "used_by = 0") != before {
		t.Fatal("collision batch inserted rows")
	}
}

func TestReserveRefusesEmptyAndUnavailableCodes(t *testing.T) {
	f := fixture(t)
	f.seedCode(t, "a"+strings.Repeat("b", 31), 0)
	err := f.store.Transaction(t.Context(), func(tx *sql.Tx) error {
		_, reserveErr := f.code.ReserveTx(t.Context(), tx, "")
		return reserveErr
	})
	if !errors.Is(err, invitation.ErrEmpty) {
		t.Fatal("empty code accepted", err)
	}
	f.seedCode(t, strings.Repeat("e", 32), 7)
	for _, code := range []string{"c" + strings.Repeat("d", 31), strings.Repeat("e", 32)} {
		err := f.store.Transaction(t.Context(), func(tx *sql.Tx) error {
			_, reserveErr := f.code.ReserveTx(t.Context(), tx, code)
			return reserveErr
		})
		if !errors.Is(err, invitation.ErrUnavailable) {
			t.Fatalf("code %q accepted: %v", code, err)
		}
	}
}

func TestReserveAndConsumeHandleOneRow(t *testing.T) {
	f := fixture(t)
	code := strings.Repeat("f", 32)
	f.seedCode(t, code, 0)
	var reservation modules.Reservation
	err := f.store.Transaction(t.Context(), func(tx *sql.Tx) error {
		var reserveErr error
		reservation, reserveErr = f.code.ReserveTx(t.Context(), tx, code)
		return reserveErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if reservation == nil {
		t.Fatal("usable code produced no reservation")
	}
	if err = f.store.Transaction(t.Context(), func(tx *sql.Tx) error {
		return reservation.ConsumeTx(t.Context(), tx, 1)
	}); err != nil {
		t.Fatal(err)
	}
	if f.countRows(t, "used_by = 1") != 1 {
		t.Fatal("consume did not record the owner")
	}
	var consumedBy int64
	if err := f.store.DB.QueryRow("SELECT used_by FROM "+f.store.Table("invitation_codes")+" WHERE code=?", code).Scan(&consumedBy); err != nil || consumedBy != 1 {
		t.Fatalf("consume wrote uid=%d err=%v", consumedBy, err)
	}
	// Two unused rows for one code settle it as ambiguous history: the
	// registration refuses, no row is chosen and no row is deleted.
	duplicated := strings.Repeat("9", 32)
	f.seedCode(t, duplicated, 0)
	f.seedCode(t, duplicated, 0)
	err = f.store.Transaction(t.Context(), func(tx *sql.Tx) error {
		_, reserveErr := f.code.ReserveTx(t.Context(), tx, duplicated)
		return reserveErr
	})
	if !errors.Is(err, invitation.ErrAmbiguous) {
		t.Fatalf("duplicate rows read as usable: %v", err)
	}
	if f.countRows(t, "code = '"+duplicated+"'") != 2 {
		t.Fatal("duplicate handling deleted history")
	}
	// One used row plus one free row keeps the original invalid verdict; the
	// used instance wins before any ambiguity is considered.
}

func TestCheckReadyBlocksEnableWithoutSchema(t *testing.T) {
	f := fixture(t)
	if _, err := f.store.DB.Exec("DROP TABLE " + f.store.Table("invitation_codes")); err != nil {
		t.Fatal(err)
	}
	err := f.store.Transaction(t.Context(), func(tx *sql.Tx) error {
		reasons, checkErr := f.code.CheckReady(t.Context(), tx)
		if checkErr != nil {
			return checkErr
		}
		if len(reasons) == 0 || !strings.Contains(reasons[0], "invitation_codes") {
			t.Errorf("unexpected refusal reasons: %v", reasons)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestConsumerRegistrationsRestrictEligibilityNames(t *testing.T) {
	f := fixture(t)
	if err := f.module.RegisterConsumer("unsupported", f.code.ReserveTx); !errors.Is(err, modules.ErrUnknownModule) {
		t.Fatal("unsupported consumer accepted", err)
	}
	if err := f.module.RegisterConsumer("yggdrasil-api", f.code.ReserveTx); !errors.Is(err, modules.ErrUnknownModule) {
		t.Fatal("non-restricting consumer accepted", err)
	}
	if _, connected := f.module.ConsumerOf("disable-registration"); connected {
		t.Fatal("unconnected consumer reported connected")
	}
	if err := f.module.RegisterConsumer("invitation-codes", f.code.ReserveTx); err != nil {
		t.Fatal(err)
	}
	if _, connected := f.module.ConsumerOf("invitation-codes"); !connected {
		t.Fatal("connected consumer missing")
	}
}
