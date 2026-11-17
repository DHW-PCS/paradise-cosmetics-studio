// Package modules owns the four fixed module declarations, the DB-authoritative
// install/enable option rows and their lock discipline.
//
// The enable fact keeps the original options.plugins_enabled object array
// (unmodified entries stay verbatim, including out-of-scope entries) and the
// install registration lives in options.go_module_installations. ModuleManager
// is the only writer of these two keys.
package modules

import (
	"context"
	"database/sql"
	"errors"

	"paradise-cosmetics-studio/internal/database"
	"paradise-cosmetics-studio/internal/identity"
)

var (
	ErrUnknownModule = errors.New("modules: unsupported module name")
	ErrNotFound      = errors.New("modules: module not found")
	// State failures are deployment conflicts: both authoritative rows must
	// exist exactly once and the layer never falls back to snapshots or
	// defaults; duplicate option rows keep their history and fail reads.
	ErrStateMissing      = errors.New("modules: module state rows missing; run offline migrate")
	ErrStateAmbiguous    = errors.New("modules: duplicate module state option rows")
	ErrStateInvalid      = errors.New("modules: module state value invalid")
	ErrStatePlanConflict = errors.New("modules: module state plan changed inside the transaction")
	ErrForbidden         = errors.New("modules: administrator required")
)

// NotReady reports that one module's enable precondition refused. Reasons are
// the fulfilled-translated strings the module check produced and belong to the
// manage response; the state rows keep their original values.
type NotReady struct {
	Reasons []string
}

func (e *NotReady) Error() string { return "modules: enable readiness check refused" }

// AsNotReady classifies enable refusals carrying the module's own reasons.
func AsNotReady(err error) (*NotReady, bool) {
	var notReady *NotReady
	if errors.As(err, &notReady) {
		return notReady, true
	}
	return nil, false
}

// Reasons returns the translated refusal reasons of an enable outcome.
func Reasons(err error) []string {
	if notReady, ok := AsNotReady(err); ok {
		return notReady.Reasons
	}
	return nil
}

// EligibilityConsumers names the modules whose enabled state requires a
// registration, transaction-based consumer. Owners connect their consumers in
// their own packages; until then an enabled entry explicitly refuses.
var EligibilityConsumers = []string{"invitation-codes", "disable-registration", "restricted-email-domains"}

// Reservation is the consume handle a module consumer returns from one
// registration transaction; ConsumeTx runs inside the same transaction.
type Reservation interface {
	ConsumeTx(ctx context.Context, tx *sql.Tx, uid int64) error
}

// Consumer consults one restricting module with the request's registration
// input. A refused or malformed code fails the whole registration
// transaction; the state rows decide nothing further here.
type Consumer func(ctx context.Context, tx *sql.Tx, code string) (Reservation, error)

const (
	enableOptionKey  = "plugins_enabled"
	installOptionKey = "go_module_installations"
)

// Manager owns the module state read/write boundary. It knows nothing about
// account, player, OAuth or display layers; domains consume its state and the
// composition root wires everything.
type Manager struct {
	Store     *database.Store
	Identity  *identity.Service
	checks    map[string]InstallationCheck
	consumers map[string]Consumer
}

func New(store *database.Store, id *identity.Service) *Manager {
	return &Manager{Store: store, Identity: id, checks: map[string]InstallationCheck{}, consumers: map[string]Consumer{}}
}

// RegisterCheck installs one module's own enable precondition (schema/config
// readiness). Owners connect these from their packages after the exclusive
// state locks were taken; an unmet check fails the whole enable transaction.
func (m *Manager) RegisterCheck(name string, check InstallationCheck) error {
	if _, ok := meta(name); !ok {
		return ErrUnknownModule
	}
	m.checks[name] = check
	return nil
}

// RegisterConsumer connects a restricting module's registration consumer. A
// restricting module stays without a consumer until its owner connects one;
// connecting a name outside the supported set is a wiring error.
func (m *Manager) RegisterConsumer(name string, consumer Consumer) error {
	if _, ok := meta(name); !ok {
		return ErrUnknownModule
	}
	var restricting bool
	for _, candidate := range EligibilityConsumers {
		if candidate == name {
			restricting = true
			break
		}
	}
	if !restricting {
		return ErrUnknownModule
	}
	m.consumers[name] = consumer
	return nil
}

// ConsumerOf returns the connected consumer for one restricting module.
func (m *Manager) ConsumerOf(name string) (Consumer, bool) {
	consumer, ok := m.consumers[name]
	return consumer, ok
}
