package oauthserver

import (
	"context"
	"errors"
	"sync"
)

// Snapshot is an immutable scope set. Issuance flows bind one read lease for
// the whole flow, so an online update never changes the scope facts a running
// flow reads halfway through.
type Snapshot struct {
	// Names drive the engine client scope list in the frozen order.
	Names []string
}

// ScopePolicy is the single reader/writer coordination of the scope snapshot.
// Read leases guard whole issuance flows (authorize/consent/token/refresh and
// the initial access validation); the write lease owns exactly one
// transaction-then-publish cycle, so an update waits until every flow that
// pinned the old snapshot committed or rolled back. The engine reads scope
// facts through the pinned snapshot never from a mutable slice.
type ScopePolicy struct {
	mu       sync.Mutex
	snapshot *Snapshot
	cond     *sync.Cond
	pinned   int
	writing  bool
	poison   error
}

var errOutsideWriteLease = errors.New("oauth server: publish outside the write lease")

// ReadLease pins one snapshot from acquire until release.
type ReadLease struct {
	policy   *ScopePolicy
	snapshot Snapshot
}

// Snapshot returns the pinned immutable facts.
func (l *ReadLease) Snapshot() Snapshot { return l.snapshot }

// Release unpins the lease and wakes a waiting writer.
func (l *ReadLease) Release() {
	l.policy.mu.Lock()
	defer l.policy.mu.Unlock()
	if l.policy.pinned > 0 {
		l.policy.pinned--
	}
	if l.policy.pinned == 0 {
		l.policy.cond.Broadcast()
	}
}

// WriteLease takes the update boundary from acquired until release.
type WriteLease struct{ policy *ScopePolicy }

// Publish installs the committed snapshot while the write lease is held; a
// commit that never becomes visible must fail instead.
func (l *WriteLease) Publish(snapshot Snapshot) error {
	l.policy.mu.Lock()
	defer l.policy.mu.Unlock()
	if !l.policy.writing {
		return errOutsideWriteLease
	}
	l.policy.snapshot = &snapshot
	return nil
}

// Release closes the write boundary and wakes waiting readers.
func (l *WriteLease) Release() {
	l.policy.mu.Lock()
	defer l.policy.mu.Unlock()
	l.policy.writing = false
	l.policy.cond.Broadcast()
}

// Poison marks the policy unusable after an ambiguous commit; issuance
// refuses until the process restarts and rebuilds from the authoritative DB.
func (p *ScopePolicy) Poison() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.poison = errors.New("oauth server: scope policy poisoned by an ambiguous commit")
	p.cond.Broadcast()
}

func NewScopePolicy(snapshot Snapshot) *ScopePolicy {
	p := &ScopePolicy{snapshot: &snapshot}
	p.cond = sync.NewCond(&p.mu)
	return p
}

// AcquireRead pins the current snapshot for the caller's flow lifetime;
// password computation runs outside the lease window.
func (p *ScopePolicy) AcquireRead(ctx context.Context) (*ReadLease, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.poison != nil {
		return nil, p.poison
	}
	for p.writing {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.cond.Wait()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.pinned++
	return &ReadLease{policy: p, snapshot: *p.snapshot}, nil
}

// AcquireWrite blocks until no flow pins the read lease, then owns the write
// boundary until release; ctx cancellation breaks the wait.
func (p *ScopePolicy) AcquireWrite(ctx context.Context) (*WriteLease, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.poison != nil {
		return nil, p.poison
	}
	for p.writing || p.pinned > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.cond.Wait()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.writing = true
	return &WriteLease{policy: p}, nil
}
