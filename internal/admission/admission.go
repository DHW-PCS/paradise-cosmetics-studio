// Package admission bounds concurrent password work and the requests waiting for it.
package admission

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrBusy = errors.New("login admission: retry later")

type Config struct {
	Concurrency int
	Queue       int
	Wait        time.Duration
}

type Gate struct {
	active  chan struct{}
	waiting chan struct{}
	wait    time.Duration
}

func New(c Config) (*Gate, error) {
	if c.Concurrency < 1 || c.Queue < 0 || c.Wait <= 0 {
		return nil, fmt.Errorf("login admission: concurrency must be positive, queue nonnegative and wait positive")
	}
	return &Gate{make(chan struct{}, c.Concurrency), make(chan struct{}, c.Queue), c.Wait}, nil
}

// Acquire returns a release function owned by the admitted caller. A cancelled
// password computation keeps its slot until the computation actually stops.
func (g *Gate) Acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	release := func() { <-g.active }
	select {
	case g.active <- struct{}{}:
		return release, nil
	default:
	}
	select {
	case g.waiting <- struct{}{}:
		defer func() { <-g.waiting }()
	default:
		return nil, ErrBusy
	}
	timer := time.NewTimer(g.wait)
	defer timer.Stop()
	select {
	case g.active <- struct{}{}:
		if err := ctx.Err(); err != nil {
			release()
			return nil, err
		}
		return release, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, ErrBusy
	}
}
