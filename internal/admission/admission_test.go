package admission

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBoundedQueueCancellationTimeoutAndRelease(t *testing.T) {
	g, err := New(Config{1, 1, 40 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	release, err := g.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	queued := make(chan error, 1)
	go func() {
		done, err := g.Acquire(ctx)
		if done != nil {
			done()
		}
		queued <- err
	}()
	deadline := time.Now().Add(time.Second)
	for len(g.waiting) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("request did not queue")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err = g.Acquire(t.Context()); !errors.Is(err, ErrBusy) {
		t.Fatalf("full queue: %v", err)
	}
	cancel()
	if err = <-queued; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = g.Acquire(t.Context()); !errors.Is(err, ErrBusy) {
		t.Fatalf("wait deadline: %v", err)
	}
	release()
	for i := 0; i < 3; i++ {
		done, err := g.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		done()
	}
}

func TestQueuedRequestAdmittedAfterRelease(t *testing.T) {
	g, _ := New(Config{1, 1, time.Second})
	release, _ := g.Acquire(t.Context())
	result := make(chan error, 1)
	go func() {
		done, err := g.Acquire(t.Context())
		if done != nil {
			done()
		}
		result <- err
	}()
	release()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
