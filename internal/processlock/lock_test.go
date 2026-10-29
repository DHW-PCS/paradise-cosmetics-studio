package processlock

import (
	"path/filepath"
	"testing"
)

func TestOfflineLockExcludesServeAndWorker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instance.lock")
	serve, err := Acquire(path, false)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := Acquire(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if l, err := Acquire(path, true); err == nil {
		l.Close()
		t.Fatal("offline operation admitted while running")
	}
	serve.Close()
	worker.Close()
	offline, err := Acquire(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer offline.Close()
	if l, err := Acquire(path, false); err == nil {
		l.Close()
		t.Fatal("service admitted during offline operation")
	}
}
