// Package processlock coordinates the single-host service and offline CLI.
package processlock

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type Lock struct{ file *os.File }

// Acquire uses a shared lock for serve/worker and an exclusive lock for offline
// migration/reset. Every command in one deployment uses the same configured path.
func Acquire(path string, offline bool) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	mode := unix.LOCK_SH
	if offline {
		mode = unix.LOCK_EX
	}
	if err = unix.Flock(int(f.Fd()), mode|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("instance lock unavailable: stop conflicting processes before this command")
	}
	return &Lock{f}, nil
}

func (l *Lock) Close() error { return l.file.Close() }
