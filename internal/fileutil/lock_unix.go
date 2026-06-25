//go:build !windows

package fileutil

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// Lock blocks until it acquires an exclusive advisory lock on path (creating
// the file if it doesn't exist) and returns a handle that releases the lock
// when closed. The OS also releases the lock automatically if the holding
// process exits without closing it, which is sufficient for envseal's
// short-lived, one-command-per-process invocation model.
//
// O_NOFOLLOW makes the open fail (ELOOP) if a symlink has been planted at the
// lock path: lock files live at predictable locations (.envseal/lock,
// .envseal.lock, audit.log.lock), and following a symlink there would let an
// attacker with write access to the directory redirect the open+flock onto an
// arbitrary file the victim's process then creates or holds locked. Every
// other predictable-path open in this codebase (audit log, key file, vault)
// already refuses symlinks; the lock path must not be the one exception.
func Lock(path string) (*os.File, error) {
	//nolint:gosec // G304: path is always one of this package's own predictable lock locations (.envseal/lock, .envseal.lock, audit.log.lock), constructed internally, not user-supplied traversal input; O_NOFOLLOW above and the regular-file check below are the actual defenses for this path.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	// fd-based stat (no TOCTOU): reject a pre-created FIFO, device, or other
	// non-regular file at the lock path — fail closed like the symlink case.
	info, err := f.Stat()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("stat lock file: %w", err), f.Close())
	}
	if !info.Mode().IsRegular() {
		return nil, errors.Join(
			fmt.Errorf("lock path %q is not a regular file — refusing to lock for security", path),
			f.Close(),
		)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, errors.Join(fmt.Errorf("acquire lock: %w", err), f.Close())
	}
	return f, nil
}
