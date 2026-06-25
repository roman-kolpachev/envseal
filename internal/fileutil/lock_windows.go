//go:build windows

package fileutil

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// Lock blocks until it acquires an exclusive lock on path (creating the file
// if it doesn't exist) and returns a handle that releases the lock when
// closed. The OS also releases the lock automatically if the holding process
// exits without closing it, which is sufficient for envseal's short-lived,
// one-command-per-process invocation model.
//
// A symlink or junction planted at the predictable lock path (.envseal/lock,
// .envseal.lock, audit.log.lock) would redirect the open+lock onto an
// arbitrary file. The fd-based Stat plus post-open Lstat/SameFile comparison
// below detects that (mirroring the pattern used by audit.Logger.Log for the
// newly-created-file case) and fails closed, matching the O_NOFOLLOW
// behaviour of the Unix implementation.
func Lock(path string) (*os.File, error) {
	//nolint:gosec // G304: path is an internal application lock file path computed by the tool, never derived from user input.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	fdInfo, err := f.Stat()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("stat lock file: %w", err), f.Close())
	}
	if !fdInfo.Mode().IsRegular() {
		return nil, errors.Join(
			fmt.Errorf("lock path %q is not a regular file — refusing to lock for security", path),
			f.Close(),
		)
	}
	lstatInfo, err := os.Lstat(path)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("lstat lock path: %w", err), f.Close())
	}
	if lstatInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(lstatInfo, fdInfo) {
		return nil, errors.Join(
			fmt.Errorf("lock path %q is a symlink or was replaced — refusing to lock for security", path),
			f.Close(),
		)
	}
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0,
		1, 0,
		overlapped,
	); err != nil {
		return nil, errors.Join(fmt.Errorf("acquire lock: %w", err), f.Close())
	}
	return f, nil
}
