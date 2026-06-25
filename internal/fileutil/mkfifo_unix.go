//go:build !windows

package fileutil

import "syscall"

// mkfifo creates a FIFO at path, used by tests to verify Lock refuses
// non-regular files. FIFOs don't exist on Windows, so this file is excluded
// there via the build tag.
func mkfifo(path string) error {
	return syscall.Mkfifo(path, 0600)
}
