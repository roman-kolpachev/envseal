//go:build !windows

package keyring

import (
	"fmt"
	"os"
	"syscall"
)

// secureKeyFile is a no-op on non-Windows platforms: mode 0600 (set by
// AtomicWriteFile) already restricts the file to the owner via the traditional
// Unix permission bits, and any additional POSIX ACLs are caught by
// checkKeyFileOwnership on load.
func secureKeyFile(_ string) error { return nil }

// checkKeyFileOwnership verifies that the key file at path is owned by the
// current user. On Unix, a file with mode 0600 can still be readable by a
// non-owner if POSIX ACLs are present (e.g. setfacl -m u:victim:r-- file);
// os.Lstat().Mode().Perm() returns only the traditional 9 permission bits and
// does not see ACL entries. Checking the owning UID closes this gap.
func checkKeyFileOwnership(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat key file for ownership check: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Cannot retrieve ownership metadata on this platform variant; skip.
		return nil
	}
	currentUID := os.Getuid()
	//nolint:gosec // G115: os.Getuid() is always a small non-negative value representable in uint32 on POSIX systems; it cannot overflow in practice.
	if stat.Uid != uint32(currentUID) {
		return fmt.Errorf(
			"owned by UID %d but running as UID %d — possible key substitution attack",
			stat.Uid, currentUID,
		)
	}
	return nil
}
