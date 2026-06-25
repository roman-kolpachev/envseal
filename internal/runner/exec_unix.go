//go:build !windows

package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func execProcess(_ context.Context, binary string, args, env []string) error {
	//nolint:gosec // G204: executing the user-specified command is this tool's entire purpose ("envseal run -- CMD"); binary is resolved via exec.LookPath by the only caller (runner.go), not passed through a shell.
	return syscall.Exec(binary, args, env)
}

func cleanupSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func validateTempDirSecurity(info os.FileInfo) bool {
	if info.Mode().Perm()&0077 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	//nolint:gosec // G115: os.Getuid() is always a small non-negative value representable in uint32 on POSIX systems; it cannot overflow in practice.
	return stat.Uid == uint32(os.Getuid())
}

// validateTempDirOwnership is a no-op on Unix: validateTempDirSecurity has
// already verified both the 0700 permission mask and that the directory is
// owned by the current UID via syscall.Stat_t before this is called.
func validateTempDirOwnership(_ string) error {
	return nil
}

func userTempDir() (string, error) {
	dir := filepath.Join(os.TempDir(), fmt.Sprintf(".envseal-%d", os.Getuid()))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create user temp directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", fmt.Errorf("stat user temp directory: %w", err)
	}
	if !validateTempDirSecurity(info) {
		return "", fmt.Errorf("user temp directory %s has insecure ownership or permissions — remove it and re-run", dir)
	}
	return dir, nil
}
