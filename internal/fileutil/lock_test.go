package fileutil

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLock_CreatesFileIfMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	f, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected lock file to be created: %v", err)
	}
}

// TestRequireRealDir covers the shared guard used by every .envseal writer
// (key file, vault, config, audit log): real directory passes; a symlinked
// directory, a regular file, and a missing path are all refused.
func TestRequireRealDir(t *testing.T) {
	base := t.TempDir()

	if err := RequireRealDir(base); err != nil {
		t.Errorf("real directory should pass, got: %v", err)
	}

	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := RequireRealDir(file); err == nil {
		t.Error("regular file should be refused")
	}

	if err := RequireRealDir(filepath.Join(base, "missing")); err == nil {
		t.Error("missing path should be refused")
	}

	link := filepath.Join(base, "link")
	if err := os.Symlink(base, link); err != nil {
		t.Skipf("cannot create symlink on this platform: %v", err)
	}
	if err := RequireRealDir(link); err == nil {
		t.Error("symlinked directory should be refused")
	}
}

// TestLock_RefusesSymlink verifies that Lock fails closed when a symlink has
// been planted at the lock path instead of following it to the target file
// (O_NOFOLLOW on Unix, Lstat/SameFile comparison on Windows).
func TestLock_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "lock")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink on this platform: %v", err)
	}
	f, err := Lock(link)
	if err == nil {
		_ = f.Close()
		t.Fatal("expected Lock to refuse a symlinked lock path")
	}
}

// TestLock_BlocksSecondAcquisition verifies the lock actually excludes a
// second holder rather than being a no-op. flock (and LockFileEx) associate
// the lock with the open file description, not the process, so two separate
// Lock calls from goroutines in this same test process still contend
// correctly — this doesn't require spawning real subprocesses to exercise
// the blocking behavior that requireDeps relies on.
func TestLock_BlocksSecondAcquisition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")

	first, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}

	acquired := make(chan struct{})
	go func() {
		second, err := Lock(path)
		if err != nil {
			t.Error(err)
			return
		}
		close(acquired)
		_ = second.Close()
	}()

	select {
	case <-acquired:
		t.Fatal("second Lock acquired while first still held")
	case <-time.After(100 * time.Millisecond):
		// expected: second call is still blocked
	}

	_ = first.Close()

	select {
	case <-acquired:
		// expected: released, second call proceeds
	case <-time.After(2 * time.Second):
		t.Fatal("second Lock did not acquire after first was released")
	}
}

// TestLock_RefusesNonRegularFile verifies Lock's fd-based Stat check rejects
// a FIFO pre-created at the lock path — the same fail-closed behavior as the
// symlink case, but for a non-regular file that isn't a symlink at all (so
// O_NOFOLLOW alone wouldn't catch it): a process that then wrote to what it
// believes is its own lock file would instead block indefinitely on a pipe
// with no reader, or hand data to whatever process the attacker has reading
// the other end.
func TestLock_RefusesNonRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	if err := mkfifo(path); err != nil {
		t.Skipf("cannot create FIFO on this platform: %v", err)
	}
	f, err := Lock(path)
	if err == nil {
		_ = f.Close()
		t.Fatal("expected Lock to refuse a FIFO at the lock path")
	}
}
