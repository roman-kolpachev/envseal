package fileutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// RequireRealDir verifies that dir exists and is a real directory — not a
// symlink (or, on Windows, a junction, which also carries ModeSymlink in
// Lstat results). Callers that write security-relevant files into fixed,
// predictable locations (.envseal/, .envseal/vault/) use this to stop a
// pre-planted symlink from silently redirecting the write: for the private
// key that would leak secret material, and for vault/config files it would
// make a save (e.g. a revoke's re-encryption) land outside the repository
// while the command still reports success — the git-tracked state silently
// keeps the pre-revoke encryption. Lstat never follows links, so this check
// itself is not subject to the race it guards against; the final component's
// own symlink protection is handled separately by StageWrite/openers.
func RequireRealDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("path %q is a symlink or not a real directory — refusing to write through it for security", dir)
	}
	return nil
}

// StageWrite writes data to a new temp file in the same directory as path
// (so a later CommitWrite's rename is atomic and stays on the same
// filesystem) but does not touch path itself. Splitting the write from the
// commit lets a caller stage several files — none of which affect any
// existing on-disk state — and only commit (rename) all of them once every
// one has staged successfully, giving callers that must write multiple
// files as a unit (see cmd.saveAllVaults) real all-or-nothing semantics
// instead of a partial write leaving some files updated and others not.
// On any failure, no temp file is left behind.
func StageWrite(path string, data []byte, perm os.FileMode, pattern string) (string, error) {
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return "", fmt.Errorf("target path %q is not a regular file", path)
	}

	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		return "", errors.Join(
			fmt.Errorf("write temp file: %w", err),
			tmp.Close(),
			os.Remove(tmpName),
		)
	}

	if err := tmp.Sync(); err != nil {
		return "", errors.Join(
			fmt.Errorf("sync temp file: %w", err),
			tmp.Close(),
			os.Remove(tmpName),
		)
	}

	if err := tmp.Chmod(perm); err != nil {
		return "", errors.Join(
			fmt.Errorf("set temp file permissions: %w", err),
			tmp.Close(),
			os.Remove(tmpName),
		)
	}

	if err := tmp.Close(); err != nil {
		return "", errors.Join(
			fmt.Errorf("close temp file: %w", err),
			os.Remove(tmpName),
		)
	}

	return tmpName, nil
}

// CommitWrite renames a temp file created by StageWrite into place at path
// and best-effort fsyncs the containing directory afterward so the rename
// survives a crash or power loss (not supported on all platforms/
// filesystems, so errors here are deliberately ignored).
func CommitWrite(tmpName, path string) error {
	if err := os.Rename(tmpName, path); err != nil {
		return errors.Join(
			fmt.Errorf("rename temp file: %w", err),
			os.Remove(tmpName),
		)
	}

	dir := filepath.Dir(path)
	//nolint:gosec // G304: dir is filepath.Dir() of a path this function just finished writing; best-effort fsync only, errors are intentionally ignored.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}

	return nil
}

// AbortWrite discards a temp file created by StageWrite without committing
// it. Safe to call on an empty or already-removed path.
func AbortWrite(tmpName string) error {
	if tmpName == "" {
		return nil
	}
	if err := os.Remove(tmpName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove staged temp file: %w", err)
	}
	return nil
}

func AtomicWriteFile(path string, data []byte, perm os.FileMode, pattern string) error {
	tmpName, err := StageWrite(path, data, perm, pattern)
	if err != nil {
		return err
	}
	return CommitWrite(tmpName, path)
}
