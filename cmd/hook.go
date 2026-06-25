package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/roman-kolpachev/envseal/internal/fileutil"
	"github.com/roman-kolpachev/envseal/internal/ui"
)

const hookMarker = "# envseal pre-commit hook"

const preCommitScript = `#!/bin/sh
# envseal pre-commit hook — blocks .envseal/keys and decrypted .env secret
# files from being committed

staged=$(git diff --cached --name-only)

if echo "$staged" | grep -qE '(^|/)\.envseal/keys(\.[^/]*)?$'; then
  echo "✗ .envseal/keys (or a key rotation temp file) is staged for commit."
  echo "  This file contains your private key and must NEVER be committed."
  echo ""
  echo "  To unstage:  git reset HEAD .envseal/keys"
  echo "  To discard:  git checkout -- .envseal/keys"
  exit 1
fi

if echo "$staged" | grep -E '(^|/)\.env(\.[^/]+)?$' | grep -vE '\.(vault|example|sample|template)$' | grep -q .; then
  echo "✗ A plaintext .env-style file is staged for commit."
  echo "  envseal decrypts secrets into files like .env or .env.production —"
  echo "  these must never be committed. Only .envseal/vault/*.vault files"
  echo "  (encrypted) should be tracked in git."
  echo ""
  echo "  To unstage: git reset HEAD -- <file>"
  exit 1
fi
`

func (a *App) newHookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Manage git hooks for envseal",
	}

	cmd.AddCommand(
		a.newHookInstallCmd(),
		a.newHookUninstallCmd(),
	)

	return cmd
}

// gitHooksDir resolves the directory git will actually look in for hooks,
// by asking git itself (`rev-parse --git-path hooks`) rather than assuming
// the default `.git/hooks`. Hardcoding that default silently breaks whenever
// core.hooksPath is configured — a common setup via Husky, the pre-commit
// framework, or lefthook: envseal would report "Installed pre-commit hook"
// while writing to a location git never consults, leaving commits of
// .envseal/keys completely unblocked with no indication anything is wrong.
func gitHooksDir(dir string) (string, error) {
	gitDir := filepath.Join(dir, ".git")
	info, err := os.Lstat(gitDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf(".git directory not found — run from a git repository")
		}
		return "", fmt.Errorf("stat .git: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf(".git is not a directory (worktrees and submodules are not supported for hook management)")
	}

	gitPath, err := exec.LookPath("git")
	if err != nil {
		return "", fmt.Errorf("git binary not found in PATH — hook management requires git to correctly resolve the hooks directory (respecting core.hooksPath)")
	}

	var stdout, stderr bytes.Buffer
	//nolint:gosec // G204: gitPath is resolved via exec.LookPath (not a shell); dir is this process's own working directory, not attacker-controlled input.
	cmd := exec.Command(gitPath, "-C", dir, "rev-parse", "--git-path", "hooks")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("resolve git hooks directory: %s: %w", strings.TrimSpace(stderr.String()), err)
	}

	hooksDir := strings.TrimSpace(stdout.String())
	if hooksDir == "" {
		return "", fmt.Errorf("git returned an empty hooks directory path")
	}
	if filepath.IsAbs(hooksDir) {
		return hooksDir, nil
	}
	return filepath.Join(dir, hooksDir), nil
}

func (a *App) hookPath() (string, error) {
	dir, err := a.workDir()
	if err != nil {
		return "", err
	}

	hooksDir, err := gitHooksDir(dir)
	if err != nil {
		return "", err
	}

	return filepath.Join(hooksDir, "pre-commit"), nil
}

func (a *App) installHook(dir string, w io.Writer) error {
	hooksDir, err := gitHooksDir(dir)
	if err != nil {
		return err
	}
	hookFile := filepath.Join(hooksDir, "pre-commit")
	if lstatInfo, err := os.Lstat(hookFile); err == nil {
		if !lstatInfo.Mode().IsRegular() {
			return fmt.Errorf("pre-commit hook path is not a regular file")
		}
		// An existing hook must be readable before we decide anything about it.
		// Falling through on a read failure would silently overwrite a hook
		// that was never inspected for the envseal marker.
		//nolint:gosec // G304: hookFile was just Lstat-verified above to be a regular file.
		f, openErr := os.Open(hookFile)
		if openErr != nil {
			return fmt.Errorf("read existing pre-commit hook: %w", openErr)
		}
		fdInfo, statErr := f.Stat()
		if statErr != nil {
			return errors.Join(
				fmt.Errorf("stat open hook file: %w", statErr),
				f.Close(),
			)
		}
		if !os.SameFile(lstatInfo, fdInfo) {
			return errors.Join(
				fmt.Errorf("pre-commit hook file changed between stat and open"),
				f.Close(),
			)
		}
		data, readErr := io.ReadAll(io.LimitReader(f, 64*1024))
		closeErr := f.Close()
		if readErr != nil {
			return errors.Join(fmt.Errorf("read existing pre-commit hook: %w", readErr), closeErr)
		}
		if strings.Contains(string(data), hookMarker) {
			return closeErr
		}
		return errors.Join(
			ui.Warn(w, "Pre-commit hook already exists (not envseal) — skipping. Run `envseal hook install` to see details."),
			closeErr,
		)
	}
	if err := ensureHooksDir(filepath.Dir(hookFile)); err != nil {
		return err
	}
	if err := atomicWriteExecutable(hookFile, []byte(preCommitScript)); err != nil {
		return fmt.Errorf("write pre-commit hook: %w", err)
	}
	return ui.Success(w, "Installed pre-commit hook")
}

func atomicWriteExecutable(path string, data []byte) error {
	return fileutil.AtomicWriteFile(
		path,
		data,
		0755,
		".envseal-hook-*",
	)
}

// ensureHooksDir creates the hooks directory at path if it does not exist and
// then verifies it is a real directory (not a symlink or junction). A symlink
// or directory junction here could redirect hook writes to an attacker-controlled
// location. On Windows, directory junctions may report IsDir=true, so we check
// the ModeSymlink bit explicitly as a defence-in-depth measure.
func ensureHooksDir(path string) error {
	if err := os.MkdirAll(path, 0750); err != nil {
		return fmt.Errorf("create hooks directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat hooks directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("hooks directory %q is a symlink or junction — refusing to use for security", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("hooks directory %q is not a real directory — possible symlink injection", path)
	}
	return nil
}

func (a *App) newHookInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install a pre-commit hook that blocks .envseal/keys from being committed",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			hookFile, err := a.hookPath()
			if err != nil {
				return err
			}

			if lstatInfo, statErr := os.Lstat(hookFile); statErr == nil {
				if !lstatInfo.Mode().IsRegular() {
					return fmt.Errorf("pre-commit hook path %q is not a regular file", hookFile)
				}
				//nolint:gosec // G304: hookFile was just Lstat-verified above to be a regular file.
				f, openErr := os.Open(hookFile)
				if openErr != nil {
					return fmt.Errorf("read existing pre-commit hook: %w", openErr)
				}
				fdInfo, fstatErr := f.Stat()
				if fstatErr != nil {
					return errors.Join(
						fmt.Errorf("stat open hook file: %w", fstatErr),
						f.Close(),
					)
				}
				if !os.SameFile(lstatInfo, fdInfo) {
					return errors.Join(
						fmt.Errorf("pre-commit hook file changed between stat and open"),
						f.Close(),
					)
				}
				data, readErr := io.ReadAll(io.LimitReader(f, 64*1024))
				closeErr := f.Close()
				if readErr != nil {
					return errors.Join(fmt.Errorf("read existing pre-commit hook: %w", readErr), closeErr)
				}
				if closeErr != nil {
					return fmt.Errorf("close pre-commit hook: %w", closeErr)
				}
				if strings.Contains(string(data), hookMarker) {
					return ui.Info(cmd.OutOrStdout(), "Pre-commit hook already installed")
				}
				return fmt.Errorf("pre-commit hook already exists at %s — add the envseal check manually:\n\n%s", hookFile, preCommitScript)
			}

			if err := ensureHooksDir(filepath.Dir(hookFile)); err != nil {
				return err
			}

			if err := atomicWriteExecutable(hookFile, []byte(preCommitScript)); err != nil {
				return fmt.Errorf("write pre-commit hook: %w", err)
			}

			return ui.Success(cmd.OutOrStdout(), "Installed pre-commit hook")
		},
	}
}

func (a *App) newHookUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the envseal pre-commit hook",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			hookFile, err := a.hookPath()
			if err != nil {
				return err
			}

			lstatInfo, statErr := os.Lstat(hookFile)
			if statErr != nil {
				return fmt.Errorf("pre-commit hook not found — nothing to uninstall")
			}
			if !lstatInfo.Mode().IsRegular() {
				return fmt.Errorf("pre-commit hook path %q is not a regular file — not removing", hookFile)
			}

			//nolint:gosec // G304: hookFile was just Lstat-verified above to be a regular file.
			f, openErr := os.Open(hookFile)
			if openErr != nil {
				return fmt.Errorf("read pre-commit hook: %w", openErr)
			}
			fdInfo, fstatErr := f.Stat()
			if fstatErr != nil {
				return errors.Join(
					fmt.Errorf("stat open hook file: %w", fstatErr),
					f.Close(),
				)
			}
			if !os.SameFile(lstatInfo, fdInfo) {
				return errors.Join(
					fmt.Errorf("pre-commit hook file changed between stat and open"),
					f.Close(),
				)
			}
			data, readErr := io.ReadAll(io.LimitReader(f, 64*1024))
			closeErr := f.Close()
			if readErr != nil {
				return errors.Join(fmt.Errorf("read pre-commit hook: %w", readErr), closeErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close pre-commit hook: %w", closeErr)
			}

			if !strings.Contains(string(data), hookMarker) {
				return fmt.Errorf("pre-commit hook exists but was not installed by envseal — not removing")
			}

			if err := os.Remove(hookFile); err != nil {
				return fmt.Errorf("remove pre-commit hook: %w", err)
			}

			return ui.Success(cmd.OutOrStdout(), "Removed pre-commit hook")
		},
	}
}
