package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/roman-kolpachev/envseal/internal/config"
	"github.com/roman-kolpachev/envseal/internal/crypto"
	"github.com/roman-kolpachev/envseal/internal/fileutil"
	"github.com/roman-kolpachev/envseal/internal/ui"
	"github.com/roman-kolpachev/envseal/internal/vault"
)

func (a *App) newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize envseal in the current directory",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			// invocationDir, not workDir: init must always target the exact
			// directory it was run from, never get silently redirected to an
			// ancestor project's root the way every other command now is
			// (see Deps.InvocationDir) — otherwise running `init` from a
			// subdirectory of an already-initialized project would either
			// refuse ("already initialized", pointing at the ancestor) or,
			// worse, incorrectly initialize a fresh project there instead of
			// at the directory the user actually asked for.
			dir, err := a.invocationDir()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			if verbose, _ := cmd.Flags().GetBool("verbose"); verbose {
				if err := ui.Info(cmd.ErrOrStderr(), fmt.Sprintf("initializing at %s", dir)); err != nil {
					return err
				}
			}

			// Serialize concurrent `init` invocations across the whole
			// check-then-write sequence below: without this, two processes
			// can both pass the "not already initialized" check before
			// either finishes, each generating and reporting a different
			// keypair to the user, with only the last writer's version
			// surviving in the final config — silently invalidating the
			// public key any earlier process printed. This can't reuse the
			// vault lock at .envseal/lock (cmd/root.go, requireDeps): that
			// path doesn't exist until after the very check this needs to
			// guard, and unconditionally creating .envseal/ just to host the
			// lock would make every fresh init see itself as already
			// initialized.
			initLock, err := fileutil.Lock(filepath.Join(dir, ".envseal.lock"))
			if err != nil {
				return fmt.Errorf("acquire init lock: %w", err)
			}
			defer func() {
				if cerr := initLock.Close(); cerr != nil {
					err = errors.Join(err, fmt.Errorf("release init lock: %w", cerr))
				}
			}()

			force, _ := cmd.Flags().GetBool("force")
			envsealDir := config.DirPath(dir)
			if info, err := os.Lstat(envsealDir); err == nil {
				if info.Mode()&os.ModeSymlink != 0 {
					return fmt.Errorf("%s is a symlink — refusing to initialize for security", config.DirName)
				}
				if !force {
					return fmt.Errorf("already initialized — found %s/. Use --force to overwrite", config.DirName)
				}
			}

			if err := os.MkdirAll(config.VaultDirPath(dir), 0700); err != nil {
				return fmt.Errorf("create %s directory: %w", config.DirName, err)
			}
			if postInfo, postErr := os.Lstat(envsealDir); postErr == nil {
				if !postInfo.IsDir() || postInfo.Mode()&os.ModeSymlink != 0 {
					return fmt.Errorf("%s is not a regular directory — refusing to initialize for security", config.DirName)
				}
			}
			vaultDir := config.VaultDirPath(dir)
			if vaultInfo, vaultErr := os.Lstat(vaultDir); vaultErr == nil {
				if !vaultInfo.IsDir() || vaultInfo.Mode()&os.ModeSymlink != 0 {
					return fmt.Errorf("%s/%s is not a regular directory — refusing to initialize for security", config.DirName, config.VaultDir)
				}
			}

			name, _ := cmd.Flags().GetString("name")
			if name == "" {
				name = filepath.Base(dir)
			}
			// Validate up front with the same rule config.Load enforces:
			// writing an unvalidated name (from --name or a pathological
			// directory name) would produce a config.toml that every
			// subsequent Load rejects, bricking the fresh project.
			if err := config.ValidateProjectName(name); err != nil {
				return fmt.Errorf("invalid project name: %w (use --name to set one explicitly)", err)
			}

			id, err := a.generateAndSaveKey(dir, force)
			if err != nil {
				return err
			}

			cfg := config.Default(name)
			if err := cfg.AddRecipient("default", id.PublicKey, false); err != nil {
				return err
			}
			if err := cfg.Save(config.ConfigPath(dir)); err != nil {
				return err
			}

			enc := crypto.NewAgeEncryptor(id)
			vaultSvc := vault.NewService(enc, cfg)
			// Bind the fresh (empty) vault to its environment so Save records
			// it and any future entries are encrypted with it embedded.
			if err := vaultSvc.SetEnvironment(cfg.Default); err != nil {
				return err
			}
			vaultPath := filepath.Join(dir, cfg.CurrentEnvironment().VaultPath)
			if err := vaultSvc.Save(vaultPath, cfg.Default); err != nil {
				return err
			}

			keysRel := config.DirName + "/" + config.KeysFile
			if err := appendToGitignore(dir, keysRel); err != nil {
				return err
			}
			// Also protect key rotation temp files (e.g. keys.new left after a
			// failed rotate) from being accidentally committed.
			keysGlob := config.DirName + "/" + config.KeysFile + ".*"
			if err := appendToGitignore(dir, keysGlob); err != nil {
				return err
			}
			// The cross-process vault lock file (see requireDeps in root.go)
			// is host-local coordination state, not project data.
			lockRel := config.DirName + "/lock"
			if err := appendToGitignore(dir, lockRel); err != nil {
				return err
			}
			// Same for this command's own init-time lock (see above) — it
			// lives outside .envseal/ since it must be acquirable before that
			// directory exists.
			if err := appendToGitignore(dir, ".envseal.lock"); err != nil {
				return err
			}
			// The audit log's own cross-process lock (internal/audit/logger.go's
			// Log): audit.log itself is committed alongside the vault, but this
			// sibling coordination file is host-local like the others above.
			auditLockRel := config.DirName + "/" + config.AuditFile + ".lock"
			if err := appendToGitignore(dir, auditLockRel); err != nil {
				return err
			}
			// Vault saves (vault.Service.Save and saveAllVaults, the
			// multi-environment path grant/revoke/rotate use) stage to a
			// ".envseal-tmp-*" file in this directory before renaming it into
			// place. That temp file normally lives for a moment, but on a
			// cleanup-on-error-path failure it can be orphaned — still fully
			// age-encrypted, never plaintext, but still not something that
			// should end up committed via a stray `git add -A`.
			vaultTmpGlob := config.DirName + "/" + config.VaultDir + "/.envseal-tmp-*"
			if err := appendToGitignore(dir, vaultTmpGlob); err != nil {
				return err
			}
			// Protect decrypted secret files too: `envseal pull` (and hand-edited
			// sources) write plaintext into files like .env / .env.production, and
			// those must never be committed alongside the encrypted *.vault files.
			// Template/example/sample files are conventionally checked in, so they
			// are explicitly un-ignored — mirrors discovery.excludedSuffixes.
			for _, entry := range []string{".env", ".env.*", "!.env.example", "!.env.sample", "!.env.template"} {
				if err := appendToGitignore(dir, entry); err != nil {
					return err
				}
			}

			w := cmd.OutOrStdout()
			if err := ui.Success(w, "Generated age keypair"); err != nil {
				return err
			}
			if err := ui.KeyValue(w, "Public key", id.PublicKey); err != nil {
				return err
			}
			if err := ui.KeyValue(w, "Private key", "saved to "+keysRel); err != nil {
				return err
			}
			if err := ui.Success(w, "Created "+filepath.Join(config.DirName, config.ConfigFile)); err != nil {
				return err
			}
			if err := ui.Success(w, "Added "+keysRel+" to .gitignore"); err != nil {
				return err
			}

			gitDir := filepath.Join(dir, ".git")
			if info, err := os.Lstat(gitDir); err == nil && info.IsDir() && a.deps.Confirm != nil {
				if yes, err := a.deps.Confirm("Install pre-commit hook to protect " + keysRel + "? [Y/n] "); err == nil && yes {
					if err := a.installHook(dir, w); err != nil {
						return err
					}
				}
			}

			return ui.Success(w, "Ready! Run `envseal set KEY=VALUE` to add secrets.")
		},
	}

	cmd.Flags().String("name", "", "project name (default: directory name)")
	cmd.Flags().Bool("force", false, "overwrite existing config, vault, and keys")
	return cmd
}

func appendToGitignore(dir, entry string) (err error) {
	path := filepath.Join(dir, ".gitignore")

	var data []byte
	if lstatInfo, statErr := os.Lstat(path); statErr == nil {
		if !lstatInfo.Mode().IsRegular() {
			return fmt.Errorf(".gitignore at %q is not a regular file", path)
		}
		//nolint:gosec // G304: path is the fixed ".gitignore" file under the project dir, just Lstat-verified above to be a regular file.
		f, openErr := os.Open(path)
		if openErr != nil {
			return fmt.Errorf("read .gitignore: %w", openErr)
		}
		fdInfo, fstatErr := f.Stat()
		if fstatErr != nil {
			return errors.Join(
				fmt.Errorf("stat open .gitignore: %w", fstatErr),
				f.Close(),
			)
		}
		if !os.SameFile(lstatInfo, fdInfo) {
			return errors.Join(
				fmt.Errorf(".gitignore changed between stat and open"),
				f.Close(),
			)
		}
		readData, readErr := io.ReadAll(f)
		closeErr := f.Close()
		if readErr != nil {
			return errors.Join(fmt.Errorf("read .gitignore: %w", readErr), closeErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close .gitignore: %w", closeErr)
		}
		data = readData
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("stat .gitignore: %w", statErr)
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == entry {
			return nil
		}
	}

	if lstatInfo, statErr := os.Lstat(path); statErr == nil && !lstatInfo.Mode().IsRegular() {
		return fmt.Errorf(".gitignore at %q is not a regular file", path)
	}

	//nolint:gosec // G302: .gitignore intentionally stays world-readable (0644) like any normal git-tracked file — it holds only glob patterns, never secret material (unlike the 0600 keys/vault/config files elsewhere in this codebase).
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open .gitignore: %w", err)
	}

	defer func() {
		if cerr := f.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}()

	fdInfo, statErr := f.Stat()
	if statErr != nil {
		return fmt.Errorf("stat .gitignore after open: %w", statErr)
	}
	if !fdInfo.Mode().IsRegular() {
		return fmt.Errorf(".gitignore is not a regular file")
	}
	if postLstat, lstatErr := os.Lstat(path); lstatErr == nil {
		if !os.SameFile(fdInfo, postLstat) {
			return fmt.Errorf(".gitignore was replaced between read and write")
		}
	}

	prefix := ""
	if len(data) > 0 && data[len(data)-1] != '\n' {
		prefix = "\n"
	}

	_, err = fmt.Fprintf(f, "%s%s\n", prefix, entry)
	return err
}
