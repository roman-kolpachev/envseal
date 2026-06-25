package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/roman-kolpachev/envseal/internal/audit"
	"github.com/roman-kolpachev/envseal/internal/config"
	"github.com/roman-kolpachev/envseal/internal/fileutil"
	"github.com/roman-kolpachev/envseal/internal/keyring"
	"github.com/roman-kolpachev/envseal/internal/runner"
	"github.com/roman-kolpachev/envseal/internal/ui"
	"github.com/roman-kolpachev/envseal/internal/vault"
)

type Deps struct {
	Vault      *vault.Service
	Runner     *runner.Runner
	Keyring    *keyring.Identity
	Config     *config.Config
	Audit      *audit.Logger
	Dir string
	// InvocationDir is the literal directory the process was invoked from,
	// before any upward project-directory discovery (see
	// config.FindProjectDir). Dir may be an ancestor of InvocationDir when
	// the command was run from a subdirectory of an initialized project —
	// every command except `init` should resolve paths against Dir (the
	// discovered project root); `init` must use InvocationDir instead, since
	// its whole purpose is creating a new project at the exact directory the
	// user asked for, not being silently redirected to an existing ancestor
	// project (which would also incorrectly block a deliberate, independent
	// nested project, e.g. a monorepo package with its own vault). Left
	// empty, commands fall back to Dir — this keeps tests that only set Dir
	// unaffected.
	InvocationDir    string
	Version          string
	ReadSecret       func(prompt string) ([]byte, error)
	Confirm          func(prompt string) (bool, error)
	ConfirmOverwrite vault.OnConflict
	SelectOption     func(prompt string, options []string) (string, error)
}

type App struct {
	root *cobra.Command
	deps Deps
	// vaultLock, once acquired, is held for the remainder of the process
	// (released automatically on exit) rather than explicitly unlocked —
	// see requireDeps.
	vaultLock *os.File
}

func NewApp(deps Deps) *App {
	a := &App{deps: deps}
	a.root = a.buildRoot()
	return a
}

func (a *App) Execute() error {
	return a.root.Execute()
}

func (a *App) workDir() (string, error) {
	if a.deps.Dir != "" {
		return a.deps.Dir, nil
	}
	return os.Getwd()
}

// invocationDir returns the literal directory the process was invoked from
// (see the Deps.InvocationDir doc comment). Only `init` should call this —
// every other command should use workDir, which resolves against the
// discovered project root instead.
func (a *App) invocationDir() (string, error) {
	if a.deps.InvocationDir != "" {
		return a.deps.InvocationDir, nil
	}
	return a.workDir()
}

// requireDeps loads the vault for the resolved environment, holding a
// project-wide lock across the call. mutate must be true for any command
// that will persist a change afterward (via saveVault or a direct
// vault.Service.Save — see grant/revoke/rotate) and false for a command that
// only reads.
//
// The lock is project-wide, not per-environment: grant/revoke/rotate load
// and re-encrypt every configured environment's vault in a single invocation
// (see reEncryptAllVaults, rotate.go), so a lock scoped to only the resolved
// environment would leave those other files unprotected. Without it,
// concurrent invocations race a plain read-modify-write cycle — each reads
// the vault, decrypts, adds its own change, and atomically overwrites the
// file — so the last writer's version silently wins and discards every
// other process's change, with every process still reporting success.
//
// mutate=true leaves the lock held for the rest of the process (the OS
// reclaims it on exit) so the eventual save can't race another writer's.
// mutate=false releases it before returning, right here in one place, rather
// than requiring every read-only call site to remember a separate release
// call — a call site that forgets is exactly how run --sealed ended up
// blocking every other envseal invocation on the project for as long as its
// child process ran: it decrypts once from the already-loaded in-memory
// vault and then blocks waiting on a real child process (unlike the default
// mode's syscall.Exec, which replaces the process image and so implicitly
// drops the lock via Go's default close-on-exec fds), so holding the lock
// past the load serves no purpose for it and costs every concurrent command.
func (a *App) requireDeps(cmd *cobra.Command, mutate bool) error {
	if a.deps.Vault == nil || a.deps.Config == nil {
		return fmt.Errorf("not initialized — run `envseal init` first")
	}
	dir, err := a.workDir()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}
	if a.vaultLock == nil {
		lock, lockErr := fileutil.Lock(filepath.Join(config.DirPath(dir), "lock"))
		if lockErr != nil {
			return fmt.Errorf("acquire vault lock: %w", lockErr)
		}
		a.vaultLock = lock
	}
	// Guard against junction attacks at the .envseal/ level. The per-write
	// RequireRealDir checks in vault.Service.Save and saveAllVaults inspect
	// only .envseal/vault/ — os.Lstat on that path follows through a junction
	// planted at .envseal/ and sees the real vault/ dir inside the decoy, so
	// the per-write check passes. Checking the envseal directory itself here,
	// after the lock is held and before any vault I/O, closes the gap: a
	// junction at .envseal/ carries ModeSymlink in Lstat results on all
	// platforms (junctions on Windows, symlinks everywhere else).
	if dirErr := fileutil.RequireRealDir(config.DirPath(dir)); dirErr != nil {
		return fmt.Errorf("envseal directory: %w", dirErr)
	}
	if !mutate {
		defer a.releaseVaultLock()
	}

	// Reload config.toml fresh from disk now that the lock is held.
	// main.go loads it once at process startup, long before any lock is
	// acquired — a config-mutating command (grant/revoke/rotate/env
	// add/use) that ran and saved its change to disk while this process
	// was waiting for the lock would otherwise be invisible to it: this
	// process would go on mutating its own stale, pre-lock in-memory copy
	// of the recipient/environment list and overwrite the other process's
	// change with it when it eventually saves. Concretely: two `grant`
	// calls fired at the same time, both starting from the same on-disk
	// config, both reporting "✓ Granted access to ..." — but only the
	// last one to save wins, so the first grantee silently isn't actually
	// in the recipient list (or the vault's wrapped keys) despite the
	// success message. The vault lock's fresh Load below already avoided
	// this for vault *contents*; config.toml needed the same treatment.
	freshCfg, cfgErr := config.Load(config.ConfigPath(dir))
	if cfgErr != nil {
		return fmt.Errorf("reload config: %w", cfgErr)
	}
	a.deps.Config = freshCfg
	a.deps.Vault = vault.NewService(a.deps.Vault.Encryptor(), freshCfg)
	// Runner holds the *old* vault.Service instance directly (see
	// runner.New in main.go) rather than going through a.deps.Vault each
	// time, so replacing the latter above — a fresh object, not a mutation
	// of the original in place — leaves Runner decrypting from a Service
	// whose Load() is never called again. run/run --sealed would silently
	// use stale, pre-lock vault contents and the stale config's recipient
	// set forever. Point it at the fresh Service too.
	a.deps.Runner = runner.New(a.deps.Vault)

	env, err := a.resolveEnvironment(cmd)
	if err != nil {
		return err
	}
	// Bind the service to the resolved environment BEFORE loading: Load
	// rejects a vault file recorded for a different environment, and every
	// entry encrypted from here on embeds this name in its ciphertext (and
	// every decrypt verifies it) — see vault.SetEnvironment.
	if err := a.deps.Vault.SetEnvironment(a.resolveEnvironmentName(cmd)); err != nil {
		return err
	}
	vaultPath, err := safePath(dir, env.VaultPath)
	if err != nil {
		return err
	}
	if verbose, _ := cmd.Flags().GetBool("verbose"); verbose {
		// --verbose is declared globally (every command's --help lists it
		// under "Global Flags"), but until now only import's --from-sops/
		// --from-dotenvx error paths actually consulted it — everywhere
		// else the flag was silently accepted and did nothing, despite its
		// help text promising general "verbose output". requireDeps is the
		// one place every vault-touching command already passes through, so
		// reporting the resolved project directory and vault path here
		// makes the flag meaningfully global instead of two narrow special
		// cases, and is genuinely useful now that commands are discovered
		// from an ancestor directory (see config.FindProjectDir) rather
		// than always matching the literal invocation directory — a user
		// running from a subdirectory can no longer just assume which
		// project or vault file they're actually operating against.
		_ = ui.Info(cmd.ErrOrStderr(), fmt.Sprintf("using project directory %s, vault %s", dir, vaultPath))
	}
	a.deps.Vault.Reset()
	// Load itself rejects a vault whose recorded environment differs from the
	// binding set above (and, cryptographically, every entry decrypt verifies
	// the environment embedded in its plaintext), so no separate post-load
	// environment check is needed here anymore.
	loadErr := a.deps.Vault.Load(vaultPath)
	if loadErr != nil && !errors.Is(loadErr, vault.ErrVaultNotFound) {
		return fmt.Errorf("load vault: %w", loadErr)
	}
	return nil
}

// releaseVaultLock releases the vault lock acquired by requireDeps.
func (a *App) releaseVaultLock() {
	if a.vaultLock == nil {
		return
	}
	if err := a.vaultLock.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: release vault lock: %v\n", err)
	}
	a.vaultLock = nil
}

func safePath(base, rel string) (string, error) {
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("absolute path not allowed in config: %q", rel)
	}
	joined := filepath.Join(base, rel)
	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("resolve base: %w", err)
	}

	if realBase, evalErr := filepath.EvalSymlinks(absBase); evalErr == nil {
		absBase = realBase
	}
	if realJoined, evalErr := filepath.EvalSymlinks(absJoined); evalErr == nil {
		absJoined = realJoined
	} else if realDir, evalErr := filepath.EvalSymlinks(filepath.Dir(absJoined)); evalErr == nil {
		absJoined = filepath.Join(realDir, filepath.Base(absJoined))
	}

	prefix := absBase + string(filepath.Separator)
	if runtime.GOOS == "windows" {
		if !strings.HasPrefix(strings.ToLower(absJoined), strings.ToLower(prefix)) && !strings.EqualFold(absJoined, absBase) {
			return "", fmt.Errorf("path %q escapes project directory", rel)
		}
	} else {
		if !strings.HasPrefix(absJoined, prefix) && absJoined != absBase {
			return "", fmt.Errorf("path %q escapes project directory", rel)
		}
	}
	return joined, nil
}

// maxUserPathLength is the maximum byte length accepted for user-supplied paths.
// On Windows without long-path support, filepath.Abs truncates paths beyond
// MAX_PATH (260), which can cause the containment check in safePath to pass
// for a path that resolves differently at the OS level.
const maxUserPathLength = 4096

func safeUserPath(base, userPath string) (string, error) {
	if len(userPath) > maxUserPathLength {
		return "", fmt.Errorf("path too long (%d bytes, maximum %d)", len(userPath), maxUserPathLength)
	}
	if filepath.IsAbs(userPath) {
		// Absolute paths bypass project-directory containment. Print a visible
		// warning so accidental use in pipelines is discoverable in logs.
		fmt.Fprintf(os.Stderr, "warning: using absolute path %q outside the project directory — ensure this is intentional\n", userPath)
		return filepath.Clean(userPath), nil
	}
	return safePath(base, userPath)
}

func (a *App) resolveEnvironmentName(cmd *cobra.Command) string {
	envFlag, _ := cmd.Flags().GetString("env")
	if envFlag != "" {
		return envFlag
	}
	if a.deps.Config == nil {
		return ""
	}
	return a.deps.Config.Default
}

func (a *App) resolveEnvironment(cmd *cobra.Command) (config.Environment, error) {
	name := a.resolveEnvironmentName(cmd)
	if name == "" {
		return config.Environment{}, fmt.Errorf("no environment specified — use --env or set default_env in config")
	}
	if err := config.ValidateEnvironmentName(name); err != nil {
		return config.Environment{}, fmt.Errorf("invalid --env flag: %w", err)
	}
	return a.deps.Config.GetEnvironment(name)
}

func (a *App) saveVault(cmd *cobra.Command) error {
	dir, err := a.workDir()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}
	env, err := a.resolveEnvironment(cmd)
	if err != nil {
		return err
	}
	vaultPath, err := safePath(dir, env.VaultPath)
	if err != nil {
		return err
	}
	return a.deps.Vault.Save(vaultPath, a.resolveEnvironmentName(cmd))
}

func (a *App) auditLog(action, message string, keys ...string) {
	if a.deps.Audit == nil {
		return
	}
	e := audit.Event{
		Action:  action,
		Message: message,
		Keys:    keys,
	}
	if a.deps.Keyring != nil {
		e.Actor = a.deps.Keyring.PublicKey
	}
	if err := a.deps.Audit.Log(e); err != nil {
		fmt.Fprintf(os.Stderr, "warning: audit log: %v\n", err)
	}
}

func (a *App) auditLogWithTarget(action, target, message string) {
	if a.deps.Audit == nil {
		return
	}
	e := audit.Event{
		Action:  action,
		Target:  target,
		Message: message,
	}
	if a.deps.Keyring != nil {
		e.Actor = a.deps.Keyring.PublicKey
	}
	if err := a.deps.Audit.Log(e); err != nil {
		fmt.Fprintf(os.Stderr, "warning: audit log: %v\n", err)
	}
}

func (a *App) resolveSourcePath(cmd *cobra.Command) (string, error) {
	env, err := a.resolveEnvironment(cmd)
	if err != nil {
		return "", err
	}
	source, _ := cmd.Flags().GetString("source")
	dir, err := a.workDir()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	if source != "" {
		return safeUserPath(dir, source)
	}
	return safePath(dir, env.SourcePath)
}

func (a *App) saveConfig() error {
	dir, err := a.workDir()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}
	return a.deps.Config.Save(config.ConfigPath(dir))
}

func (a *App) reEncryptAllVaults(ctx context.Context, dir string, newRecipients []string) (map[string]*vault.Service, int, error) {
	totalSecrets := 0
	envVaults := make(map[string]*vault.Service)

	for envName, envCfg := range a.deps.Config.Environments {
		vaultPath, pathErr := safePath(dir, envCfg.VaultPath)
		if pathErr != nil {
			return nil, 0, fmt.Errorf("invalid vault path for %q: %w", envName, pathErr)
		}
		svc := vault.NewService(a.deps.Vault.Encryptor(), a.deps.Config)
		// Bind before Load: Load verifies the file's recorded environment
		// against this binding, and ReEncryptAll embeds it into every
		// re-encrypted entry's plaintext.
		if err := svc.SetEnvironment(envName); err != nil {
			return nil, 0, fmt.Errorf("invalid environment name %q: %w", envName, err)
		}
		if loadErr := svc.Load(vaultPath); loadErr != nil {
			if errors.Is(loadErr, vault.ErrVaultNotFound) {
				continue
			}
			return nil, 0, fmt.Errorf("load vault for %q: %w", envName, loadErr)
		}

		if err := svc.ReEncryptAll(ctx, newRecipients); err != nil {
			return nil, 0, fmt.Errorf("re-encrypt %q: %w", envName, err)
		}

		keys, _ := svc.List()
		totalSecrets += len(keys)
		envVaults[envName] = svc
	}

	return envVaults, totalSecrets, nil
}

// saveAllVaults writes every vault in vaults as a single all-or-nothing
// unit: every file is staged to a temp file first, and only once every one
// has staged successfully are any of them committed (renamed into place).
//
// This matters specifically for grant/revoke/rotate, which call this to
// persist a re-encryption spanning every configured environment in one
// invocation (see reEncryptAllVaults). Saving each vault as its own
// independent write — as this used to do — meant a failure partway through
// (e.g. one environment's vault directory being read-only) left environments
// processed before the failure already re-encrypted for the new recipient
// set and the rest still on the old one, while the caller's subsequent
// saveConfig() call never ran (config.toml, the source of truth for who
// should have access, matched neither state). For revoke specifically, that
// silently left the revoked recipient with continued access to whichever
// environments hadn't been reached yet — with an error message that gave no
// indication some environments had already changed, inviting an operator to
// read "it failed" as "nothing happened" and not go verify per-environment
// access. Staging every vault before committing any of them collapses the
// failure window down to the commit (rename) phase, which is far smaller and
// far less likely to fail than the writes it replaces.
func (a *App) saveAllVaults(dir string, vaults map[string]*vault.Service) (err error) {
	type staged struct {
		tmpPath   string
		finalPath string
		envName   string
	}
	var stagedFiles []staged
	defer func() {
		if err != nil {
			for _, s := range stagedFiles {
				// Best-effort: err is already non-nil here (the operation is
				// failing regardless), so a cleanup failure can't be joined
				// into it without masking which one is the real cause. But
				// silently dropping it would leave an operator with no way to
				// know a stray, still-encrypted temp file may be sitting in
				// .envseal/vault/ — warn instead, matching how this codebase
				// treats every other cleanup-on-error-path failure.
				if cerr := fileutil.AbortWrite(s.tmpPath); cerr != nil {
					fmt.Fprintf(os.Stderr, "warning: clean up staged vault for %q: %v\n", s.envName, cerr)
				}
			}
		}
	}()

	for envName, svc := range vaults {
		envCfg := a.deps.Config.Environments[envName]
		vaultPath, pathErr := safePath(dir, envCfg.VaultPath)
		if pathErr != nil {
			return fmt.Errorf("invalid vault path for %q: %w", envName, pathErr)
		}
		data, marshalErr := svc.Marshal(envName)
		if marshalErr != nil {
			return fmt.Errorf("marshal vault for %q: %w", envName, marshalErr)
		}
		// Same symlinked-directory refusal as vault.Service.Save: a redirected
		// staged write would commit the re-encrypted vault outside the repo
		// while this grant/revoke/rotate still reports success.
		if dirErr := fileutil.RequireRealDir(filepath.Dir(vaultPath)); dirErr != nil {
			return fmt.Errorf("vault directory for %q: %w", envName, dirErr)
		}
		tmpPath, stageErr := fileutil.StageWrite(vaultPath, data, 0600, ".envseal-tmp-*")
		if stageErr != nil {
			return fmt.Errorf("stage vault for %q (no vaults were modified): %w", envName, stageErr)
		}
		stagedFiles = append(stagedFiles, staged{tmpPath: tmpPath, finalPath: vaultPath, envName: envName})
	}

	for _, s := range stagedFiles {
		if commitErr := fileutil.CommitWrite(s.tmpPath, s.finalPath); commitErr != nil {
			return fmt.Errorf(
				"commit vault for %q: %w (WARNING: other environments in this operation may already be committed — verify recipient access per environment before assuming nothing changed)",
				s.envName, commitErr,
			)
		}
	}

	return nil
}

func (a *App) buildRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "envseal",
		Short:         "Encrypt .env secrets, store in git, inject at runtime",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringP("env", "e", "", "environment (default from config)")
	root.PersistentFlags().BoolP("verbose", "v", false, "verbose output")

	root.AddCommand(
		a.newInitCmd(),
		a.newKeygenCmd(),
		a.newSetCmd(),
		a.newGetCmd(),
		a.newRunCmd(),
		a.newImportCmd(),
		a.newPullCmd(),
		a.newSyncCmd(),
		a.newListCmd(),
		a.newRmCmd(),
		a.newDiffCmd(),
		a.newExportCmd(),
		a.newEnvCmd(),
		a.newRotateCmd(),
		a.newAuditCmd(),
		a.newGrantCmd(),
		a.newRevokeCmd(),
		a.newVersionCmd(),
		a.newCompletionCmd(),
		a.newHookCmd(),
	)

	return root
}
