package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/roman-kolpachev/envseal/internal/dotenv"
	"github.com/roman-kolpachev/envseal/internal/envcheck"
)

type SecretProvider interface {
	DecryptAll(ctx context.Context) (map[string][]byte, error)
}

type Runner struct {
	provider SecretProvider
}

func New(provider SecretProvider) *Runner {
	return &Runner{provider: provider}
}

func (r *Runner) Env(ctx context.Context) ([]string, error) {
	secrets, err := r.provider.DecryptAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("decrypt secrets: %w", err)
	}
	defer clearByteMap(secrets)

	// Validate all secrets before touching any state.
	for k := range secrets {
		if envcheck.IsDangerous(k) {
			return nil, fmt.Errorf("secret %q overrides a dangerous system variable — refusing to inject (remove it from the vault or set it directly in your environment)", k)
		}
	}
	if err := checkSecretKeyCollisions(secrets); err != nil {
		return nil, err
	}

	osEnv := os.Environ()
	env := make([]string, 0, len(osEnv)+len(secrets))

	// Copy the OS environment, skipping internal vars and keys that will be
	// overridden by a secret so that no duplicate entries appear.
	isSecretKey := secretKeyLookup(secrets)
	for _, e := range osEnv {
		k, _, _ := strings.Cut(e, "=")
		if strings.EqualFold(k, "ENVSEAL_KEY") || strings.EqualFold(k, "ENVSEAL_SECRETS") {
			continue
		}
		if isSecretKey(k) {
			continue
		}
		// Clone rather than reuse e: os.Environ() strings alias the process's
		// real environment block, and clearEnvSlice (deferred by every caller
		// of Env) zeros string bytes in place via unsafe — without this clone,
		// that zeroing corrupts the process's actual environment (e.g. wipes
		// PATH) whenever Run/RunSealed return through an error path instead
		// of the syscall.Exec success path that never returns.
		env = append(env, strings.Clone(e))
	}

	// Append secrets as "KEY=VALUE". Assemble each entry via a []byte buffer
	// so that only one immutable string copy per secret is created (in the
	// env slice itself); the intermediate buffer is zeroed immediately.
	for k, v := range secrets {
		entry := make([]byte, 0, len(k)+1+len(v))
		entry = append(entry, k...)
		entry = append(entry, '=')
		entry = append(entry, v...)
		env = append(env, string(entry))
		clear(entry)
	}

	return env, nil
}

func (r *Runner) SealedEnv(ctx context.Context) (env []string, secretsFile string, err error) {
	secrets, err := r.provider.DecryptAll(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt secrets: %w", err)
	}
	defer clearByteMap(secrets)

	// Validate everything BEFORE touching any state (matching Env()'s
	// invariant): a dangerous or colliding key must fail before a temp file
	// is ever created, not after — otherwise a rejected run still leaves a
	// freshly created (if empty) secrets file to clean up on the error path,
	// and validation ordering should never depend on filesystem side effects
	// having already happened.
	if err := checkSecretKeyCollisions(secrets); err != nil {
		return nil, "", err
	}
	for k := range secrets {
		if envcheck.IsDangerous(k) {
			return nil, "", fmt.Errorf("secret %q overrides a dangerous system variable — refusing to inject (remove it from the vault or set it directly in your environment)", k)
		}
	}

	tmpDir, err := secureTempDir()
	if err != nil {
		return nil, "", fmt.Errorf("resolve temp directory: %w", err)
	}
	f, err := os.CreateTemp(tmpDir, ".envseal-*")
	if err != nil {
		return nil, "", fmt.Errorf("create secrets file: %w", err)
	}
	secretsFile = f.Name()

	if err := f.Chmod(0600); err != nil {
		return nil, "", errors.Join(
			fmt.Errorf("set secrets file permissions: %w", err),
			f.Close(),
			os.Remove(secretsFile),
		)
	}

	entries := make([]dotenv.Entry, 0, len(secrets))
	for k, v := range secrets {
		entries = append(entries, dotenv.Entry{Key: k, Value: v})
	}
	data := dotenv.Marshal(entries)
	defer clear(data)

	// On failures after data may have reached the file, wipe before deleting
	// (secureRemove) instead of plain os.Remove: a partial write can already
	// have placed plaintext secrets on disk, and unlinking alone leaves those
	// sectors recoverable — the same reason the success path in RunSealed wipes.
	if _, err := f.Write(data); err != nil {
		cerr := f.Close()
		secureRemove(secretsFile)
		return nil, "", errors.Join(fmt.Errorf("write secrets file: %w", err), cerr)
	}
	if err := f.Sync(); err != nil {
		cerr := f.Close()
		secureRemove(secretsFile)
		return nil, "", errors.Join(fmt.Errorf("sync secrets file: %w", err), cerr)
	}
	if err := f.Close(); err != nil {
		secureRemove(secretsFile)
		return nil, "", fmt.Errorf("close secrets file: %w", err)
	}

	// Build env slice using []byte buffers so that only one immutable string
	// copy per entry is created (in the slice itself); buffers are zeroed
	// immediately. This matches the pattern in Env() and reduces the window
	// during which environment values live as heap strings.
	type kv struct{ k, v string }
	osEnv := os.Environ()
	pairs := make([]kv, 0, len(osEnv)+1)
	for _, e := range osEnv {
		k, v, _ := strings.Cut(e, "=")
		if strings.EqualFold(k, "ENVSEAL_KEY") || strings.EqualFold(k, "ENVSEAL_SECRETS") {
			continue
		}
		pairs = append(pairs, kv{k, v})
	}
	pairs = append(pairs, kv{"ENVSEAL_SECRETS", secretsFile})

	env = make([]string, 0, len(pairs))
	for _, p := range pairs {
		entry := make([]byte, 0, len(p.k)+1+len(p.v))
		entry = append(entry, p.k...)
		entry = append(entry, '=')
		entry = append(entry, p.v...)
		env = append(env, string(entry))
		clear(entry)
	}
	return env, secretsFile, nil
}

// execProcessFunc is indirected through a variable (rather than calling
// execProcess directly) so tests can substitute a stand-in: on Unix,
// execProcess runs syscall.Exec, which replaces the calling process image on
// success and never returns — invoked directly from a test, that silently
// kills the test binary mid-suite and every test after it never runs, while
// go test still reports the package as passing (the binary's replacement
// process, e.g. echo, exits 0).
var execProcessFunc = execProcess

func (r *Runner) Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command specified")
	}

	env, err := r.Env(ctx)
	if err != nil {
		return err
	}
	defer clearEnvSlice(env)

	binary, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("command not found: %s: %w", args[0], err)
	}

	return execProcessFunc(ctx, binary, args, env)
}

// secretKeyLookup returns a predicate reporting whether an OS environment
// variable name collides with a vault secret key. Windows treats environment
// variable names case-insensitively, so an OS entry "Foo" must be considered
// a collision with secret "FOO" there — otherwise both land in the child's
// environment block and which one wins is undefined, allowing an ambient OS
// variable to shadow an injected secret.
func secretKeyLookup(secrets map[string][]byte) func(string) bool {
	if runtime.GOOS != "windows" {
		return func(k string) bool {
			_, ok := secrets[k]
			return ok
		}
	}
	upper := make(map[string]struct{}, len(secrets))
	for k := range secrets {
		upper[strings.ToUpper(k)] = struct{}{}
	}
	return func(k string) bool {
		_, ok := upper[strings.ToUpper(k)]
		return ok
	}
}

// checkSecretKeyCollisions rejects vaults containing two secret keys that
// differ only by letter case when running on Windows, where environment
// variable names are case-insensitive. Injecting both (e.g. "TOKEN" and
// "token") would leave undefined which value the child process sees,
// enabling silent value confusion.
func checkSecretKeyCollisions(secrets map[string][]byte) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	seen := make(map[string]string, len(secrets))
	for k := range secrets {
		upper := strings.ToUpper(k)
		if prev, ok := seen[upper]; ok {
			return fmt.Errorf("secrets %q and %q differ only by letter case — Windows environment variables are case-insensitive, so only one would take effect; remove one of them from the vault", prev, k)
		}
		seen[upper] = k
	}
	return nil
}

func clearByteMap(m map[string][]byte) {
	for k, v := range m {
		clear(v)
		delete(m, k)
	}
}

func clearEnvSlice(env []string) {
	for i := range env {
		if n := len(env[i]); n > 0 {
			// Zero the underlying bytes of each dynamically-allocated env string.
			// All entries are created at runtime (never string literals), so
			// mutating their underlying storage via unsafe is safe.
			//nolint:gosec // G103: audited — see comment above; required to zero secret env values, which Go strings otherwise can never scrub from heap.
			clear(unsafe.Slice(unsafe.StringData(env[i]), n))
		}
		env[i] = ""
	}
	clear(env)
}

func (r *Runner) RunSealed(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command specified")
	}

	env, secretsFile, err := r.SealedEnv(ctx)
	if err != nil {
		return err
	}
	defer clearEnvSlice(env)

	var cleanupOnce sync.Once
	cleanup := func() {
		secureRemove(secretsFile)
	}

	done := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, cleanupSignals()...)
	defer func() {
		cleanupOnce.Do(cleanup)
		signal.Stop(sigCh)
		close(done)
	}()

	go func() {
		select {
		case <-sigCh:
			cleanupOnce.Do(cleanup)
		case <-done:
		}
	}()

	binary, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("command not found: %s: %w", args[0], err)
	}

	//nolint:gosec // G204: executing the user-specified command is this tool's entire purpose ("envseal run -- CMD"); binary is resolved via exec.LookPath, not passed through a shell.
	cmd := exec.CommandContext(ctx, binary, args[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func secureTempDir() (string, error) {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		//nolint:gosec // G703: dir is this process's own XDG_RUNTIME_DIR, read for a metadata-only Lstat (no open/read/write, doesn't follow symlinks); validateTempDirSecurity/validateTempDirOwnership below must both pass before it's ever used, so a hostile value just falls through to userTempDir() rather than being trusted.
		info, err := os.Lstat(dir)
		// validateTempDirOwnership closes a Windows-specific gap: FileMode
		// permission bits are advisory there (Chmod toggles only the read-only
		// attribute), so the real protection for the secrets file created in
		// this directory is the directory's DACL. Without the ownership check
		// an attacker who pre-created a world-writable directory at
		// XDG_RUNTIME_DIR could read the sealed secrets file.
		if err == nil && info.IsDir() && validateTempDirSecurity(info) && validateTempDirOwnership(dir) == nil {
			return dir, nil
		}
	}
	return userTempDir()
}

// secureRemove overwrites the file with zeros before deleting.
// This is best-effort: COW filesystems (btrfs, ZFS, APFS), SSD wear-leveling,
// and filesystem journaling may retain the original data on the storage medium.
func secureRemove(path string) {
	lstatInfo, err := os.Lstat(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "warning: failed to stat secrets file for wipe: %v\n", err)
		}
		return
	}
	if !lstatInfo.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "warning: secrets path %s is not a regular file — removing without wipe\n", path)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "warning: failed to remove secrets path: %v\n", err)
		}
		return
	}

	//nolint:gosec // G304: path was just Lstat-verified above to be a regular file; this wipes the sealed-secrets temp file this package itself created.
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "warning: failed to open secrets file for wipe: %v\n", err)
		}
		return
	}

	fdInfo, err := f.Stat()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to stat open secrets file: %v\n", err)
		if cerr := f.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close secrets file: %v\n", cerr)
		}
		return
	}
	if !os.SameFile(lstatInfo, fdInfo) {
		fmt.Fprintf(os.Stderr, "warning: secrets file changed between stat and open — skipping wipe\n")
		if cerr := f.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close secrets file: %v\n", cerr)
		}
		return
	}

	const maxWipeSize = 64 * 1024 * 1024 // 64 MiB
	switch {
	case fdInfo.Size() > maxWipeSize:
		// Never skip silently: a sealed secrets file CAN exceed this cap
		// (vault limits allow up to 10000 entries of 1 MiB each), and the
		// operator deserves to know its plaintext was deleted without being
		// overwritten — every other failure in this function warns too. The
		// cap itself stays: cleanup runs on signal delivery, where writing
		// gigabytes of zeros would stall process shutdown indefinitely.
		fmt.Fprintf(os.Stderr,
			"warning: secrets file is %d bytes (wipe limit %d) — removing without zeroing; its plaintext may remain recoverable on disk\n",
			fdInfo.Size(), int64(maxWipeSize))
	case fdInfo.Size() > 0:
		zeros := make([]byte, fdInfo.Size())
		if _, err := f.WriteAt(zeros, 0); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to zero secrets file: %v\n", err)
		}
		if err := f.Sync(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to sync zeroed secrets file: %v\n", err)
		}
	}

	if cerr := f.Close(); cerr != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to close secrets file: %v\n", cerr)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "warning: failed to remove secrets file: %v\n", err)
	}
}
