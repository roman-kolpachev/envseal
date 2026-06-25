package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"github.com/roman-kolpachev/envseal/internal/audit"
	"github.com/roman-kolpachev/envseal/internal/config"
	"github.com/roman-kolpachev/envseal/internal/crypto"
	"github.com/roman-kolpachev/envseal/internal/keyring"
	"github.com/roman-kolpachev/envseal/internal/runner"
	"github.com/roman-kolpachev/envseal/internal/vault"
)

func newTestApp(t *testing.T) (*App, string) {
	t.Helper()
	dir := t.TempDir()

	if err := os.MkdirAll(config.VaultDirPath(dir), 0700); err != nil {
		t.Fatal(err)
	}

	id, err := keyring.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.SaveToFile(id, config.KeysPath(dir)); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default("test-project")
	if err := cfg.AddRecipient("test", id.PublicKey, false); err != nil {
		t.Fatal(err)
	}
	// requireDeps reloads config.toml from disk under the vault lock (see
	// its doc comment) rather than trusting the in-memory copy main.go
	// loaded before the lock was acquired, so — matching the real
	// invariant: deps.Config is only ever populated from a config.toml
	// that actually exists on disk — tests need one there too.
	if err := cfg.Save(config.ConfigPath(dir)); err != nil {
		t.Fatal(err)
	}

	enc := crypto.NewAgeEncryptor(id)
	vaultSvc := vault.NewService(enc, cfg)
	run := runner.New(vaultSvc)

	auditLogger := audit.NewLogger(config.AuditPath(dir))

	app := NewApp(Deps{
		Vault:   vaultSvc,
		Runner:  run,
		Keyring: id,
		Config:  cfg,
		Audit:   auditLogger,
		Dir:     dir,
	})

	// On Windows, open file handles prevent t.TempDir() cleanup from deleting
	// the directory. Write commands (mutate=true) intentionally hold the vault
	// lock until process exit; in tests the process never exits, so we release
	// it explicitly before the temp dir is removed.
	t.Cleanup(func() { app.releaseVaultLock() })

	return app, dir
}

// testGitInit runs "git init dir" so that gitHooksDir's "git rev-parse
// --git-path hooks" call succeeds. Tests that exercise hook install/uninstall
// or the init command's hook-install prompt need a real git repo, not just a
// manually created .git/hooks directory.
func testGitInit(t *testing.T, dir string) {
	t.Helper()
	out, err := exec.Command("git", "init", dir).CombinedOutput()
	if err != nil {
		t.Skipf("git init failed (%v): %s", err, out)
	}
}

func execApp(t *testing.T, app *App, args ...string) string {
	t.Helper()
	var buf bytes.Buffer
	app.root.SetOut(&buf)
	app.root.SetErr(&buf)
	app.root.SetArgs(args)
	if err := app.Execute(); err != nil {
		t.Fatalf("command %v failed: %v", args, err)
	}
	return buf.String()
}

func execAppErr(app *App, args ...string) error {
	var buf bytes.Buffer
	app.root.SetOut(&buf)
	app.root.SetErr(&buf)
	app.root.SetArgs(args)
	return app.Execute()
}
