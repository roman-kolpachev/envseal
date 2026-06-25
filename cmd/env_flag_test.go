package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/roman-kolpachev/envseal/internal/config"
)

func TestEnvFlagOverridesDefault(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "SECRET=value")

	stagingVault := filepath.Join(dir, config.VaultFilePath("staging"))
	if _, err := os.Stat(stagingVault); err == nil {
		t.Fatal("staging vault should not exist before -e staging")
	}

	execApp(t, app, "-e", "staging", "set", "STAGING_SECRET=staging_value")

	if _, err := os.Stat(stagingVault); err != nil {
		t.Error("staging vault should exist after -e staging set")
	}
}

func TestEnvFlagSyncUsesCorrectSource(t *testing.T) {
	app, dir := newTestApp(t)

	if err := os.WriteFile(filepath.Join(dir, ".env.staging"), []byte("STAGE_KEY=stage_val\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "-e", "staging", "sync")
	if !strings.Contains(out, "Synced 1 keys") {
		t.Errorf("expected 'Synced 1 keys', got: %s", out)
	}
}

func TestEnvFlagDiffUsesCorrectSource(t *testing.T) {
	app, dir := newTestApp(t)

	if err := os.WriteFile(filepath.Join(dir, ".env.staging"), []byte("NEW_KEY=value\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "-e", "staging", "diff")
	if !strings.Contains(out, "added") {
		t.Errorf("expected 'added' for NEW_KEY, got: %s", out)
	}
}

func TestEnvFlagInvalidEnvironment(t *testing.T) {
	app, _ := newTestApp(t)

	err := execAppErr(app, "-e", "nonexistent", "set", "KEY=val")
	if err == nil {
		t.Error("expected error for nonexistent environment")
	}
}

func TestEnvFlagIsolatesVaultData(t *testing.T) {
	app, _ := newTestApp(t)

	execApp(t, app, "-e", "development", "set", "DEV_SECRET=dev_value")
	execApp(t, app, "-e", "staging", "set", "STAGING_SECRET=staging_value")

	devList := execApp(t, app, "-e", "development", "list")
	if !strings.Contains(devList, "DEV_SECRET") {
		t.Error("expected DEV_SECRET in development vault")
	}
	if strings.Contains(devList, "STAGING_SECRET") {
		t.Error("STAGING_SECRET leaked into development vault")
	}

	stagingList := execApp(t, app, "-e", "staging", "list")
	if !strings.Contains(stagingList, "STAGING_SECRET") {
		t.Error("expected STAGING_SECRET in staging vault")
	}
	if strings.Contains(stagingList, "DEV_SECRET") {
		t.Error("DEV_SECRET leaked into staging vault")
	}
}

func TestEnvFlagImportIsolatesVaults(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "-e", "development", "set", "DEV_KEY=dev")

	if err := os.WriteFile(filepath.Join(dir, ".env.staging"), []byte("STAGE_IMPORTED=yes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	execApp(t, app, "-e", "staging", "import", ".env.staging")

	devList := execApp(t, app, "-e", "development", "list")
	if strings.Contains(devList, "STAGE_IMPORTED") {
		t.Error("staging import leaked into development vault")
	}

	stagingList := execApp(t, app, "-e", "staging", "list")
	if !strings.Contains(stagingList, "STAGE_IMPORTED") {
		t.Error("expected STAGE_IMPORTED in staging vault")
	}
	if strings.Contains(stagingList, "DEV_KEY") {
		t.Error("DEV_KEY leaked into staging vault")
	}
}

func TestEnvFlagSyncIsolatesVaults(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "-e", "development", "set", "DEV_ONLY=123")

	if err := os.WriteFile(filepath.Join(dir, ".env.staging"), []byte("STAGE_SYNCED=abc\n"), 0600); err != nil {
		t.Fatal(err)
	}
	execApp(t, app, "-e", "staging", "sync")

	devList := execApp(t, app, "-e", "development", "list")
	if strings.Contains(devList, "STAGE_SYNCED") {
		t.Error("staging sync leaked into development vault")
	}
	if !strings.Contains(devList, "DEV_ONLY") {
		t.Error("DEV_ONLY should still be in development vault")
	}
}

func TestEnvFlagDoesNotChangeConfig(t *testing.T) {
	app, _ := newTestApp(t)

	execApp(t, app, "-e", "staging", "set", "KEY=val")

	if app.deps.Config.Default != "development" {
		t.Errorf("expected default to remain 'development', got %q", app.deps.Config.Default)
	}
}
