package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/roman-kolpachev/envseal/internal/vault"
)

func TestSyncCommand(t *testing.T) {
	app, dir := newTestApp(t)

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1\nB=2\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "sync", "--source", ".env")
	if !strings.Contains(out, "Synced 2 keys") {
		t.Errorf("expected 'Synced 2 keys', got: %s", out)
	}
	if !strings.Contains(out, "+ Added: A") {
		t.Error("expected A to be added")
	}

	listOut := execApp(t, app, "list")
	if !strings.Contains(listOut, "A") || !strings.Contains(listOut, "B") {
		t.Error("expected A and B in vault after sync")
	}
}

func TestSyncMissingSourceCreatesFile(t *testing.T) {
	app, dir := newTestApp(t)
	app.deps.Confirm = func(prompt string) (bool, error) {
		return true, nil
	}

	source := filepath.Join(dir, ".env.missing")
	var buf bytes.Buffer
	app.root.SetOut(&buf)
	app.root.SetErr(&buf)
	app.root.SetArgs([]string{"sync", "--source", ".env.missing"})
	if err := app.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Source file not found") {
		t.Errorf("expected warning about missing file, got: %s", out)
	}
	if !strings.Contains(out, "Created .env.missing") {
		t.Errorf("expected creation message, got: %s", out)
	}
	if _, err := os.Stat(source); err != nil {
		t.Error("expected source file to be created")
	}
}

func TestSyncMissingSourceDeclined(t *testing.T) {
	app, dir := newTestApp(t)
	app.deps.Confirm = func(prompt string) (bool, error) {
		return false, nil
	}

	source := filepath.Join(dir, ".env.missing")
	err := execAppErr(app, "sync", "--source", ".env.missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(source); !os.IsNotExist(statErr) {
		t.Error("expected source file to NOT be created when declined")
	}
}

func TestSyncSkipsExistingWithoutCallback(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "KEY=old")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("KEY=new\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "sync", "--source", ".env")
	if !strings.Contains(out, "Unchanged: 1 key") {
		t.Errorf("expected unchanged, got: %s", out)
	}

	val := execApp(t, app, "get", "KEY")
	if strings.TrimSpace(val) != "old" {
		t.Errorf("expected 'old' (not overwritten), got %q", strings.TrimSpace(val))
	}
}

func TestSyncUsesSourceFromConfig(t *testing.T) {
	app, dir := newTestApp(t)

	// Default environment is "development" with source ".env.development"
	if err := os.WriteFile(filepath.Join(dir, ".env.development"), []byte("FROM_CONFIG=yes\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "sync")
	if !strings.Contains(out, "Synced 1 keys") {
		t.Errorf("expected 'Synced 1 keys', got: %s", out)
	}
	if !strings.Contains(out, "+ Added: FROM_CONFIG") {
		t.Errorf("expected FROM_CONFIG to be added, got: %s", out)
	}
}

func TestSyncUsesSourceFromConfigWithEnvFlag(t *testing.T) {
	app, dir := newTestApp(t)

	// Staging environment has source ".env.staging"
	if err := os.WriteFile(filepath.Join(dir, ".env.staging"), []byte("STAGE_KEY=1\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "sync", "--env", "staging")
	if !strings.Contains(out, "Synced 1 keys") {
		t.Errorf("expected 'Synced 1 keys', got: %s", out)
	}
	if !strings.Contains(out, "+ Added: STAGE_KEY") {
		t.Errorf("expected STAGE_KEY to be added, got: %s", out)
	}
}

func TestSyncWithPruneRemovesKeys(t *testing.T) {
	app, dir := newTestApp(t)
	app.deps.ConfirmOverwrite = func(key string) vault.ConflictChoice { return vault.ConflictAll }

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1\nB=2\nC=3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	execApp(t, app, "sync", "--source", ".env")

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out := execApp(t, app, "sync", "--source", ".env", "--prune")
	if !strings.Contains(out, "Removed:") {
		t.Errorf("expected removed keys with --prune, got: %s", out)
	}

	listOut := execApp(t, app, "list")
	if strings.Contains(listOut, "B") || strings.Contains(listOut, "C") {
		t.Error("B and C should be removed from vault after prune")
	}
}

func TestSyncWithoutPruneKeepsKeys(t *testing.T) {
	app, dir := newTestApp(t)
	app.deps.ConfirmOverwrite = func(key string) vault.ConflictChoice { return vault.ConflictAll }

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1\nB=2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	execApp(t, app, "sync", "--source", ".env")

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out := execApp(t, app, "sync", "--source", ".env")
	if !strings.Contains(out, "Kept 1 vault-only") {
		t.Errorf("expected kept message, got: %s", out)
	}
}

func TestSyncUpdatesExisting(t *testing.T) {
	app, dir := newTestApp(t)
	app.deps.ConfirmOverwrite = func(key string) vault.ConflictChoice { return vault.ConflictAll }

	execApp(t, app, "set", "KEY=old")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("KEY=new\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "sync", "--source", ".env")
	if !strings.Contains(out, "~ Changed: KEY") {
		t.Errorf("expected KEY to be changed, got: %s", out)
	}

	val := execApp(t, app, "get", "KEY")
	if strings.TrimSpace(val) != "new" {
		t.Errorf("expected 'new', got %q", strings.TrimSpace(val))
	}
}
