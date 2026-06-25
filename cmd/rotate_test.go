package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/roman-kolpachev/envseal/internal/config"
)

func TestRotateCommand(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "SECRET=value")

	oldKey, _ := os.ReadFile(config.KeysPath(dir))

	out := execApp(t, app, "rotate")
	if !strings.Contains(out, "Generated new keypair") {
		t.Errorf("expected success message, got %q", out)
	}
	if !strings.Contains(out, "Re-encrypted 1 secret") && !strings.Contains(out, "Re-encrypted 1 secret across") {
		t.Errorf("expected re-encryption message, got %q", out)
	}

	newKey, _ := os.ReadFile(config.KeysPath(dir))
	if string(oldKey) == string(newKey) {
		t.Error("expected new private key after rotate")
	}
}

func TestRotatePreservesSecrets(t *testing.T) {
	app, _ := newTestApp(t)

	execApp(t, app, "set", "A=1")
	execApp(t, app, "set", "B=2")

	execApp(t, app, "rotate")

	valA := strings.TrimSpace(execApp(t, app, "get", "A"))
	valB := strings.TrimSpace(execApp(t, app, "get", "B"))

	if valA != "1" {
		t.Errorf("expected A=1 after rotate, got %q", valA)
	}
	if valB != "2" {
		t.Errorf("expected B=2 after rotate, got %q", valB)
	}
}

func TestRotateEmptyVault(t *testing.T) {
	app, _ := newTestApp(t)

	out := execApp(t, app, "rotate")
	if !strings.Contains(out, "Re-encrypted 0 secrets") && !strings.Contains(out, "0 secrets across") {
		t.Errorf("expected 0 secrets message, got %q", out)
	}
}
