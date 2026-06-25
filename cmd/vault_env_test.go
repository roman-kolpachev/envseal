package cmd

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/roman-kolpachev/envseal/internal/vault"
)

// TestVaultEnvironmentBinding_LoadRejectsSwappedFile verifies detection of
// whole-file swaps at the cmd integration level: a vault saved for one
// environment must be rejected by Load when the service is bound to another.
// (The per-entry ciphertext binding provides the authoritative check at
// decrypt time; this exercises the fast pre-decryption path.)
func TestVaultEnvironmentBinding_LoadRejectsSwappedFile(t *testing.T) {
	svc := vault.NewService(nil, nil)
	if err := svc.SetEnvironment("staging"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "staging.vault")
	if err := svc.Save(path, "staging"); err != nil {
		t.Fatal(err)
	}

	matching := vault.NewService(nil, nil)
	if err := matching.SetEnvironment("staging"); err != nil {
		t.Fatal(err)
	}
	if err := matching.Load(path); err != nil {
		t.Errorf("matching environment should load, got: %v", err)
	}

	swapped := vault.NewService(nil, nil)
	if err := swapped.SetEnvironment("production"); err != nil {
		t.Fatal(err)
	}
	err := swapped.Load(path)
	if err == nil {
		t.Fatal("mismatched environment should be rejected — vault file may have been swapped")
	}
	if !strings.Contains(err.Error(), "staging") || !strings.Contains(err.Error(), "production") {
		t.Errorf("error should name both environments, got: %v", err)
	}
}

// TestVaultEnvironmentBinding_SetEnvironmentValidatesName: the binding uses
// the same validation rule as config environment names, so a service can
// never be bound to (and thus never encrypt for) a malformed name.
func TestVaultEnvironmentBinding_SetEnvironmentValidatesName(t *testing.T) {
	svc := vault.NewService(nil, nil)
	if err := svc.SetEnvironment("prod uction"); err == nil {
		t.Error("SetEnvironment should reject a name with invalid characters")
	}
	if err := svc.SetEnvironment(""); err == nil {
		t.Error("SetEnvironment should reject an empty name")
	}
}
