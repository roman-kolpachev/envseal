package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/roman-kolpachev/envseal/internal/keyring"
)

func TestGrantAndRevoke(t *testing.T) {
	app, _ := newTestApp(t)
	execApp(t, app, "set", "SECRET=value")

	id2, err := keyring.Generate()
	if err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "grant", "alice", "--key", id2.PublicKey)
	if !strings.Contains(out, "Granted access to alice") {
		t.Error("expected grant success message")
	}
	if !strings.Contains(out, "Re-encrypted") {
		t.Error("expected re-encryption message")
	}

	val := execApp(t, app, "get", "SECRET")
	if strings.TrimSpace(val) != "value" {
		t.Errorf("expected 'value' after grant, got %q", strings.TrimSpace(val))
	}

	out = execApp(t, app, "revoke", "alice")
	if !strings.Contains(out, "Revoked access for alice") {
		t.Error("expected revoke success message")
	}
	if !strings.Contains(out, "Remember to rotate") {
		t.Error("expected rotation warning")
	}

	val = execApp(t, app, "get", "SECRET")
	if strings.TrimSpace(val) != "value" {
		t.Errorf("expected 'value' after revoke, got %q", strings.TrimSpace(val))
	}
}

func TestGrantFromKeyFile(t *testing.T) {
	app, dir := newTestApp(t)
	execApp(t, app, "set", "SECRET=value")

	id2, err := keyring.Generate()
	if err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(dir, "alice.pub")
	if writeErr := os.WriteFile(keyFile, []byte(id2.PublicKey+"\n"), 0600); writeErr != nil {
		t.Fatal(writeErr)
	}

	out := execApp(t, app, "grant", "alice", "--key-file", keyFile)
	if !strings.Contains(out, "Granted access to alice") {
		t.Error("expected grant success from key-file")
	}
}

func TestGrantMissingKey(t *testing.T) {
	app, _ := newTestApp(t)

	err := execAppErr(app, "grant", "alice")
	if err == nil {
		t.Error("expected error when no key provided")
	}
}

func TestRevokeNonExistentRecipient(t *testing.T) {
	app, _ := newTestApp(t)

	id2, err := keyring.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err = app.deps.Config.AddRecipient("extra", id2.PublicKey, false); err != nil {
		t.Fatal(err)
	}

	err = execAppErr(app, "revoke", "ghost")
	if err == nil {
		t.Fatal("expected error when revoking non-existent recipient")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got: %v", err)
	}
}

func TestRevokeLastRecipient(t *testing.T) {
	app, _ := newTestApp(t)
	execApp(t, app, "set", "SECRET=value")

	err := execAppErr(app, "revoke", "test")
	if err == nil {
		t.Fatal("expected error when revoking the last recipient")
	}
	if !strings.Contains(err.Error(), "last recipient") {
		t.Errorf("expected 'last recipient' error, got: %v", err)
	}
}

func TestGrantInvalidKeyFormat(t *testing.T) {
	app, _ := newTestApp(t)

	err := execAppErr(app, "grant", "alice", "--key", "not-a-valid-age-key")
	if err == nil {
		t.Fatal("expected error for invalid age key")
	}
	if !strings.Contains(err.Error(), "invalid age public key") {
		t.Errorf("expected 'invalid age public key' error, got: %v", err)
	}
}
