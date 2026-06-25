package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/roman-kolpachev/envseal/internal/config"
)

func TestKeygenCommand(t *testing.T) {
	app, dir := newTestApp(t)

	if err := os.Remove(config.KeysPath(dir)); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	out := execApp(t, app, "keygen")

	keysRel := filepath.Join(config.DirName, config.KeysFile)
	if !strings.Contains(out, "Generated age keypair") {
		t.Error("expected success message")
	}
	if !strings.Contains(out, "Public key") {
		t.Error("expected public key in output")
	}
	if !strings.Contains(out, "age1") {
		t.Error("expected age1 prefix in public key")
	}
	if !strings.Contains(out, "saved to "+keysRel) {
		t.Error("expected private key saved message")
	}

	data, err := os.ReadFile(config.KeysPath(dir))
	if err != nil {
		t.Fatalf("expected keys file to exist: %v", err)
	}
	if !strings.HasPrefix(string(data), "AGE-SECRET-KEY-") {
		t.Error("expected private key in keys file")
	}
}

func TestKeygenRefusesToOverwrite(t *testing.T) {
	app, _ := newTestApp(t)

	err := execAppErr(app, "keygen")
	if err == nil {
		t.Error("expected error when keys file already exists")
	}
}
