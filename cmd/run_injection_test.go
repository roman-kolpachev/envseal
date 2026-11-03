package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/roman-kolpachev/envseal/internal/crypto"
	"github.com/roman-kolpachev/envseal/internal/keyring"
)

// forgeEntries models the reported attack: someone who can land a change to
// the committed vault but holds none of its private keys. They encrypt
// entries to the recipients' public keys (committed in config.toml) with an
// identity of their own and add them to the vault file.
func forgeEntries(t *testing.T, app *App, dir string, entries map[string]string) {
	t.Helper()

	attacker, err := keyring.Generate()
	if err != nil {
		t.Fatal(err)
	}
	enc := crypto.NewAgeEncryptor(attacker)
	env := app.deps.Config.CurrentEnvironment()
	vaultPath := filepath.Join(dir, env.VaultPath)

	data, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	var existing map[string]json.RawMessage
	if err := json.Unmarshal(raw["entries"], &existing); err != nil {
		t.Fatal(err)
	}

	for key, value := range entries {
		// Entry plaintext framing from docs/vault-format.md:
		// <environment> 0x00 <key> 0x00 <value>.
		framed := []byte(app.deps.Config.Default + "\x00" + key + "\x00" + value)
		ciphertext, err := enc.Encrypt(framed, app.deps.Config.RecipientKeys())
		if err != nil {
			t.Fatal(err)
		}
		entry, err := json.Marshal(map[string]string{"encrypted": ciphertext})
		if err != nil {
			t.Fatal(err)
		}
		existing[key] = entry
	}

	entriesJSON, err := json.Marshal(existing)
	if err != nil {
		t.Fatal(err)
	}
	raw["entries"] = entriesJSON
	forged, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultPath, forged, 0600); err != nil {
		t.Fatal(err)
	}
}

// The fsmonitor command is a harmless "true": the tests assert the refusal,
// and must not run anything real on a developer machine if the check ever
// regresses (an attacker's value would be e.g. a command reading
// /proc/self/environ).
var gitConfigInjectionEntries = map[string]string{
	"GIT_CONFIG_COUNT":   "1",
	"GIT_CONFIG_KEY_0":   "core.fsmonitor",
	"GIT_CONFIG_VALUE_0": "true",
}

// TestForgedGitConfigEntriesDecrypt is the control for the tests below: it
// proves the forged entries pass decryption and the integrity binding, so the
// dangerous-name check is the only thing standing between them and git.
func TestForgedGitConfigEntriesDecrypt(t *testing.T) {
	app, dir := newTestApp(t)
	execApp(t, app, "set", "DB_PASSWORD=hunter2")
	forgeEntries(t, app, dir, gitConfigInjectionEntries)

	out := execApp(t, app, "get", "GIT_CONFIG_KEY_0")
	if !strings.Contains(out, "core.fsmonitor") {
		t.Fatalf("forged entry did not decrypt as genuine, got %q", out)
	}
}

func TestRunRefusesForgedGitConfigInjection(t *testing.T) {
	for _, sealed := range []bool{false, true} {
		name := "env"
		if sealed {
			name = "sealed"
		}
		t.Run(name, func(t *testing.T) {
			app, dir := newTestApp(t)
			execApp(t, app, "set", "DB_PASSWORD=hunter2")
			forgeEntries(t, app, dir, gitConfigInjectionEntries)

			args := []string{"run"}
			if sealed {
				args = append(args, "--sealed")
			}
			args = append(args, "--", "git", "status")

			err := execAppErr(app, args...)
			if err == nil {
				t.Fatal("run -- git status accepted a vault with GIT_CONFIG_* entries")
			}
			if !strings.Contains(err.Error(), "dangerous") {
				t.Errorf("expected a dangerous-variable refusal, got: %v", err)
			}
		})
	}
}

func TestPullRefusesForgedGitConfigInjection(t *testing.T) {
	app, dir := newTestApp(t)
	execApp(t, app, "set", "DB_PASSWORD=hunter2")
	forgeEntries(t, app, dir, gitConfigInjectionEntries)

	err := execAppErr(app, "pull")
	if err == nil || !strings.Contains(err.Error(), "dangerous") {
		t.Fatalf("pull: want a dangerous-variable refusal, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, ".env.development")); statErr == nil {
		t.Error("pull wrote .env.development despite refusing")
	}
}

func TestExportRefusesForgedGitConfigInjection(t *testing.T) {
	app, dir := newTestApp(t)
	execApp(t, app, "set", "DB_PASSWORD=hunter2")
	forgeEntries(t, app, dir, gitConfigInjectionEntries)

	err := execAppErr(app, "export")
	if err == nil || !strings.Contains(err.Error(), "dangerous") {
		t.Fatalf("export: want a dangerous-variable refusal, got: %v", err)
	}
}

func TestRunRefusesForgedNpmScriptShell(t *testing.T) {
	app, dir := newTestApp(t)
	execApp(t, app, "set", "DB_PASSWORD=hunter2")
	forgeEntries(t, app, dir, map[string]string{"NPM_CONFIG_SCRIPT_SHELL": "/tmp/evil"})

	err := execAppErr(app, "run", "--", "npm", "run", "deploy")
	if err == nil || !strings.Contains(err.Error(), "dangerous") {
		t.Fatalf("run -- npm run deploy: want a dangerous-variable refusal, got: %v", err)
	}
}
