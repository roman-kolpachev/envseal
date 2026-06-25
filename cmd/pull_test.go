package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/roman-kolpachev/envseal/internal/dotenv"
)

func TestPullCommand(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "DB_HOST=localhost")
	execApp(t, app, "set", "DB_PASS=secret")

	out := execApp(t, app, "pull")
	if !strings.Contains(out, "Pulled 2 secrets") {
		t.Errorf("expected pull message, got %q", out)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".env.development"))
	if err != nil {
		t.Fatalf("expected .env to exist: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "DB_HOST=localhost") {
		t.Error("expected DB_HOST in .env")
	}
	if !strings.Contains(content, "DB_PASS=secret") {
		t.Error("expected DB_PASS in .env")
	}
}

func TestPullWithEnvFlag(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "KEY=val")

	out := execApp(t, app, "-e", "staging", "pull")
	if !strings.Contains(out, ".env.staging") {
		t.Errorf("expected .env.staging in output, got %q", out)
	}

	if _, err := os.Stat(filepath.Join(dir, ".env.staging")); err != nil {
		t.Error("expected .env.staging to exist")
	}
}

func TestPullWithOutputFlag(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "KEY=val")

	customPath := filepath.Join(dir, ".env.local")
	out := execApp(t, app, "pull", "-o", customPath)
	if !strings.Contains(out, ".env.local") {
		t.Errorf("expected .env.local in output, got %q", out)
	}

	data, err := os.ReadFile(customPath)
	if err != nil {
		t.Fatalf("expected .env.local to exist: %v", err)
	}
	if !strings.Contains(string(data), "KEY=val") {
		t.Error("expected KEY=val in .env.local")
	}
}

func TestPullEmptyVault(t *testing.T) {
	app, _ := newTestApp(t)

	out := execApp(t, app, "pull")
	if !strings.Contains(out, "Pulled 0 secrets") {
		t.Errorf("expected 0 secrets message, got %q", out)
	}
}

func TestPullBlocksDangerousKeysInTamperedVault(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "SAFE_VAR=ok")

	vaultPath := filepath.Join(dir, app.deps.Config.CurrentEnvironment().VaultPath)

	data, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(raw["entries"], &entries); err != nil {
		t.Fatal(err)
	}

	entries["LD_PRELOAD"] = entries["SAFE_VAR"]
	entriesJSON, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	raw["entries"] = entriesJSON
	tampered, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultPath, tampered, 0600); err != nil {
		t.Fatal(err)
	}

	err = execAppErr(app, "pull")
	if err == nil {
		t.Fatal("pull should reject vault containing dangerous key LD_PRELOAD")
	}
	if !strings.Contains(err.Error(), "dangerous") {
		t.Errorf("expected 'dangerous' in error, got: %v", err)
	}

	envFile := filepath.Join(dir, ".env.development")
	if _, statErr := os.Stat(envFile); statErr == nil {
		envData, _ := os.ReadFile(envFile)
		if strings.Contains(string(envData), "LD_PRELOAD") {
			t.Error(".env file should NOT contain LD_PRELOAD")
		}
	}
}

func TestPullMultilineValue(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "CERT=line1\nline2\nline3")
	execApp(t, app, "set", "SIMPLE=hello")
	execApp(t, app, "pull")

	data, err := os.ReadFile(filepath.Join(dir, ".env.development"))
	if err != nil {
		t.Fatalf("expected .env to exist: %v", err)
	}

	// Re-parse the written file to verify roundtrip
	entries, err := dotenv.Parse(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("failed to parse pulled .env: %v", err)
	}

	found := map[string]string{}
	for _, e := range entries {
		found[e.Key] = string(e.Value)
	}

	if found["CERT"] != "line1\nline2\nline3" {
		t.Errorf("multiline roundtrip failed: got %q", found["CERT"])
	}
	if found["SIMPLE"] != "hello" {
		t.Errorf("simple value roundtrip failed: got %q", found["SIMPLE"])
	}
}
