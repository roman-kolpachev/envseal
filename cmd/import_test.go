package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/roman-kolpachev/envseal/internal/vault"
)

func TestImportCommand(t *testing.T) {
	app, dir := newTestApp(t)

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1\nB=2\nC=3\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "import")
	if !strings.Contains(out, "Imported 3 secrets from .env") {
		t.Errorf("expected 'Imported 3 secrets', got: %s", out)
	}

	listOut := execApp(t, app, "list")
	for _, key := range []string{"A", "B", "C"} {
		if !strings.Contains(listOut, key) {
			t.Errorf("expected %s in vault after import", key)
		}
	}
}

func TestImportCommand_ExplicitPath(t *testing.T) {
	app, dir := newTestApp(t)

	if err := os.WriteFile(filepath.Join(dir, ".env.staging"), []byte("X=10\nY=20\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "import", ".env.staging")
	if !strings.Contains(out, "Imported 2 secrets from .env.staging") {
		t.Errorf("expected 'Imported 2 secrets from .env.staging', got: %s", out)
	}
}

func TestImportCommand_SkipsExisting(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "A=old")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=new\nB=2\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "import")
	if !strings.Contains(out, "Imported 1 secret") {
		t.Errorf("expected 'Imported 1 secret', got: %s", out)
	}
	if !strings.Contains(out, "Skipped: 1 key") {
		t.Errorf("expected skip message, got: %s", out)
	}

	val := strings.TrimSpace(execApp(t, app, "get", "A"))
	if val != "old" {
		t.Errorf("A = %q, want %q (should not be overwritten)", val, "old")
	}
}

func TestImportCommand_Force(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "A=old")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=new\nB=2\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "import", "--force")
	if !strings.Contains(out, "Imported 2 secrets") {
		t.Errorf("expected 'Imported 2 secrets', got: %s", out)
	}

	val := strings.TrimSpace(execApp(t, app, "get", "A"))
	if val != "new" {
		t.Errorf("A = %q, want %q (should be overwritten with --force)", val, "new")
	}
}

func TestImportCommand_AllExist(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "A=1")
	execApp(t, app, "set", "B=2")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1\nB=2\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "import")
	if !strings.Contains(out, "Nothing to import") {
		t.Errorf("expected 'Nothing to import', got: %s", out)
	}
}

func TestImportCommand_ConfirmOverwritePerKey(t *testing.T) {
	app, dir := newTestApp(t)
	app.deps.ConfirmOverwrite = func(key string) vault.ConflictChoice {
		if key == "A" {
			return vault.ConflictYes
		}
		return vault.ConflictNo
	}

	execApp(t, app, "set", "A=old")
	execApp(t, app, "set", "B=old")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=new\nB=new\nC=3\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "import")
	if !strings.Contains(out, "Imported 2 secrets") {
		t.Errorf("expected 'Imported 2 secrets', got: %s", out)
	}

	val := strings.TrimSpace(execApp(t, app, "get", "A"))
	if val != "new" {
		t.Errorf("A = %q, want %q", val, "new")
	}
	val = strings.TrimSpace(execApp(t, app, "get", "B"))
	if val != "old" {
		t.Errorf("B = %q, want %q (should not be overwritten)", val, "old")
	}
}

func TestImportCommand_FileNotFound(t *testing.T) {
	app, _ := newTestApp(t)

	err := execAppErr(app, "import", "nonexistent.env")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestImportCommand_InteractiveSelectsFile(t *testing.T) {
	app, dir := newTestApp(t)
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env.local"), []byte("B=2\nC=3\n"), 0600); err != nil {
		t.Fatal(err)
	}

	app.deps.SelectOption = func(prompt string, options []string) (string, error) {
		for _, o := range options {
			if o == ".env.local" {
				return ".env.local", nil
			}
		}
		t.Fatalf("expected .env.local in options, got %v", options)
		return "", nil
	}

	out := execApp(t, app, "import")
	if !strings.Contains(out, "Imported 2 secrets from .env.local") {
		t.Errorf("expected import from .env.local, got: %s", out)
	}
}

func TestImportCommand_InteractiveCustomPath(t *testing.T) {
	app, dir := newTestApp(t)
	if err := os.MkdirAll(filepath.Join(dir, "config"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config", "secrets.env"), []byte("X=10\n"), 0600); err != nil {
		t.Fatal(err)
	}

	app.deps.SelectOption = func(prompt string, options []string) (string, error) {
		return "config/secrets.env", nil
	}

	out := execApp(t, app, "import")
	if !strings.Contains(out, "Imported 1 secret from config/secrets.env") {
		t.Errorf("expected import from config/secrets.env, got: %s", out)
	}
}

func TestImportCommand_InteractiveAbsolutePath(t *testing.T) {
	app, dir := newTestApp(t)
	absFile := filepath.Join(dir, "external.env")
	if err := os.WriteFile(absFile, []byte("EXT=yes\n"), 0600); err != nil {
		t.Fatal(err)
	}

	app.deps.SelectOption = func(prompt string, options []string) (string, error) {
		return absFile, nil
	}

	out := execApp(t, app, "import")
	if !strings.Contains(out, "Imported 1 secret") {
		t.Errorf("expected import, got: %s", out)
	}

	val := strings.TrimSpace(execApp(t, app, "get", "EXT"))
	if val != "yes" {
		t.Errorf("EXT = %q, want %q", val, "yes")
	}
}

func TestImportCommand_ShowsTargetVault(t *testing.T) {
	app, dir := newTestApp(t)
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "import", ".env")
	if !strings.Contains(out, "development") {
		t.Errorf("expected target vault info with 'development', got: %s", out)
	}
}

func TestImportCommand_ShowsTargetVaultWithEnvFlag(t *testing.T) {
	app, dir := newTestApp(t)
	if err := os.WriteFile(filepath.Join(dir, ".env.staging"), []byte("A=1\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "import", "--env", "staging", ".env.staging")
	if !strings.Contains(out, "staging") {
		t.Errorf("expected target vault info with 'staging', got: %s", out)
	}
}

func TestImportCommand_InteractiveNoEnvFiles(t *testing.T) {
	app, dir := newTestApp(t)
	if err := os.WriteFile(filepath.Join(dir, "custom.env"), []byte("Z=99\n"), 0600); err != nil {
		t.Fatal(err)
	}

	app.deps.SelectOption = func(prompt string, options []string) (string, error) {
		if !strings.Contains(prompt, "No .env files found") {
			t.Errorf("expected 'No .env files found' prompt, got %q", prompt)
		}
		return "custom.env", nil
	}

	out := execApp(t, app, "import")
	if !strings.Contains(out, "Imported 1 secret from custom.env") {
		t.Errorf("expected import from custom.env, got: %s", out)
	}
}

func TestImportCommand_ExplicitPathSkipsInteractive(t *testing.T) {
	app, dir := newTestApp(t)
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env.local"), []byte("B=2\n"), 0600); err != nil {
		t.Fatal(err)
	}

	app.deps.SelectOption = func(prompt string, options []string) (string, error) {
		t.Fatal("SelectOption should not be called when path is given as argument")
		return "", nil
	}

	out := execApp(t, app, "import", ".env")
	if !strings.Contains(out, "Imported 1 secret from .env") {
		t.Errorf("expected import from .env, got: %s", out)
	}
}

func TestImportFromSops_ParsesDecryptedOutput(t *testing.T) {
	app, dir := newTestApp(t)

	sopsDecrypted := "DB_HOST=localhost\nDB_PASSWORD=s3cret\nAPI_KEY=sk-abc\n"
	decryptedFile := filepath.Join(dir, ".env.sops-decrypted")
	if err := os.WriteFile(decryptedFile, []byte(sopsDecrypted), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "import", decryptedFile)
	if !strings.Contains(out, "Imported 3 secrets") {
		t.Errorf("expected 'Imported 3 secrets', got: %s", out)
	}

	for _, key := range []string{"DB_HOST", "DB_PASSWORD", "API_KEY"} {
		listOut := execApp(t, app, "list")
		if !strings.Contains(listOut, key) {
			t.Errorf("expected %s in vault after SOPS import", key)
		}
	}

	val := strings.TrimSpace(execApp(t, app, "get", "DB_PASSWORD"))
	if val != "s3cret" {
		t.Errorf("DB_PASSWORD = %q, want %q", val, "s3cret")
	}
}

func TestImportFromSops_Flag(t *testing.T) {
	app, dir := newTestApp(t)

	fakeSops := filepath.Join(dir, "sops.bat")
	if err := os.WriteFile(fakeSops, []byte("@echo SOPS_KEY=decrypted_value"), 0755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	out := execApp(t, app, "import", "--from-sops", fakeSops)
	if !strings.Contains(out, "Imported 1 secret") {
		t.Errorf("expected 'Imported 1 secret', got: %s", out)
	}

	val := strings.TrimSpace(execApp(t, app, "get", "SOPS_KEY"))
	if val != "decrypted_value" {
		t.Errorf("SOPS_KEY = %q, want %q", val, "decrypted_value")
	}
}

func TestImportFromDotenvx_Flag(t *testing.T) {
	app, dir := newTestApp(t)

	// On Windows, exec.LookPath requires a recognised extension (.bat/.cmd/.exe).
	// Use a .bat file that prints the same output as the POSIX shell script.
	var fakeDotenvx string
	if runtime.GOOS == "windows" {
		fakeDotenvx = filepath.Join(dir, "dotenvx.bat")
		script := "@echo off\r\n" +
			"echo DOTENV_PUBLIC_KEY=\"034af93e93708b994c10f236c96ef88e47291066946cce2e8d98c9e02c741ced45\"\r\n" +
			"echo DOTENVX_KEY=\"decrypted_value\"\r\n"
		if err := os.WriteFile(fakeDotenvx, []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	} else {
		fakeDotenvx = filepath.Join(dir, "dotenvx")
		script := "#!/bin/sh\n" +
			"echo 'DOTENV_PUBLIC_KEY=\"034af93e93708b994c10f236c96ef88e47291066946cce2e8d98c9e02c741ced45\"'\n" +
			"echo 'DOTENVX_KEY=\"decrypted_value\"'\n"
		if err := os.WriteFile(fakeDotenvx, []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	out := execApp(t, app, "import", "--from-dotenvx", filepath.Join(dir, ".env"))
	if !strings.Contains(out, "Imported 1 secret") {
		t.Errorf("expected 'Imported 1 secret', got: %s", out)
	}

	val := strings.TrimSpace(execApp(t, app, "get", "DOTENVX_KEY"))
	if val != "decrypted_value" {
		t.Errorf("DOTENVX_KEY = %q, want %q", val, "decrypted_value")
	}

	listOut := execApp(t, app, "list")
	if strings.Contains(listOut, "DOTENV_PUBLIC_KEY") {
		t.Errorf("DOTENV_PUBLIC_KEY metadata should not be imported, got: %s", listOut)
	}
}

func TestImportFromDotenvx_MutuallyExclusiveWithSops(t *testing.T) {
	app, dir := newTestApp(t)

	err := execAppErr(app, "import", "--from-sops", "--from-dotenvx", filepath.Join(dir, ".env"))
	if err == nil {
		t.Fatal("expected error, got success")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutually exclusive error, got: %v", err)
	}
}
