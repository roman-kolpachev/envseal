package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/roman-kolpachev/envseal/internal/config"
)

func TestInitCommand(t *testing.T) {
	dir := t.TempDir()
	app := NewApp(Deps{Dir: dir})

	out := execApp(t, app, "init", "--name", "test-project")

	if _, err := os.Stat(config.ConfigPath(dir)); err != nil {
		t.Error("config.toml not created")
	}
	if _, err := os.Stat(config.KeysPath(dir)); err != nil {
		t.Error("keys not created")
	}
	if _, err := os.Stat(filepath.Join(dir, config.VaultFilePath("development"))); err != nil {
		t.Error("development.vault not created")
	}

	keysRel := config.DirName + "/" + config.KeysFile
	data, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Error(".gitignore not created")
	} else if !strings.Contains(string(data), keysRel) {
		t.Error(".gitignore doesn't contain " + keysRel)
	}

	if !strings.Contains(out, "Generated age keypair") {
		t.Error("expected keypair generation message")
	}
	if !strings.Contains(out, "Public key") {
		t.Error("expected public key in output")
	}
}

func TestInitRefusesWhenAlreadyInitialized(t *testing.T) {
	dir := t.TempDir()
	app := NewApp(Deps{Dir: dir})

	execApp(t, app, "init")

	err := execAppErr(app, "init")
	if err == nil {
		t.Error("expected error on second init")
	}
}

func TestInitForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	app := NewApp(Deps{Dir: dir})

	execApp(t, app, "init")

	oldKey, _ := os.ReadFile(config.KeysPath(dir))

	out := execApp(t, app, "init", "--force")
	if !strings.Contains(out, "Generated age keypair") {
		t.Error("expected success message on force init")
	}

	newKey, _ := os.ReadFile(config.KeysPath(dir))
	if string(oldKey) == string(newKey) {
		t.Error("expected new keypair after force init")
	}
}

func TestInitRefusesListsExistingFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(config.DirPath(dir), 0700); err != nil {
		t.Fatal(err)
	}

	app := NewApp(Deps{Dir: dir})
	err := execAppErr(app, "init")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), config.DirName) {
		t.Errorf("expected error to mention %s, got: %v", config.DirName, err)
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("expected error to mention --force, got: %v", err)
	}
}

func TestInitIdempotentGitignore(t *testing.T) {
	dir := t.TempDir()
	keysRel := config.DirName + "/" + config.KeysFile
	keysGlob := keysRel + ".*"
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(keysRel+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	app := NewApp(Deps{Dir: dir})
	execApp(t, app, "init")

	data, _ := os.ReadFile(filepath.Join(dir, ".gitignore"))
	// Count exact-line matches (not substrings) to distinguish keys vs keys.*
	countExact := func(content, pattern string) int {
		n := 0
		for _, line := range strings.Split(content, "\n") {
			if strings.TrimSpace(line) == pattern {
				n++
			}
		}
		return n
	}
	if n := countExact(string(data), keysRel); n != 1 {
		t.Errorf("expected %s once in .gitignore, got %d", keysRel, n)
	}
	if n := countExact(string(data), keysGlob); n != 1 {
		t.Errorf("expected %s once in .gitignore, got %d", keysGlob, n)
	}
}

func TestInitInstallsHookWhenConfirmed(t *testing.T) {
	dir := t.TempDir()
	testGitInit(t, dir)

	app := NewApp(Deps{
		Dir: dir,
		Confirm: func(prompt string) (bool, error) {
			return true, nil
		},
	})

	out := execApp(t, app, "init")
	if !strings.Contains(out, "Installed pre-commit hook") {
		t.Errorf("expected hook install message, got %q", out)
	}

	hookPath := filepath.Join(dir, ".git", "hooks", "pre-commit")
	if _, err := os.Stat(hookPath); err != nil {
		t.Error("pre-commit hook not created")
	}
}

func TestInitSkipsHookWhenDeclined(t *testing.T) {
	dir := t.TempDir()
	testGitInit(t, dir)

	app := NewApp(Deps{
		Dir: dir,
		Confirm: func(prompt string) (bool, error) {
			return false, nil
		},
	})

	out := execApp(t, app, "init")
	if strings.Contains(out, "Installed pre-commit hook") {
		t.Error("should not install hook when declined")
	}

	hookPath := filepath.Join(dir, ".git", "hooks", "pre-commit")
	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Error("hook should not be created when declined")
	}
}

func TestInitSkipsHookPromptWithNoGitDir(t *testing.T) {
	dir := t.TempDir()

	confirmCalled := false
	app := NewApp(Deps{
		Dir: dir,
		Confirm: func(prompt string) (bool, error) {
			confirmCalled = true
			return true, nil
		},
	})

	execApp(t, app, "init")
	if confirmCalled {
		t.Error("should not ask about hook when .git directory doesn't exist")
	}
}

func TestInitSkipsHookPromptWithNoConfirm(t *testing.T) {
	dir := t.TempDir()
	testGitInit(t, dir)

	app := NewApp(Deps{Dir: dir, Confirm: nil})

	out := execApp(t, app, "init")
	if strings.Contains(out, "Installed pre-commit hook") {
		t.Error("should not install hook when Confirm is nil")
	}
}
