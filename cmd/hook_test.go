package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestHookInstall(t *testing.T) {
	app, dir := newTestApp(t)
	testGitInit(t, dir)

	out := execApp(t, app, "hook", "install")
	if !strings.Contains(out, "Installed pre-commit hook") {
		t.Errorf("expected install success message, got %q", out)
	}

	hookPath := filepath.Join(dir, ".git", "hooks", "pre-commit")
	data, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("hook file not created: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, ".envseal/keys") {
		t.Error("hook should check for .envseal/keys")
	}
	if !strings.Contains(content, "envseal") {
		t.Error("hook should mention envseal")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(hookPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0111 == 0 {
			t.Error("hook file should be executable")
		}
	}
}

func TestHookInstallAlreadyExists(t *testing.T) {
	app, dir := newTestApp(t)
	testGitInit(t, dir)

	execApp(t, app, "hook", "install")

	out := execApp(t, app, "hook", "install")
	if !strings.Contains(out, "already installed") {
		t.Errorf("expected already-installed message, got %q", out)
	}
}

func TestHookInstallExistingHookNoMarker(t *testing.T) {
	app, dir := newTestApp(t)
	testGitInit(t, dir)

	hookPath := filepath.Join(dir, ".git", "hooks", "pre-commit")
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\necho existing\n"), 0755); err != nil {
		t.Fatal(err)
	}

	err := execAppErr(app, "hook", "install")
	if err == nil {
		t.Error("expected error when pre-commit hook already exists without envseal marker")
	}
}

func TestHookUninstall(t *testing.T) {
	app, dir := newTestApp(t)
	testGitInit(t, dir)

	execApp(t, app, "hook", "install")

	out := execApp(t, app, "hook", "uninstall")
	if !strings.Contains(out, "Removed pre-commit hook") {
		t.Errorf("expected uninstall success message, got %q", out)
	}

	hookPath := filepath.Join(dir, ".git", "hooks", "pre-commit")
	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Error("hook file should be removed after uninstall")
	}
}

func TestHookUninstallNotInstalled(t *testing.T) {
	app, dir := newTestApp(t)
	testGitInit(t, dir)

	execApp(t, app, "hook", "install")
	if err := os.Remove(filepath.Join(dir, ".git", "hooks", "pre-commit")); err != nil {
		t.Fatal(err)
	}

	err := execAppErr(app, "hook", "uninstall")
	if err == nil {
		t.Error("expected error when hook not installed")
	}
}

func TestHookInstallNoGitDir(t *testing.T) {
	app, _ := newTestApp(t)

	err := execAppErr(app, "hook", "install")
	if err == nil {
		t.Error("expected error when .git directory does not exist")
	}
}
