package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/roman-kolpachev/envseal/internal/config"
)

func TestRunNoCommand(t *testing.T) {
	app, _ := newTestApp(t)

	err := execAppErr(app, "run", "--")
	if err == nil {
		t.Error("expected error when no command specified")
	}
	if err != nil && !strings.Contains(err.Error(), "no command specified") {
		t.Errorf("expected 'no command specified' error, got: %v", err)
	}
}

func TestRunWithoutSeparator(t *testing.T) {
	app, _ := newTestApp(t)

	err := execAppErr(app, "run")
	if err == nil {
		t.Error("expected error when no command specified")
	}
}

func TestRunWithEnvFlag(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "-e", "staging", "set", "STAGING_VAR=staging_value")

	stagingVault := filepath.Join(dir, config.VaultFilePath("staging"))
	if _, err := os.Stat(stagingVault); err != nil {
		t.Fatalf("staging vault should exist: %v", err)
	}

	echoCmd := "echo"
	if runtime.GOOS == "windows" {
		echoCmd = "cmd"
	}

	err := execAppErr(app, "run", "-e", "staging", "--", echoCmd, "hello")
	if err != nil && strings.Contains(err.Error(), "no command specified") {
		t.Error("run -e staging -- echo hello: should parse -e flag, got 'no command specified'")
	}
	if err != nil && strings.Contains(err.Error(), "command not found: -e") {
		t.Error("run -e staging -- echo hello: -e was treated as the command instead of a flag")
	}
}

func TestRunWithEnvLongFlag(t *testing.T) {
	app, _ := newTestApp(t)

	execApp(t, app, "-e", "staging", "set", "KEY=val")

	echoCmd := "echo"
	if runtime.GOOS == "windows" {
		echoCmd = "cmd"
	}

	err := execAppErr(app, "run", "--env", "staging", "--", echoCmd, "hello")
	if err != nil && strings.Contains(err.Error(), "command not found: --env") {
		t.Error("run --env staging -- echo hello: --env was treated as the command instead of a flag")
	}
}

func TestRunSealedFlag(t *testing.T) {
	app, _ := newTestApp(t)

	execApp(t, app, "set", "SECRET=sealed_test")

	echoCmd := "echo"
	if runtime.GOOS == "windows" {
		echoCmd = "cmd"
	}

	err := execAppErr(app, "run", "--sealed", "--", echoCmd, "hello")
	if err != nil && strings.Contains(err.Error(), "command not found: --sealed") {
		t.Error("--sealed was treated as the command instead of a flag")
	}
}

func TestRunSealedWithEnvFlag(t *testing.T) {
	app, _ := newTestApp(t)

	execApp(t, app, "-e", "staging", "set", "STAGING_SECRET=val")

	echoCmd := "echo"
	if runtime.GOOS == "windows" {
		echoCmd = "cmd"
	}

	err := execAppErr(app, "run", "-e", "staging", "--sealed", "--", echoCmd, "hello")
	if err != nil && strings.Contains(err.Error(), "command not found") {
		t.Error("run -e staging --sealed -- should parse both flags")
	}
}

func TestParseRunArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantEnv    string
		wantSealed bool
		wantCmd    []string
	}{
		{"with separator", []string{"--", "echo", "hi"}, "", false, []string{"echo", "hi"}},
		{"env short flag", []string{"-e", "prod", "--", "echo"}, "prod", false, []string{"echo"}},
		{"env long flag", []string{"--env", "prod", "--", "echo"}, "prod", false, []string{"echo"}},
		{"env=value", []string{"--env=prod", "--", "echo"}, "prod", false, []string{"echo"}},
		{"e=value", []string{"-e=prod", "--", "echo"}, "prod", false, []string{"echo"}},
		{"sealed flag", []string{"--sealed", "--", "echo"}, "", true, []string{"echo"}},
		{"no separator", []string{"echo", "hi"}, "", false, []string{"echo", "hi"}},
		{"empty args", []string{}, "", false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, sealed, cmd := parseRunArgs(tt.args)
			if env != tt.wantEnv {
				t.Errorf("env = %q, want %q", env, tt.wantEnv)
			}
			if sealed != tt.wantSealed {
				t.Errorf("sealed = %v, want %v", sealed, tt.wantSealed)
			}
			if len(cmd) != len(tt.wantCmd) {
				t.Errorf("cmd = %v, want %v", cmd, tt.wantCmd)
			}
		})
	}
}
