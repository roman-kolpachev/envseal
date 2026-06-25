package cmd

import (
	"strings"
	"testing"
)

func TestCompletionBash(t *testing.T) {
	app, _ := newTestApp(t)

	out := execApp(t, app, "completion", "bash")
	if !strings.Contains(out, "bash") {
		t.Error("expected bash completion script")
	}
}

func TestCompletionPowershell(t *testing.T) {
	app, _ := newTestApp(t)

	out := execApp(t, app, "completion", "powershell")
	if !strings.Contains(out, "envseal") {
		t.Error("expected powershell completion script")
	}
}

func TestCompletionZsh(t *testing.T) {
	app, _ := newTestApp(t)

	out := execApp(t, app, "completion", "zsh")
	if out == "" {
		t.Error("expected zsh completion output")
	}
}

func TestCompletionFish(t *testing.T) {
	app, _ := newTestApp(t)

	out := execApp(t, app, "completion", "fish")
	if out == "" {
		t.Error("expected fish completion output")
	}
}

func TestCompletionInvalidShell(t *testing.T) {
	app, _ := newTestApp(t)

	err := execAppErr(app, "completion", "invalid")
	if err == nil {
		t.Error("expected error for invalid shell")
	}
}
