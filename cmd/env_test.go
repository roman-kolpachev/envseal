package cmd

import (
	"strings"
	"testing"
)

func TestEnvList(t *testing.T) {
	app, _ := newTestApp(t)

	out := execApp(t, app, "env", "list")

	if !strings.Contains(out, "* development") {
		t.Error("expected development to be marked as active")
	}
	if !strings.Contains(out, "staging") {
		t.Error("expected staging in list")
	}
	if !strings.Contains(out, "production") {
		t.Error("expected production in list")
	}
}

func TestEnvUse(t *testing.T) {
	app, _ := newTestApp(t)

	out := execApp(t, app, "env", "use", "staging")
	if !strings.Contains(out, "Switched to staging") {
		t.Errorf("expected switch message, got %q", out)
	}

	out = execApp(t, app, "env", "list")
	if !strings.Contains(out, "* staging") {
		t.Error("expected staging to be active after switch")
	}
	if strings.Contains(out, "* development") {
		t.Error("development should no longer be active")
	}
}

func TestEnvUse_InvalidEnvironment(t *testing.T) {
	app, _ := newTestApp(t)

	err := execAppErr(app, "env", "use", "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent environment")
	}
}

func TestEnvUse_NoArgs(t *testing.T) {
	app, _ := newTestApp(t)

	err := execAppErr(app, "env", "use")
	if err == nil {
		t.Error("expected error when no environment specified")
	}
}

func TestEnvAdd(t *testing.T) {
	app, _ := newTestApp(t)

	out := execApp(t, app, "env", "add", "testing")
	if !strings.Contains(out, "Added environment testing") {
		t.Errorf("expected success message, got %q", out)
	}

	out = execApp(t, app, "env", "list")
	if !strings.Contains(out, "testing") {
		t.Error("expected testing in list after add")
	}
}

func TestEnvAdd_AlreadyExists(t *testing.T) {
	app, _ := newTestApp(t)

	err := execAppErr(app, "env", "add", "development")
	if err == nil {
		t.Error("expected error for existing environment")
	}
}

func TestEnvAdd_ThenUse(t *testing.T) {
	app, _ := newTestApp(t)

	execApp(t, app, "env", "add", "testing")
	out := execApp(t, app, "env", "use", "testing")
	if !strings.Contains(out, "Switched to testing") {
		t.Errorf("expected switch message, got %q", out)
	}
}
