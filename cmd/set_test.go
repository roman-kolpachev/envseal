package cmd

import (
	"fmt"
	"strings"
	"testing"
)

func TestSetAndGet(t *testing.T) {
	app, _ := newTestApp(t)

	out := execApp(t, app, "set", "DB_HOST=localhost")
	if !strings.Contains(out, "Encrypted DB_HOST") {
		t.Error("expected encryption success message")
	}

	val := execApp(t, app, "get", "DB_HOST")
	if strings.TrimSpace(val) != "localhost" {
		t.Errorf("expected 'localhost', got %q", strings.TrimSpace(val))
	}
}

func TestSetInvalidFormat(t *testing.T) {
	app, _ := newTestApp(t)
	app.deps.ReadSecret = nil

	err := execAppErr(app, "set", "INVALID")
	if err == nil {
		t.Error("expected error for KEY without = and no ReadSecret")
	}
}

func TestGetMissingKey(t *testing.T) {
	app, _ := newTestApp(t)

	err := execAppErr(app, "get", "NONEXISTENT")
	if err == nil {
		t.Error("expected error for missing key")
	}
}

func TestSetInteractivePrompt(t *testing.T) {
	app, _ := newTestApp(t)
	app.deps.ReadSecret = func(prompt string) ([]byte, error) {
		return []byte("interactive-secret"), nil
	}

	out := execApp(t, app, "set", "API_KEY")
	if !strings.Contains(out, "Encrypted API_KEY") {
		t.Error("expected encryption success message")
	}

	val := execApp(t, app, "get", "API_KEY")
	if strings.TrimSpace(val) != "interactive-secret" {
		t.Errorf("expected 'interactive-secret', got %q", strings.TrimSpace(val))
	}
}

func TestSetInteractiveEmptyValue(t *testing.T) {
	app, _ := newTestApp(t)
	app.deps.ReadSecret = func(prompt string) ([]byte, error) {
		return nil, nil
	}

	err := execAppErr(app, "set", "EMPTY_KEY")
	if err == nil {
		t.Error("expected error for empty interactive value")
	}
}

func TestSetInteractiveReaderError(t *testing.T) {
	app, _ := newTestApp(t)
	app.deps.ReadSecret = func(prompt string) ([]byte, error) {
		return nil, fmt.Errorf("terminal not available")
	}

	err := execAppErr(app, "set", "FAIL_KEY")
	if err == nil {
		t.Error("expected error when ReadSecret fails")
	}
}

func TestSetKeyValueStillWorksWith_ReadSecret(t *testing.T) {
	app, _ := newTestApp(t)
	app.deps.ReadSecret = func(prompt string) ([]byte, error) {
		t.Error("ReadSecret should not be called for KEY=VALUE format")
		return nil, nil
	}

	out := execApp(t, app, "set", "EXPLICIT=value123")
	if !strings.Contains(out, "Encrypted EXPLICIT") {
		t.Error("expected encryption success message")
	}

	val := execApp(t, app, "get", "EXPLICIT")
	if strings.TrimSpace(val) != "value123" {
		t.Errorf("expected 'value123', got %q", strings.TrimSpace(val))
	}
}
