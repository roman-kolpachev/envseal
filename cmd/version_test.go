package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	app, _ := newTestApp(t)

	out := execApp(t, app, "version")
	if !strings.Contains(out, "envseal") {
		t.Errorf("expected 'envseal' in output, got %q", out)
	}
}

func TestVersionCommandWithCustomVersion(t *testing.T) {
	app, _ := newTestApp(t)
	app.deps.Version = "v1.2.3"

	out := execApp(t, app, "version")
	if !strings.Contains(out, "v1.2.3") {
		t.Errorf("expected 'v1.2.3' in output, got %q", out)
	}
}

func TestVersionJSON(t *testing.T) {
	app, _ := newTestApp(t)
	app.deps.Version = "v1.0.0"

	out := execApp(t, app, "version", "--json")

	var result map[string]string
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result["version"] != "v1.0.0" {
		t.Errorf("expected version v1.0.0, got %q", result["version"])
	}
}
