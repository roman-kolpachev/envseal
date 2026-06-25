package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestListCommand(t *testing.T) {
	app, _ := newTestApp(t)

	execApp(t, app, "set", "B_KEY=val2")
	execApp(t, app, "set", "A_KEY=val1")

	out := execApp(t, app, "list")
	lines := strings.Split(strings.TrimSpace(out), "\n")

	if len(lines) != 2 {
		t.Fatalf("expected 2 keys, got %d: %v", len(lines), lines)
	}
	if lines[0] != "A_KEY" || lines[1] != "B_KEY" {
		t.Errorf("expected sorted [A_KEY, B_KEY], got %v", lines)
	}
}

func TestListEmpty(t *testing.T) {
	app, _ := newTestApp(t)

	out := execApp(t, app, "list")
	if strings.TrimSpace(out) != "" {
		t.Errorf("expected empty output, got %q", out)
	}
}

func TestListJSON(t *testing.T) {
	app, _ := newTestApp(t)

	execApp(t, app, "set", "B_KEY=val2")
	execApp(t, app, "set", "A_KEY=val1")

	out := execApp(t, app, "list", "--json")

	var keys []string
	if err := json.Unmarshal([]byte(out), &keys); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(keys) != 2 || keys[0] != "A_KEY" || keys[1] != "B_KEY" {
		t.Errorf("expected sorted [A_KEY, B_KEY], got %v", keys)
	}
}
