package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/roman-kolpachev/envseal/internal/audit"
	"github.com/roman-kolpachev/envseal/internal/config"
)

func TestAuditCommand_ShowsEvents(t *testing.T) {
	app, _ := newTestApp(t)

	execApp(t, app, "set", "DB_HOST=localhost")
	execApp(t, app, "set", "DB_PASS=secret")

	out := execApp(t, app, "audit")
	if !strings.Contains(out, "set") {
		t.Errorf("expected 'set' action in audit, got: %s", out)
	}
	if !strings.Contains(out, "DB_HOST") {
		t.Errorf("expected 'DB_HOST' in audit, got: %s", out)
	}
}

func TestAuditCommand_EmptyLog(t *testing.T) {
	app, _ := newTestApp(t)

	out := execApp(t, app, "audit")
	if !strings.Contains(out, "No audit events") {
		t.Errorf("expected empty message, got: %s", out)
	}
}

func TestAuditCommand_LastFlag(t *testing.T) {
	app, _ := newTestApp(t)

	for i := 0; i < 5; i++ {
		execApp(t, app, "set", "KEY"+string(rune('A'+i))+"=val")
	}

	out := execApp(t, app, "audit", "--last", "2")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	// Header + separator + 2 data rows = 4 lines minimum
	dataLines := 0
	for _, line := range lines {
		if strings.Contains(line, "set") {
			dataLines++
		}
	}
	if dataLines != 2 {
		t.Errorf("expected 2 data lines with --last 2, got %d in:\n%s", dataLines, out)
	}
}

func TestAudit_SetCreatesLogEntry(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "SECRET=val")

	data, err := os.ReadFile(config.AuditPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, `"action":"set"`) {
		t.Error("audit log should contain set action")
	}
	if !strings.Contains(content, "SECRET") {
		t.Error("audit log should contain key name")
	}
}

func TestAudit_GetCreatesLogEntry(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "KEY=val")
	execApp(t, app, "get", "KEY")

	data, _ := os.ReadFile(config.AuditPath(dir))
	if !strings.Contains(string(data), `"action":"get"`) {
		t.Error("audit log should contain get action")
	}
}

func TestAudit_RmCreatesLogEntry(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "KEY=val")
	execApp(t, app, "rm", "KEY")

	data, _ := os.ReadFile(config.AuditPath(dir))
	if !strings.Contains(string(data), `"action":"rm"`) {
		t.Error("audit log should contain rm action")
	}
}

func TestAudit_ImportCreatesLogEntry(t *testing.T) {
	app, dir := newTestApp(t)

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1\nB=2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	execApp(t, app, "import")

	data, _ := os.ReadFile(config.AuditPath(dir))
	content := string(data)
	if !strings.Contains(content, `"action":"import"`) {
		t.Error("audit log should contain import action")
	}
}

func TestAudit_GrantCreatesLogEntry(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "KEY=val")
	execApp(t, app, "grant", "bob", "--key", "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p")

	data, _ := os.ReadFile(config.AuditPath(dir))
	content := string(data)
	if !strings.Contains(content, `"action":"grant"`) {
		t.Error("audit log should contain grant action")
	}
	if !strings.Contains(content, `"target":"bob"`) {
		t.Error("audit log should contain target name")
	}
}

func TestAuditJSON(t *testing.T) {
	app, _ := newTestApp(t)

	execApp(t, app, "set", "DB_HOST=localhost")

	out := execApp(t, app, "audit", "--json")

	var events []audit.Event
	if err := json.Unmarshal([]byte(out), &events); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected at least one event")
	}
	if events[0].Action != "set" {
		t.Errorf("expected action 'set', got %q", events[0].Action)
	}
}

func TestAuditJSON_Empty(t *testing.T) {
	app, _ := newTestApp(t)

	out := execApp(t, app, "audit", "--json")

	var events []audit.Event
	if err := json.Unmarshal([]byte(out), &events); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected empty array, got %d events", len(events))
	}
}
