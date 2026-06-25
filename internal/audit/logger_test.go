package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLog_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l := NewLogger(path)

	err := l.Log(Event{Action: "set", Actor: "age1test", Keys: []string{"DB_HOST"}, Message: "Set DB_HOST"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatal("audit log file not created")
	}

	data, _ := os.ReadFile(path)
	var event Event
	if err := json.Unmarshal(data[:len(data)-1], &event); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if event.Action != "set" {
		t.Errorf("action = %q, want %q", event.Action, "set")
	}
	if event.Actor != "age1test" {
		t.Errorf("actor = %q, want %q", event.Actor, "age1test")
	}
}

func TestLog_AppendsToExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l := NewLogger(path)

	if err := l.Log(Event{Action: "set", Keys: []string{"A"}}); err != nil {
		t.Fatal(err)
	}
	if err := l.Log(Event{Action: "get", Keys: []string{"B"}}); err != nil {
		t.Fatal(err)
	}
	if err := l.Log(Event{Action: "rm", Keys: []string{"C"}}); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d", len(lines))
	}
}

func TestLog_SetsTimestamp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l := NewLogger(path)

	if err := l.Log(Event{Action: "set", Keys: []string{"KEY"}}); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	var event Event
	if err := json.Unmarshal(data[:len(data)-1], &event); err != nil {
		t.Fatal(err)
	}

	if event.Timestamp == "" {
		t.Error("timestamp should be set automatically")
	}
	if !strings.Contains(event.Timestamp, "T") || !strings.Contains(event.Timestamp, "Z") {
		t.Errorf("timestamp should be RFC3339 UTC, got %q", event.Timestamp)
	}
}

func TestLog_PreservesTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l := NewLogger(path)

	if err := l.Log(Event{Action: "grant", Actor: "age1me", Target: "alice", Message: "Granted access to alice"}); err != nil {
		t.Fatal(err)
	}

	events, _ := l.Recent(0)
	if len(events) != 1 {
		t.Fatal("expected 1 event")
	}
	if events[0].Target != "alice" {
		t.Errorf("target = %q, want %q", events[0].Target, "alice")
	}
}

func TestRecent_ReturnsLastN(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l := NewLogger(path)

	for i := 0; i < 5; i++ {
		if err := l.Log(Event{Action: "set", Keys: []string{string(rune('A' + i))}}); err != nil {
			t.Fatal(err)
		}
	}

	events, err := l.Recent(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Errorf("expected 3 events, got %d", len(events))
	}
	if events[0].Keys[0] != "C" {
		t.Errorf("first event key = %q, want %q", events[0].Keys[0], "C")
	}
	if events[2].Keys[0] != "E" {
		t.Errorf("last event key = %q, want %q", events[2].Keys[0], "E")
	}
}

func TestRecent_ZeroReturnsAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l := NewLogger(path)

	for i := 0; i < 5; i++ {
		if err := l.Log(Event{Action: "set"}); err != nil {
			t.Fatal(err)
		}
	}

	events, err := l.Recent(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 5 {
		t.Errorf("expected 5 events, got %d", len(events))
	}
}

func TestRecent_MoreThanExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l := NewLogger(path)

	if err := l.Log(Event{Action: "set"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Log(Event{Action: "get"}); err != nil {
		t.Fatal(err)
	}

	events, err := l.Recent(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}
}

func TestRecent_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.log")
	l := NewLogger(path)

	events, err := l.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
}

func TestLog_CreatesParentDir(t *testing.T) {
	// Logger must create the parent directory if it doesn't exist so that
	// audit logging works on a freshly-cloned repo where audit.log is in .gitignore.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "subdir", "audit.log")
	l := NewLogger(logPath)
	if err := l.Log(Event{Action: "test"}); err != nil {
		t.Fatalf("unexpected error creating parent dir: %v", err)
	}
	if _, err := os.Stat(logPath); err != nil {
		t.Errorf("expected log file to exist after Log(): %v", err)
	}
}

func TestRecent_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte("not json\n{\"action\":\"set\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	l := NewLogger(path)
	events, err := l.Recent(0)
	if err == nil {
		t.Fatal("expected tamper warning error for corrupted entries")
	}
	if !strings.Contains(err.Error(), "corrupted") {
		t.Errorf("error should mention corruption, got: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("expected 1 valid event (skipping malformed), got %d", len(events))
	}
	if events[0].Action != "set" {
		t.Errorf("action = %q, want %q", events[0].Action, "set")
	}
}

func TestHashChain_DetectsTampering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l := NewLogger(path)

	for i := 0; i < 3; i++ {
		if err := l.Log(Event{Action: "set", Keys: []string{string(rune('A' + i))}}); err != nil {
			t.Fatal(err)
		}
	}

	events, err := l.Recent(0)
	if err != nil {
		t.Fatalf("clean log should have no errors: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if events[1].PrevHash == "" {
		t.Error("second event should have a PrevHash")
	}

	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	lines[1] = strings.Replace(lines[1], `"set"`, `"tampered"`, 1)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	l2 := NewLogger(path)
	_, err = l2.Recent(0)
	if err == nil {
		t.Fatal("expected hash chain error after tampering")
	}
	if !strings.Contains(err.Error(), "hash chain is broken") {
		t.Errorf("expected 'hash chain is broken' error, got: %v", err)
	}
}

func TestHashChain_ValidOnCleanLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l := NewLogger(path)

	for i := 0; i < 5; i++ {
		if err := l.Log(Event{Action: "set", Keys: []string{string(rune('A' + i))}}); err != nil {
			t.Fatal(err)
		}
	}

	l2 := NewLogger(path)
	_, err := l2.Recent(0)
	if err != nil {
		t.Fatalf("clean log should pass chain verification: %v", err)
	}
}

func TestLog_OmitsEmptyFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l := NewLogger(path)

	if err := l.Log(Event{Action: "set", Keys: []string{"KEY"}}); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	line := string(data)
	if strings.Contains(line, "target") {
		t.Error("empty target should be omitted from JSON")
	}
}
