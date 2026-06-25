package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/roman-kolpachev/envseal/internal/vault"
)

func TestDiffCommand(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "EXISTING=value")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("EXISTING=value\nNEW=value2\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "diff", "--source", ".env")
	if !strings.Contains(out, "unchanged") {
		t.Errorf("expected 'unchanged' for EXISTING, got: %s", out)
	}
	if !strings.Contains(out, "added") {
		t.Errorf("expected 'added' for NEW, got: %s", out)
	}
}

func TestDiffJSON(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "EXISTING=value")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("EXISTING=value\nNEW=value2\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "diff", "--source", ".env", "--json")

	var diffs []vault.DiffResult
	if err := json.Unmarshal([]byte(out), &diffs); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(diffs) != 2 {
		t.Fatalf("expected 2 diffs, got %d", len(diffs))
	}

	found := map[string]string{}
	for _, d := range diffs {
		found[d.Key] = d.Status
	}
	if found["EXISTING"] != "unchanged" {
		t.Errorf("expected EXISTING=unchanged, got %q", found["EXISTING"])
	}
	if found["NEW"] != "added" {
		t.Errorf("expected NEW=added, got %q", found["NEW"])
	}
}

func TestDiffRemoved(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "A=1")
	execApp(t, app, "set", "B=2")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "diff", "--source", ".env")
	if !strings.Contains(out, "removed") {
		t.Errorf("expected 'removed' for B, got: %s", out)
	}
}

func TestDiffChanged(t *testing.T) {
	app, dir := newTestApp(t)

	execApp(t, app, "set", "KEY=old")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("KEY=new\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := execApp(t, app, "diff", "--source", ".env")
	if !strings.Contains(out, "changed") {
		t.Errorf("expected 'changed' for KEY, got: %s", out)
	}
}
