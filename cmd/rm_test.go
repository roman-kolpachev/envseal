package cmd

import (
	"strings"
	"testing"
)

func TestRmCommand(t *testing.T) {
	app, _ := newTestApp(t)

	execApp(t, app, "set", "TO_DELETE=value")

	out := execApp(t, app, "rm", "TO_DELETE")
	if !strings.Contains(out, "Removed TO_DELETE") {
		t.Error("expected removal success message")
	}

	err := execAppErr(app, "get", "TO_DELETE")
	if err == nil {
		t.Error("expected error after removing key")
	}
}

func TestRmMissingKey(t *testing.T) {
	app, _ := newTestApp(t)

	err := execAppErr(app, "rm", "NONEXISTENT")
	if err == nil {
		t.Error("expected error for missing key")
	}
}
