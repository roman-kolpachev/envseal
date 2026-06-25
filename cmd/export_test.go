package cmd

import (
	"strings"
	"testing"
)

func TestExportJSON(t *testing.T) {
	app, _ := newTestApp(t)
	execApp(t, app, "set", "MY_KEY=my_value")

	out := execApp(t, app, "export", "--format", "json")
	if !strings.Contains(out, `"MY_KEY"`) || !strings.Contains(out, `"my_value"`) {
		t.Errorf("expected key-value in JSON, got: %s", out)
	}
}

func TestExportShell(t *testing.T) {
	app, _ := newTestApp(t)
	execApp(t, app, "set", "MY_KEY=my_value")

	out := execApp(t, app, "export", "--format", "shell")
	if !strings.Contains(out, "export MY_KEY='my_value'") {
		t.Errorf("expected shell export, got: %s", out)
	}
}

func TestExportDocker(t *testing.T) {
	app, _ := newTestApp(t)
	execApp(t, app, "set", "MY_KEY=my_value")

	out := execApp(t, app, "export", "--format", "docker")
	if !strings.Contains(out, `MY_KEY="my_value"`) {
		t.Errorf("expected docker format, got: %s", out)
	}
}

func TestExportK8s(t *testing.T) {
	app, _ := newTestApp(t)
	execApp(t, app, "set", "MY_KEY=my_value")

	out := execApp(t, app, "export", "--format", "k8s")
	if !strings.Contains(out, "apiVersion: v1") {
		t.Error("expected apiVersion in k8s export")
	}
	if !strings.Contains(out, "kind: Secret") {
		t.Error("expected kind: Secret in k8s export")
	}
	if !strings.Contains(out, "MY_KEY:") {
		t.Error("expected MY_KEY in k8s export")
	}
}

func TestExportUnknownFormat(t *testing.T) {
	app, _ := newTestApp(t)
	execApp(t, app, "set", "MY_KEY=my_value")

	err := execAppErr(app, "export", "--format", "xml")
	if err == nil {
		t.Error("expected error for unknown format")
	}
}
