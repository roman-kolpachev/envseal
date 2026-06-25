package ui

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type errWriter struct{}

func (e errWriter) Write([]byte) (int, error) {
	return 0, errors.New("write error")
}

type failAfterN struct {
	n       int
	written int
}

func (f *failAfterN) Write(p []byte) (int, error) {
	f.written++
	if f.written > f.n {
		return 0, errors.New("write error")
	}
	return len(p), nil
}

func TestSuccess(t *testing.T) {
	var buf bytes.Buffer
	if err := Success(&buf, "done"); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "✓") {
		t.Errorf("want ✓ in output, got %q", got)
	}
	if !strings.Contains(got, "done") {
		t.Errorf("want 'done' in output, got %q", got)
	}
}

func TestError(t *testing.T) {
	var buf bytes.Buffer
	if err := Error(&buf, "fail"); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "✗") {
		t.Errorf("want ✗ in output, got %q", got)
	}
}

func TestInfo(t *testing.T) {
	var buf bytes.Buffer
	if err := Info(&buf, "note"); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "ℹ") {
		t.Errorf("want ℹ in output, got %q", got)
	}
}

func TestWarn(t *testing.T) {
	var buf bytes.Buffer
	if err := Warn(&buf, "careful"); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "⚠") {
		t.Errorf("want ⚠ in output, got %q", got)
	}
}

func TestTable(t *testing.T) {
	var buf bytes.Buffer
	if err := Table(&buf, []string{"Key", "Status"}, [][]string{
		{"DB_HOST", "set"},
		{"DB_PORT", "missing"},
	}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "DB_HOST") {
		t.Error("table should contain DB_HOST")
	}
	if !strings.Contains(got, "missing") {
		t.Error("table should contain missing")
	}
}

func TestPlural(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "secrets"},
		{1, "secret"},
		{2, "secrets"},
		{100, "secrets"},
	}
	for _, tt := range tests {
		got := Plural(tt.n, "secret", "secrets")
		if got != tt.want {
			t.Errorf("Plural(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestKeyValue(t *testing.T) {
	var buf bytes.Buffer
	if err := KeyValue(&buf, "host", "localhost"); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "host") {
		t.Error("should contain key")
	}
	if !strings.Contains(got, "localhost") {
		t.Error("should contain value")
	}
}

func TestSuccess_WriteError(t *testing.T) {
	if err := Success(errWriter{}, "msg"); err == nil {
		t.Error("expected error from broken writer")
	}
}

func TestError_WriteError(t *testing.T) {
	if err := Error(errWriter{}, "msg"); err == nil {
		t.Error("expected error from broken writer")
	}
}

func TestInfo_WriteError(t *testing.T) {
	if err := Info(errWriter{}, "msg"); err == nil {
		t.Error("expected error from broken writer")
	}
}

func TestWarn_WriteError(t *testing.T) {
	if err := Warn(errWriter{}, "msg"); err == nil {
		t.Error("expected error from broken writer")
	}
}

func TestTable_WriteError(t *testing.T) {
	err := Table(errWriter{}, []string{"H1"}, [][]string{{"val"}})
	if err == nil {
		t.Error("expected error from broken writer")
	}
}

func TestTable_RowWriteError(t *testing.T) {
	w := &failAfterN{n: 2}
	err := Table(w, []string{"H1"}, [][]string{{"r1"}, {"r2"}})
	if err == nil {
		t.Error("expected error when row write fails")
	}
}

func TestTable_HeaderNewlineError(t *testing.T) {
	w := &failAfterN{n: 1}
	err := Table(w, []string{"H1"}, [][]string{{"r1"}})
	if err == nil {
		t.Error("expected error when header newline write fails")
	}
}

func TestTable_MultipleRowsAndColumns(t *testing.T) {
	var buf bytes.Buffer
	err := Table(&buf, []string{"Name", "Status", "Value"}, [][]string{
		{"key1", "set", "val1"},
		{"key2", "missing", ""},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "key1") || !strings.Contains(out, "key2") {
		t.Errorf("table should contain all rows, got: %q", out)
	}
	if !strings.Contains(out, "Name") || !strings.Contains(out, "Status") {
		t.Errorf("table should contain headers, got: %q", out)
	}
}

func TestKeyValue_WriteError(t *testing.T) {
	if err := KeyValue(errWriter{}, "k", "v"); err == nil {
		t.Error("expected error from broken writer")
	}
}
