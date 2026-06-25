package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindEnvFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{".env", ".env.local", ".env.development", ".env.staging"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("KEY=val"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main"), 0644); err != nil {
		t.Fatal(err)
	}

	files, err := FindEnvFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Errorf("expected 4 files, got %d: %v", len(files), files)
	}
}

func TestFindEnvFiles_ExcludesEnvsealDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("KEY=val"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".envseal", "vault"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".envseal", "config.toml"), []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	files, err := FindEnvFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != ".env" {
		t.Errorf("expected [.env], got %v", files)
	}
}

func TestFindEnvFiles_ReturnsRelativePaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env.production"), []byte("KEY=val"), 0600); err != nil {
		t.Fatal(err)
	}

	files, err := FindEnvFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != ".env.production" {
		t.Errorf("expected [.env.production], got %v", files)
	}
}

func TestFindEnvFiles_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	files, err := FindEnvFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

func TestFindEnvFiles_SortedAlphabetically(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{".env.staging", ".env", ".env.development"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("KEY=val"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	files, err := FindEnvFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{".env", ".env.development", ".env.staging"}
	if len(files) != len(expected) {
		t.Fatalf("expected %d files, got %d: %v", len(expected), len(files), files)
	}
	for i, f := range files {
		if f != expected[i] {
			t.Errorf("files[%d] = %q, want %q", i, f, expected[i])
		}
	}
}

func TestFindEnvFiles_SkipsDirectories(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("KEY=val"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".env.d"), 0700); err != nil {
		t.Fatal(err)
	}

	files, err := FindEnvFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d: %v", len(files), files)
	}
}

func TestFindEnvFiles_SkipsVaultFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("KEY=val"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env.vault"), []byte("encrypted"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env.staging.vault"), []byte("encrypted"), 0600); err != nil {
		t.Fatal(err)
	}

	files, err := FindEnvFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 file (no .vault), got %d: %v", len(files), files)
	}
}

func TestFindEnvFiles_SkipsExampleAndKeysFiles(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		data string
		perm os.FileMode
	}{
		{".env", "KEY=val", 0600},
		{".env.example", "KEY=", 0644},
		{".env.keys", "private", 0600},
		{".env.sample", "KEY=", 0644},
		{".env.template", "KEY=", 0644},
	} {
		if err := os.WriteFile(filepath.Join(dir, tc.name), []byte(tc.data), tc.perm); err != nil {
			t.Fatal(err)
		}
	}

	files, err := FindEnvFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d: %v", len(files), files)
	}
}
