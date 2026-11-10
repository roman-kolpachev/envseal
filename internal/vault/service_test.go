package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/roman-kolpachev/envseal/internal/config"
	"github.com/roman-kolpachev/envseal/internal/envcheck"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	cfg := &config.Config{
		Recipients: map[string]string{
			"alice": "age1testkey",
		},
	}
	svc := NewService(newMockEncryptor(), cfg)
	if err := svc.SetEnvironment("development"); err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestSet_And_Get(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "DB_HOST", []byte("localhost")); err != nil {
		t.Fatal(err)
	}

	val, err := svc.Get(ctx, "DB_HOST")
	if err != nil {
		t.Fatal(err)
	}
	if string(val) != "localhost" {
		t.Errorf("got %q, want %q", val, "localhost")
	}
}

func TestSet_Overwrite(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "KEY", []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Set(ctx, "KEY", []byte("new")); err != nil {
		t.Fatal(err)
	}

	val, _ := svc.Get(ctx, "KEY")
	if string(val) != "new" {
		t.Errorf("got %q, want %q", val, "new")
	}
}

func TestGet_NotFound(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	_, err := svc.Get(ctx, "MISSING")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("want ErrKeyNotFound, got %v", err)
	}
}

func TestRemove(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "KEY", []byte("val")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Remove("KEY"); err != nil {
		t.Fatal(err)
	}

	_, err := svc.Get(ctx, "KEY")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Error("key should be removed")
	}
}

func TestRemove_NotFound(t *testing.T) {
	svc := newTestService(t)

	err := svc.Remove("GHOST")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("want ErrKeyNotFound, got %v", err)
	}
}

func TestList(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "B", []byte("2")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Set(ctx, "A", []byte("1")); err != nil {
		t.Fatal(err)
	}

	keys, err := svc.List()
	if err != nil {
		t.Fatal(err)
	}

	slices.Sort(keys)
	if len(keys) != 2 || keys[0] != "A" || keys[1] != "B" {
		t.Errorf("keys = %v, want [A B]", keys)
	}
}

func TestList_Empty(t *testing.T) {
	svc := newTestService(t)

	keys, err := svc.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Errorf("expected empty, got %v", keys)
	}
}

func TestDecryptAll(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "A", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Set(ctx, "B", []byte("2")); err != nil {
		t.Fatal(err)
	}

	all, err := svc.DecryptAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(all["A"]) != "1" || string(all["B"]) != "2" {
		t.Errorf("decrypted = %v", all)
	}
}

func TestSync(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	// First sync: 3 new keys
	if err := os.WriteFile(envPath, []byte("A=1\nB=2\nC=3\n"), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := svc.Sync(ctx, envPath, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Added) != 3 {
		t.Errorf("added = %v, want 3 items", result.Added)
	}

	// Second sync with overwrite-all: change B, remove C, overwrite A
	if err := os.WriteFile(envPath, []byte("A=1\nB=changed\n"), 0600); err != nil {
		t.Fatal(err)
	}

	alwaysYes := func(key string) ConflictChoice { return ConflictAll }
	result, err = svc.Sync(ctx, envPath, true, alwaysYes)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Changed) != 2 {
		t.Errorf("changed = %v, want [A, B]", result.Changed)
	}
	if len(result.Removed) != 1 || result.Removed[0] != "C" {
		t.Errorf("removed = %v, want [C]", result.Removed)
	}
}

func TestSync_SkipsExistingWithoutConfirm(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	if err := os.WriteFile(envPath, []byte("A=1\nB=2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Sync(ctx, envPath, true, nil); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(envPath, []byte("A=changed\nB=changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := svc.Sync(ctx, envPath, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Unchanged) != 2 {
		t.Errorf("unchanged = %v, want 2 items", result.Unchanged)
	}
	if len(result.Changed) != 0 {
		t.Errorf("changed = %v, want 0 items", result.Changed)
	}
}

func TestSync_ConflictYesPerKey(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	if err := os.WriteFile(envPath, []byte("A=1\nB=2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Sync(ctx, envPath, true, nil); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(envPath, []byte("A=new\nB=new\n"), 0600); err != nil {
		t.Fatal(err)
	}

	onlyA := func(key string) ConflictChoice {
		if key == "A" {
			return ConflictYes
		}
		return ConflictNo
	}
	result, err := svc.Sync(ctx, envPath, true, onlyA)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Changed) != 1 || result.Changed[0] != "A" {
		t.Errorf("changed = %v, want [A]", result.Changed)
	}
	if len(result.Unchanged) != 1 || result.Unchanged[0] != "B" {
		t.Errorf("unchanged = %v, want [B]", result.Unchanged)
	}

	val, _ := svc.Get(ctx, "A")
	if string(val) != "new" {
		t.Errorf("A = %q, want %q", val, "new")
	}
	val, _ = svc.Get(ctx, "B")
	if string(val) != "2" {
		t.Errorf("B = %q, want %q (should not be overwritten)", val, "2")
	}
}

func TestSync_ConflictAllStopsAsking(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	if err := os.WriteFile(envPath, []byte("A=1\nB=2\nC=3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Sync(ctx, envPath, true, nil); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(envPath, []byte("A=new\nB=new\nC=new\n"), 0600); err != nil {
		t.Fatal(err)
	}

	callCount := 0
	allOnFirst := func(key string) ConflictChoice {
		callCount++
		return ConflictAll
	}
	result, err := svc.Sync(ctx, envPath, true, allOnFirst)
	if err != nil {
		t.Fatal(err)
	}
	if callCount != 1 {
		t.Errorf("callback called %d times, want 1 (All should stop asking)", callCount)
	}
	if len(result.Changed) != 3 {
		t.Errorf("changed = %v, want 3 items", result.Changed)
	}
}

func TestDiff(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "A", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Set(ctx, "B", []byte("2")); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("A=1\nB=changed\nC=new\n"), 0600); err != nil {
		t.Fatal(err)
	}

	diffs, err := svc.Diff(envPath)
	if err != nil {
		t.Fatal(err)
	}

	diffMap := make(map[string]string)
	for _, d := range diffs {
		diffMap[d.Key] = d.Status
	}

	if diffMap["A"] != "unchanged" {
		t.Errorf("A = %q, want unchanged", diffMap["A"])
	}
	if diffMap["B"] != "changed" {
		t.Errorf("B = %q, want changed", diffMap["B"])
	}
	if diffMap["C"] != "added" {
		t.Errorf("C = %q, want added", diffMap["C"])
	}
}

func TestExport_JSON(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "DB_HOST", []byte("localhost")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Set(ctx, "DB_PORT", []byte("5432")); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err := svc.Export(ctx, "json", &buf)
	if err != nil {
		t.Fatal(err)
	}

	out := buf.String()

	if out == "" {
		t.Error("expected non-empty JSON output")
	}
}

func TestExport_Shell(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "DB_HOST", []byte("localhost")); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err := svc.Export(ctx, "shell", &buf)
	if err != nil {
		t.Fatal(err)
	}

	got := buf.String()
	want := "export DB_HOST='localhost'\n"

	if got != want {
		t.Errorf("got %q", got)
	}
}
func TestExport_Docker(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "DB_HOST", []byte("localhost")); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err := svc.Export(ctx, "docker", &buf)
	if err != nil {
		t.Fatal(err)
	}

	got := buf.String()
	want := "DB_HOST=\"localhost\"\n"

	if got != want {
		t.Errorf("got %q", got)
	}
}
func TestExport_Shell_EscapesSpecialChars(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value []byte
		want  string
	}{
		{"dollar sign", "DSN", []byte("postgres://$USER@host"), "export DSN='postgres://$USER@host'\n"},
		{"double quotes", "MSG", []byte(`say "hello"`), "export MSG='say \"hello\"'\n"},
		{"single quotes", "MSG", []byte("it's here"), "export MSG='it'\\''s here'\n"},
		{"newline", "CERT", []byte("line1\nline2"), "export CERT='line1\nline2'\n"},
		{"backtick", "CMD", []byte("echo `whoami`"), "export CMD='echo `whoami`'\n"},
		{"simple value", "KEY", []byte("simple"), "export KEY='simple'\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t)
			ctx := context.Background()

			if err := svc.Set(ctx, tt.key, tt.value); err != nil {
				t.Fatal(err)
			}

			var buf bytes.Buffer
			err := svc.Export(ctx, "shell", &buf)
			if err != nil {
				t.Fatal(err)
			}

			got := buf.String()
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
func TestExport_Docker_EscapesSpecialChars(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value []byte
		want  string
	}{
		{"newline", "CERT", []byte("line1\nline2"), "CERT=\"line1\\nline2\"\n"},
		{"double quotes", "MSG", []byte(`say "hello"`), "MSG=\"say \\\"hello\\\"\"\n"},
		{"simple value", "KEY", []byte("simple"), "KEY=\"simple\"\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t)
			ctx := context.Background()

			if err := svc.Set(ctx, tt.key, tt.value); err != nil {
				t.Fatal(err)
			}

			var buf bytes.Buffer
			err := svc.Export(ctx, "docker", &buf)
			if err != nil {
				t.Fatal(err)
			}

			got := buf.String()
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
func TestExport_BlocksDangerousVarsInOldVaults(t *testing.T) {
	cfg := &config.Config{
		Recipients: map[string]string{"alice": "age1testkey"},
	}
	enc := newMockEncryptor()
	svc := NewService(enc, cfg)
	if err := svc.SetEnvironment("development"); err != nil {
		t.Fatal(err)
	}

	// Construct entries directly (bypassing Set, which blocks dangerous keys)
	// with valid environment- and key-bound plaintext so they represent a
	// vault created before EDITOR was added to the dangerous-variable list.
	addEntry := func(key string, value []byte) {
		t.Helper()
		encrypted, err := enc.Encrypt(encodeEntryPlaintext("development", key, value), []string{"age1testkey"})
		if err != nil {
			t.Fatal(err)
		}
		svc.vault.Entries[key] = Entry{Encrypted: encrypted}
	}
	addEntry("EDITOR", []byte("/tmp/evil"))
	addEntry("SAFE_VAR", []byte("ok"))

	for _, format := range []string{"shell", "json", "docker", "k8s"} {
		t.Run(format, func(t *testing.T) {

			var buf bytes.Buffer
			err := svc.Export(context.Background(), format, &buf)

			if err == nil {
				t.Errorf("Export(%q) should reject vault containing dangerous var EDITOR", format)
			}
			if err != nil && !strings.Contains(err.Error(), "dangerous") {
				t.Errorf("expected 'dangerous' in error, got: %v", err)
			}
		})
	}
}
func TestExport_UnknownFormat(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	var buf bytes.Buffer
	err := svc.Export(ctx, "xml", &buf)

	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestSaveAndLoad(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "SECRET", []byte("value123")); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "test.vault")

	if err := svc.Save(vaultPath, "development"); err != nil {
		t.Fatal(err)
	}

	svc2 := newTestService(t)
	if err := svc2.Load(vaultPath); err != nil {
		t.Fatal(err)
	}

	val, err := svc2.Get(ctx, "SECRET")
	if err != nil {
		t.Fatal(err)
	}
	if string(val) != "value123" {
		t.Errorf("got %q, want %q", val, "value123")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	svc := newTestService(t)

	err := svc.Load("/nonexistent/path/vault.json")
	if !errors.Is(err, ErrVaultNotFound) {
		t.Errorf("want ErrVaultNotFound, got %v", err)
	}
}

func TestReEncryptAll(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "A", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Set(ctx, "B", []byte("2")); err != nil {
		t.Fatal(err)
	}

	err := svc.ReEncryptAll(ctx, []string{"age1newkey"})
	if err != nil {
		t.Fatal(err)
	}

	val, _ := svc.Get(ctx, "A")
	if string(val) != "1" {
		t.Errorf("got %q after re-encrypt, want %q", val, "1")
	}
}

func TestImport(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("A=1\nB=2\nC=3\n"), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := svc.Import(ctx, envPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 3 {
		t.Errorf("total = %d, want 3", result.Total)
	}
	if len(result.Imported) != 3 {
		t.Errorf("imported = %v, want 3 items", result.Imported)
	}
	if len(result.Skipped) != 0 {
		t.Errorf("skipped = %v, want 0 items", result.Skipped)
	}

	// Verify values are actually in vault
	val, _ := svc.Get(ctx, "A")
	if string(val) != "1" {
		t.Errorf("A = %q, want %q", val, "1")
	}
}

func TestImport_SkipsExisting(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "A", []byte("old")); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("A=new\nB=2\n"), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := svc.Import(ctx, envPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Imported) != 1 || result.Imported[0] != "B" {
		t.Errorf("imported = %v, want [B]", result.Imported)
	}
	if len(result.Skipped) != 1 || result.Skipped[0] != "A" {
		t.Errorf("skipped = %v, want [A]", result.Skipped)
	}

	// A should keep old value
	val, _ := svc.Get(ctx, "A")
	if string(val) != "old" {
		t.Errorf("A = %q, want %q (should not be overwritten)", val, "old")
	}
}

func TestImport_Force(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "A", []byte("old")); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("A=new\nB=2\n"), 0600); err != nil {
		t.Fatal(err)
	}

	forceAll := func(key string) ConflictChoice { return ConflictAll }
	result, err := svc.Import(ctx, envPath, forceAll)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Imported) != 2 {
		t.Errorf("imported = %v, want 2 items", result.Imported)
	}
	if len(result.Skipped) != 0 {
		t.Errorf("skipped = %v, want 0 items", result.Skipped)
	}

	val, _ := svc.Get(ctx, "A")
	if string(val) != "new" {
		t.Errorf("A = %q, want %q (should be overwritten with force)", val, "new")
	}
}

func TestImport_ConflictYesPerKey(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "A", []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Set(ctx, "B", []byte("old")); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("A=new\nB=new\nC=3\n"), 0600); err != nil {
		t.Fatal(err)
	}

	onlyA := func(key string) ConflictChoice {
		if key == "A" {
			return ConflictYes
		}
		return ConflictNo
	}
	result, err := svc.Import(ctx, envPath, onlyA)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Imported) != 2 {
		t.Errorf("imported = %v, want [A, C]", result.Imported)
	}
	if len(result.Skipped) != 1 || result.Skipped[0] != "B" {
		t.Errorf("skipped = %v, want [B]", result.Skipped)
	}

	val, _ := svc.Get(ctx, "A")
	if string(val) != "new" {
		t.Errorf("A = %q, want %q", val, "new")
	}
	val, _ = svc.Get(ctx, "B")
	if string(val) != "old" {
		t.Errorf("B = %q, want %q (should not be overwritten)", val, "old")
	}
}

func TestImport_ConflictAllStopsAsking(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "A", []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Set(ctx, "B", []byte("old")); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("A=new\nB=new\n"), 0600); err != nil {
		t.Fatal(err)
	}

	callCount := 0
	allOnFirst := func(key string) ConflictChoice {
		callCount++
		return ConflictAll
	}
	result, err := svc.Import(ctx, envPath, allOnFirst)
	if err != nil {
		t.Fatal(err)
	}
	if callCount != 1 {
		t.Errorf("callback called %d times, want 1", callCount)
	}
	if len(result.Imported) != 2 {
		t.Errorf("imported = %v, want 2 items", result.Imported)
	}
}

func TestImport_FileNotFound(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	_, err := svc.Import(ctx, "/nonexistent/.env", nil)
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestSet_NoRecipients(t *testing.T) {
	cfg := &config.Config{
		Recipients: map[string]string{},
	}
	svc := NewService(newMockEncryptor(), cfg)
	if err := svc.SetEnvironment("development"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	err := svc.Set(ctx, "KEY", []byte("val"))
	if !errors.Is(err, ErrNoRecipients) {
		t.Errorf("want ErrNoRecipients, got %v", err)
	}
}

func TestSync_NoPruneKeepsVaultOnlyKeys(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	if err := os.WriteFile(envPath, []byte("A=1\nB=2\nC=3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Sync(ctx, envPath, true, nil); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(envPath, []byte("A=1\n"), 0600); err != nil {
		t.Fatal(err)
	}

	alwaysYes := func(key string) ConflictChoice { return ConflictAll }
	result, err := svc.Sync(ctx, envPath, false, alwaysYes)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Removed) != 0 {
		t.Errorf("removed = %v, want 0 (prune=false)", result.Removed)
	}
	if len(result.Kept) != 2 {
		t.Errorf("kept = %v, want 2 items", result.Kept)
	}

	_, errB := svc.Get(ctx, "B")
	_, errC := svc.Get(ctx, "C")
	if errB != nil || errC != nil {
		t.Error("vault-only keys B and C should still exist")
	}
}

func TestSave_SetsEnvironment(t *testing.T) {
	cfg := &config.Config{
		Recipients: map[string]string{"alice": "age1testkey"},
	}
	svc := NewService(newMockEncryptor(), cfg)
	if err := svc.SetEnvironment("staging"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := svc.Set(ctx, "KEY", []byte("val")); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "test.vault")

	if err := svc.Save(vaultPath, "staging"); err != nil {
		t.Fatal(err)
	}

	svc2 := NewService(newMockEncryptor(), cfg)
	if err := svc2.SetEnvironment("staging"); err != nil {
		t.Fatal(err)
	}
	if err := svc2.Load(vaultPath); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(vaultPath)
	if !strings.Contains(string(data), `"environment": "staging"`) {
		t.Errorf("vault JSON should contain environment field, got: %s", string(data))
	}
}

// TestSave_RejectsEnvironmentMismatch: the environment named at Save time must
// match the environment the entries were encrypted for, or the file-level
// field and the per-entry ciphertext bindings would contradict each other.
func TestSave_RejectsEnvironmentMismatch(t *testing.T) {
	svc := newTestService(t) // bound to "development"
	dir := t.TempDir()
	if err := svc.Save(filepath.Join(dir, "x.vault"), "staging"); err == nil {
		t.Error("Save with a mismatched environment name should fail")
	}
}

// TestLoad_RejectsEnvironmentMismatch verifies the fast pre-decryption check:
// a vault file recorded for one environment is refused by a service bound to
// another (whole-file swap, e.g. staging.vault copied over production.vault).
func TestLoad_RejectsEnvironmentMismatch(t *testing.T) {
	cfg := &config.Config{
		Recipients: map[string]string{"alice": "age1testkey"},
	}
	svc := NewService(newMockEncryptor(), cfg)
	if err := svc.SetEnvironment("staging"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "staging.vault")
	if err := svc.Save(vaultPath, "staging"); err != nil {
		t.Fatal(err)
	}

	other := NewService(newMockEncryptor(), cfg)
	if err := other.SetEnvironment("production"); err != nil {
		t.Fatal(err)
	}
	err := other.Load(vaultPath)
	if err == nil {
		t.Fatal("Load should reject a vault recorded for another environment")
	}
	if !strings.Contains(err.Error(), "staging") || !strings.Contains(err.Error(), "production") {
		t.Errorf("error should name both environments, got: %v", err)
	}
}

// TestLoad_RejectsMissingEnvironmentField: blanking the plaintext environment
// field must not slip a swapped vault past the pre-decryption check — v4
// vaults always record one, so an empty field is itself evidence of tampering.
func TestLoad_RejectsMissingEnvironmentField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blanked.vault")
	content := `{"version":4,"created_at":"","updated_at":"","entries":{}}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	svc := newTestService(t)
	err := svc.Load(path)
	if err == nil {
		t.Fatal("Load should reject a v4 vault with no environment field")
	}
	if !strings.Contains(err.Error(), "environment") {
		t.Errorf("error should mention the environment field, got: %v", err)
	}
}

// TestGet_DetectsCrossEnvironmentEntry: even if the file-level field is forged
// to match, an entry encrypted for another environment fails the per-entry
// ciphertext binding at decrypt time — the authoritative check.
func TestGet_DetectsCrossEnvironmentEntry(t *testing.T) {
	cfg := &config.Config{
		Recipients: map[string]string{"alice": "age1testkey"},
	}
	enc := newMockEncryptor()

	staging := NewService(enc, cfg)
	if err := staging.SetEnvironment("staging"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := staging.Set(ctx, "DB_URL", []byte("postgres://staging")); err != nil {
		t.Fatal(err)
	}

	// Simulate the attack: copy the ciphertext into a production vault whose
	// plaintext metadata has been forged to look native.
	production := NewService(enc, cfg)
	if err := production.SetEnvironment("production"); err != nil {
		t.Fatal(err)
	}
	production.vault.Entries["DB_URL"] = staging.vault.Entries["DB_URL"]

	if _, err := production.Get(ctx, "DB_URL"); !errors.Is(err, ErrEntryIntegrity) {
		t.Errorf("Get of a cross-environment entry: want ErrEntryIntegrity, got %v", err)
	}
}

// TestSet_RequiresEnvironmentBinding: encrypting without an environment bound
// must fail closed rather than silently producing an unbound entry.
func TestSet_RequiresEnvironmentBinding(t *testing.T) {
	cfg := &config.Config{
		Recipients: map[string]string{"alice": "age1testkey"},
	}
	svc := NewService(newMockEncryptor(), cfg)

	err := svc.Set(context.Background(), "KEY", []byte("val"))
	if !errors.Is(err, ErrNoEnvironment) {
		t.Errorf("want ErrNoEnvironment, got %v", err)
	}
}

func TestSave_FilePermissions(t *testing.T) {
	if os.Getenv("OS") == "Windows_NT" {
		t.Skip("file permission checks not reliable on Windows")
	}

	svc := newTestService(t)

	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "test.vault")

	if err := svc.Save(vaultPath, "development"); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("vault file permissions = %o, want 0600", perm)
	}
}

func TestValidateKeyName_Invalid(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{"starts with digit", "123KEY"},
		{"contains dash", "MY-KEY"},
		{"contains space", "MY KEY"},
		{"contains dot", "MY.KEY"},
		{"empty string", ""},
		{"special chars", "KEY@HOME"},
		{"path traversal", "../escape"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKeyName(tt.key)
			if err == nil {
				t.Errorf("ValidateKeyName(%q) should fail", tt.key)
			}
			if !errors.Is(err, ErrInvalidKeyName) {
				t.Errorf("want ErrInvalidKeyName, got %v", err)
			}
		})
	}
}

func TestSet_BlocksDangerousVars(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	for _, name := range envcheck.DangerousVarNames() {
		t.Run(name, func(t *testing.T) {
			err := svc.Set(ctx, name, []byte("malicious"))
			if err == nil {
				t.Errorf("Set(%q) should reject dangerous variable", name)
			}
			if err != nil && !errors.Is(err, ErrDangerousKey) {
				t.Errorf("expected ErrDangerousKey for %q, got: %v", name, err)
			}
		})
	}
}

func TestValidateKeyName_Valid(t *testing.T) {
	tests := []string{"DB_HOST", "a", "_PRIVATE", "MyVar", "A1_B2_C3"}
	for _, key := range tests {
		if err := ValidateKeyName(key); err != nil {
			t.Errorf("ValidateKeyName(%q) should pass, got %v", key, err)
		}
	}
}

func TestExport_K8s(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "DB_HOST", []byte("localhost")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Set(ctx, "DB_PORT", []byte("5432")); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err := svc.Export(ctx, "k8s", &buf)
	if err != nil {
		t.Fatal(err)
	}

	out := buf.String()

	if !strings.Contains(out, "apiVersion: v1") {
		t.Error("k8s export should contain apiVersion")
	}
	if !strings.Contains(out, "kind: Secret") {
		t.Error("k8s export should contain kind: Secret")
	}
	if !strings.Contains(out, "data:") {
		t.Error("k8s export should contain data:")
	}
	if strings.Contains(out, "stringData:") {
		t.Error("k8s export must not use stringData: (non-standard YAML escapes for non-ASCII)")
	}
	wantHost := base64.StdEncoding.EncodeToString([]byte("localhost"))
	if !strings.Contains(out, "DB_HOST: "+wantHost) {
		t.Errorf("k8s export should contain DB_HOST base64-encoded, want %q in:\n%s", wantHost, out)
	}
	wantPort := base64.StdEncoding.EncodeToString([]byte("5432"))
	if !strings.Contains(out, "DB_PORT: "+wantPort) {
		t.Errorf("k8s export should contain DB_PORT base64-encoded, want %q in:\n%s", wantPort, out)
	}
}

func TestSet_EncryptError(t *testing.T) {
	cfg := &config.Config{
		Recipients: map[string]string{"alice": "age1testkey"},
	}
	enc := newMockEncryptor()
	enc.encryptFn = func([]byte, []string) (string, error) {
		return "", errors.New("encryption hardware failure")
	}
	svc := NewService(enc, cfg)
	if err := svc.SetEnvironment("development"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	err := svc.Set(ctx, "KEY", []byte("value"))
	if err == nil {
		t.Fatal("expected error when encryption fails")
	}
	if !strings.Contains(err.Error(), "encrypt") {
		t.Errorf("error should mention encrypt, got %v", err)
	}
}

func TestReset(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "A", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Set(ctx, "B", []byte("2")); err != nil {
		t.Fatal(err)
	}

	svc.Reset()

	keys, err := svc.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Errorf("after Reset, got %d keys, want 0", len(keys))
	}
}

func TestHasChanged_UndecryptableEntry(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "KEY", []byte("value")); err != nil {
		t.Fatal(err)
	}
	svc.vault.Entries["KEY"] = Entry{Encrypted: "not-decryptable"}

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("KEY=value\n"), 0600); err != nil {
		t.Fatal(err)
	}

	diffs, err := svc.Diff(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if diffs[0].Status != "changed" {
		t.Errorf("entry that fails to decrypt should always show as changed, got %q", diffs[0].Status)
	}
}

func TestHasChanged_MismatchedKeyBinding(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "KEY", []byte("value")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Set(ctx, "OTHER", []byte("value")); err != nil {
		t.Fatal(err)
	}
	// Swap in an entry whose embedded key ("OTHER") doesn't match its map key.
	svc.vault.Entries["KEY"] = svc.vault.Entries["OTHER"]

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("KEY=value\n"), 0600); err != nil {
		t.Fatal(err)
	}

	diffs, err := svc.Diff(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if diffs[0].Status != "changed" {
		t.Errorf("entry with mismatched key binding should show as changed, got %q", diffs[0].Status)
	}
}

func TestReEncryptAll_EncryptError(t *testing.T) {
	cfg := &config.Config{
		Recipients: map[string]string{"alice": "age1testkey"},
	}
	enc := newMockEncryptor()
	svc := NewService(enc, cfg)
	if err := svc.SetEnvironment("development"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := svc.Set(ctx, "A", []byte("1")); err != nil {
		t.Fatal(err)
	}

	enc.encryptFn = func([]byte, []string) (string, error) {
		return "", errors.New("encrypt failure")
	}

	err := svc.ReEncryptAll(ctx, []string{"age1newkey"})
	if err == nil {
		t.Error("expected error when re-encryption fails")
	}
}

func TestDecryptAll_DecryptError(t *testing.T) {
	cfg := &config.Config{
		Recipients: map[string]string{"alice": "age1testkey"},
	}
	enc := newMockEncryptor()
	svc := NewService(enc, cfg)
	if err := svc.SetEnvironment("development"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := svc.Set(ctx, "A", []byte("1")); err != nil {
		t.Fatal(err)
	}

	enc.decryptFn = func(string) ([]byte, error) {
		return nil, errors.New("decrypt failure")
	}

	_, err := svc.DecryptAll(ctx)
	if err == nil {
		t.Error("expected error when decryption fails")
	}
}

func TestSet_NoPlaintextHashOrSalt(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "KEY", []byte("value")); err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(svc.vault.Entries["KEY"])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "hash") || strings.Contains(string(data), "salt") {
		t.Errorf("v4 entries must not carry a plaintext hash or salt field, got %s", data)
	}
}

func TestSave_InvalidDir(t *testing.T) {
	svc := newTestService(t)
	// "development" matches the binding so the failure exercised here is the
	// filesystem write, not the environment-mismatch check.
	err := svc.Save("/nonexistent/path/to/vault.json", "development")
	if err == nil {
		t.Error("expected error saving to non-existent directory")
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.vault")
	if err := os.WriteFile(path, []byte("{invalid json"), 0600); err != nil {
		t.Fatal(err)
	}

	svc := newTestService(t)
	err := svc.Load(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestExport_K8s_SpecialChars(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "PASSWORD", []byte(`p@ss"word`)); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err := svc.Export(ctx, "k8s", &buf)
	if err != nil {
		t.Fatal(err)
	}

	out := buf.String()

	want := base64.StdEncoding.EncodeToString([]byte(`p@ss"word`))
	if !strings.Contains(out, "PASSWORD: "+want) {
		t.Errorf("k8s export should contain PASSWORD base64-encoded, want %q in:\n%s", want, out)
	}
}

func TestDiff_Removed(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "A", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Set(ctx, "B", []byte("2")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Set(ctx, "C", []byte("3")); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("A=1\n"), 0600); err != nil {
		t.Fatal(err)
	}

	diffs, err := svc.Diff(envPath)
	if err != nil {
		t.Fatal(err)
	}

	diffMap := make(map[string]string)
	for _, d := range diffs {
		diffMap[d.Key] = d.Status
	}

	if diffMap["A"] != "unchanged" {
		t.Errorf("A = %q, want unchanged", diffMap["A"])
	}
	if diffMap["B"] != "removed" {
		t.Errorf("B = %q, want removed", diffMap["B"])
	}
	if diffMap["C"] != "removed" {
		t.Errorf("C = %q, want removed", diffMap["C"])
	}
}

func TestSet_BlocksDangerousPrefixFamilies(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	names := []string{"GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_PARAMETERS", "NPM_CONFIG_SCRIPT_SHELL"}
	for _, prefix := range envcheck.DangerousPrefixes() {
		names = append(names, prefix+"SOME_SETTING")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			err := svc.Set(ctx, name, []byte("malicious"))
			if !errors.Is(err, ErrDangerousKey) {
				t.Errorf("Set(%q): want ErrDangerousKey, got %v", name, err)
			}
		})
	}
}
