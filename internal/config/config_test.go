package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"
)

const sampleTOML = `[project]
name = "my-app"
default_env = "development"

[environments.development]
vault = ".env.vault"
source = ".env"

[environments.staging]
vault = ".env.staging.vault"
source = ".env.staging"

[environments.production]
vault = ".env.production.vault"
source = ".env.production"

[recipients]
alice = "age1cme2sghj492x7cssmnqky4f0m4z4a8xzl0k9numk4nm9vusmz4mqjn0m5w"
bob = "age1l287sgvsrh4tyg6ghq3w7fn8v60e49pl4nzm3t6am7muqeewagmsavvkfj"
`

func writeSample(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, DirName, ConfigFile)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(sampleTOML), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad(t *testing.T) {
	path := writeSample(t)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.ProjectName != "my-app" {
		t.Errorf("ProjectName = %q, want %q", cfg.ProjectName, "my-app")
	}

	if cfg.Default != "development" {
		t.Errorf("Default = %q, want %q", cfg.Default, "development")
	}

	if len(cfg.Environments) != 3 {
		t.Fatalf("len(Environments) = %d, want 3", len(cfg.Environments))
	}

	dev := cfg.Environments["development"]
	if dev.VaultPath != ".env.vault" || dev.SourcePath != ".env" {
		t.Errorf("development env = %+v", dev)
	}

	if len(cfg.Recipients) != 2 {
		t.Fatalf("len(Recipients) = %d, want 2", len(cfg.Recipients))
	}

	if cfg.Recipients["alice"] != "age1cme2sghj492x7cssmnqky4f0m4z4a8xzl0k9numk4nm9vusmz4mqjn0m5w" {
		t.Errorf("alice key = %q", cfg.Recipients["alice"])
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.toml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestSaveAndLoad_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := ConfigPath(dir)

	original := &Config{
		ProjectName: "test-project",
		Default:     "staging",
		Environments: map[string]Environment{
			"development": {VaultPath: ".env.vault", SourcePath: ".env"},
			"staging":     {VaultPath: ".env.staging.vault", SourcePath: ".env.staging"},
		},
		Recipients: map[string]string{
			"alice": "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
		},
	}

	if err := original.Save(path); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if loaded.ProjectName != original.ProjectName {
		t.Errorf("ProjectName = %q, want %q", loaded.ProjectName, original.ProjectName)
	}
	if loaded.Default != original.Default {
		t.Errorf("Default = %q, want %q", loaded.Default, original.Default)
	}
	if len(loaded.Environments) != len(original.Environments) {
		t.Errorf("len(Environments) = %d, want %d", len(loaded.Environments), len(original.Environments))
	}
	if loaded.Recipients["alice"] != original.Recipients["alice"] {
		t.Errorf("alice key mismatch")
	}
}

func testPubKey(t *testing.T) string {
	t.Helper()
	k, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return k.Recipient().String()
}

func TestAddRecipient(t *testing.T) {
	cfg := &Config{
		Recipients: map[string]string{},
	}

	key := testPubKey(t)
	if err := cfg.AddRecipient("charlie", key, false); err != nil {
		t.Fatal(err)
	}

	if cfg.Recipients["charlie"] != key {
		t.Errorf("AddRecipient failed: got %q", cfg.Recipients["charlie"])
	}
}

// TestAddRecipient_RefusesOverwriteWithoutForce guards against silently
// replacing an existing recipient's key: doing so re-encrypts the vault so
// only the new key can decrypt it, permanently revoking whoever holds the
// private key matching the old one — including the vault owner themselves if
// name is their own recipient entry (e.g. "default"). This must require
// force=true, not happen as a side effect of an ordinary grant.
func TestAddRecipient_RefusesOverwriteWithoutForce(t *testing.T) {
	oldKey := testPubKey(t)
	newKey := testPubKey(t)
	cfg := &Config{
		Recipients: map[string]string{
			"alice": oldKey,
		},
	}

	if err := cfg.AddRecipient("alice", newKey, false); err == nil {
		t.Fatal("expected error overwriting existing recipient without force")
	}
	if cfg.Recipients["alice"] != oldKey {
		t.Errorf("recipient should be unchanged after refused overwrite, got %q", cfg.Recipients["alice"])
	}
}

func TestAddRecipient_ForceOverwrite(t *testing.T) {
	oldKey := testPubKey(t)
	newKey := testPubKey(t)
	cfg := &Config{
		Recipients: map[string]string{
			"alice": oldKey,
		},
	}

	if err := cfg.AddRecipient("alice", newKey, true); err != nil {
		t.Fatal(err)
	}

	if cfg.Recipients["alice"] != newKey {
		t.Errorf("expected overwrite, got %q", cfg.Recipients["alice"])
	}
}

// TestAddRecipient_SameKeyAllowedWithoutForce re-registering the exact same
// key under its existing name changes nothing, so it must not require force.
func TestAddRecipient_SameKeyAllowedWithoutForce(t *testing.T) {
	key := testPubKey(t)
	cfg := &Config{
		Recipients: map[string]string{
			"alice": key,
		},
	}

	if err := cfg.AddRecipient("alice", key, false); err != nil {
		t.Fatalf("re-adding the same key should not require force: %v", err)
	}
}

func TestRemoveRecipient(t *testing.T) {
	cfg := &Config{
		Recipients: map[string]string{
			"alice": "age1abc...",
			"bob":   "age1def...",
		},
	}

	if err := cfg.RemoveRecipient("alice"); err != nil {
		t.Fatal(err)
	}

	if _, exists := cfg.Recipients["alice"]; exists {
		t.Error("alice should be removed")
	}
	if _, exists := cfg.Recipients["bob"]; !exists {
		t.Error("bob should still exist")
	}
}

func TestRemoveRecipient_NonExistent(t *testing.T) {
	cfg := &Config{
		Recipients: map[string]string{},
	}
	err := cfg.RemoveRecipient("ghost")
	if err == nil {
		t.Error("expected error for non-existent recipient")
	}
}

func TestRecipientKeys(t *testing.T) {
	cfg := &Config{
		Recipients: map[string]string{
			"alice": "age1aaa",
			"bob":   "age1bbb",
		},
	}

	keys := cfg.RecipientKeys()

	if len(keys) != 2 {
		t.Fatalf("len(keys) = %d, want 2", len(keys))
	}

	slices.Sort(keys)
	if keys[0] != "age1aaa" || keys[1] != "age1bbb" {
		t.Errorf("keys = %v", keys)
	}
}

func TestRecipientKeys_Empty(t *testing.T) {
	cfg := &Config{
		Recipients: map[string]string{},
	}

	keys := cfg.RecipientKeys()

	if len(keys) != 0 {
		t.Errorf("expected empty slice, got %v", keys)
	}
}

func TestGetEnvironment(t *testing.T) {
	cfg := &Config{
		Environments: map[string]Environment{
			"development": {VaultPath: ".env.vault", SourcePath: ".env"},
		},
	}

	env, err := cfg.GetEnvironment("development")
	if err != nil {
		t.Fatalf("GetEnvironment() error: %v", err)
	}
	if env.VaultPath != ".env.vault" {
		t.Errorf("VaultPath = %q", env.VaultPath)
	}
}

func TestGetEnvironment_NotFound(t *testing.T) {
	cfg := &Config{
		Environments: map[string]Environment{},
	}

	_, err := cfg.GetEnvironment("production")
	if err == nil {
		t.Fatal("expected error for missing environment")
	}
}

func TestSetDefault(t *testing.T) {
	cfg := Default("test")

	if err := cfg.SetDefault("staging"); err != nil {
		t.Fatalf("SetDefault() error: %v", err)
	}
	if cfg.Default != "staging" {
		t.Errorf("Default = %q, want %q", cfg.Default, "staging")
	}
}

func TestSetDefault_NotFound(t *testing.T) {
	cfg := Default("test")

	err := cfg.SetDefault("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent environment")
	}
	if cfg.Default != "development" {
		t.Error("Default should not change on error")
	}
}

func TestEnvironmentNames(t *testing.T) {
	cfg := Default("test")

	names := cfg.EnvironmentNames()
	if len(names) != 3 {
		t.Fatalf("len(names) = %d, want 3", len(names))
	}

	expected := map[string]bool{"development": false, "staging": false, "production": false}
	for _, name := range names {
		if _, ok := expected[name]; !ok {
			t.Errorf("unexpected environment: %q", name)
		}
		expected[name] = true
	}
	for name, found := range expected {
		if !found {
			t.Errorf("missing environment: %q", name)
		}
	}
}

func TestAddEnvironment(t *testing.T) {
	cfg := Default("test")

	if err := cfg.AddEnvironment("testing"); err != nil {
		t.Fatalf("AddEnvironment() error: %v", err)
	}

	env, err := cfg.GetEnvironment("testing")
	if err != nil {
		t.Fatalf("GetEnvironment() error: %v", err)
	}
	wantVault := VaultFilePath("testing")
	if env.VaultPath != wantVault {
		t.Errorf("VaultPath = %q, want %q", env.VaultPath, wantVault)
	}
	if env.SourcePath != ".env.testing" {
		t.Errorf("SourcePath = %q, want %q", env.SourcePath, ".env.testing")
	}
}

func TestAddEnvironment_AlreadyExists(t *testing.T) {
	cfg := Default("test")

	err := cfg.AddEnvironment("development")
	if err == nil {
		t.Fatal("expected error for existing environment")
	}
}

func TestCurrentEnvironment(t *testing.T) {
	cfg := &Config{
		Default: "staging",
		Environments: map[string]Environment{
			"staging": {VaultPath: ".env.staging.vault", SourcePath: ".env.staging"},
		},
	}

	env := cfg.CurrentEnvironment()

	if env.VaultPath != ".env.staging.vault" {
		t.Errorf("VaultPath = %q, want %q", env.VaultPath, ".env.staging.vault")
	}
}

func TestDirPath(t *testing.T) {
	got := DirPath("/project")
	if !strings.HasSuffix(got, DirName) {
		t.Errorf("DirPath = %q, want suffix %q", got, DirName)
	}
}

func TestAuditPath(t *testing.T) {
	got := AuditPath("/project")
	if !strings.HasSuffix(got, AuditFile) {
		t.Errorf("AuditPath = %q, want suffix %q", got, AuditFile)
	}
}

func TestKeysPath(t *testing.T) {
	got := KeysPath("/project")
	if !strings.HasSuffix(got, KeysFile) {
		t.Errorf("KeysPath = %q, want suffix %q", got, KeysFile)
	}
}

func TestVaultDirPath(t *testing.T) {
	got := VaultDirPath("/project")
	if !strings.HasSuffix(got, VaultDir) {
		t.Errorf("VaultDirPath = %q, want suffix %q", got, VaultDir)
	}
}

func TestVaultFilePath(t *testing.T) {
	got := VaultFilePath("staging")
	if !strings.HasSuffix(got, "staging.vault") {
		t.Errorf("VaultFilePath = %q, want suffix %q", got, "staging.vault")
	}
}

func TestConfigPath(t *testing.T) {
	got := ConfigPath("/project")
	if !strings.HasSuffix(got, ConfigFile) {
		t.Errorf("ConfigPath = %q, want suffix %q", got, ConfigFile)
	}
}

func TestValidateProjectName(t *testing.T) {
	valid := []string{
		"",                        // empty is fine — init defaults it to the directory name
		"my-app",
		"My Cool App 2026",
		"日本語プロジェクト", // free-form display metadata: any printable content is allowed
		strings.Repeat("a", maxProjectNameLength), // exactly at the boundary
	}
	for _, name := range valid {
		if err := ValidateProjectName(name); err != nil {
			t.Errorf("ValidateProjectName(%q) = %v, want nil", name, err)
		}
	}

	invalid := map[string]string{
		strings.Repeat("a", maxProjectNameLength+1): "too long",
		"evil\x1b[31mname":                          "control character (escape)",
		"name\x00withnull":                          "control character (null)",
		"trailing\x7f":                               "DEL character",
	}
	for name, reason := range invalid {
		if err := ValidateProjectName(name); err == nil {
			t.Errorf("ValidateProjectName(%q) should reject (%s)", name, reason)
		}
	}
}

func TestAddRecipient_NilMap(t *testing.T) {
	key := testPubKey(t)
	cfg := &Config{}
	if err := cfg.AddRecipient("alice", key, false); err != nil {
		t.Fatal(err)
	}
	if cfg.Recipients["alice"] != key {
		t.Error("AddRecipient should initialize nil map")
	}
}

func TestAddRecipient_InvalidKey(t *testing.T) {
	cfg := &Config{Recipients: map[string]string{}}
	if err := cfg.AddRecipient("alice", "not-a-valid-key", false); err == nil {
		t.Error("expected error for invalid age public key")
	}
}

func TestValidateEnvironmentName_Invalid(t *testing.T) {
	tests := []string{"env name!", "../escape", "has space", "a@b", ""}
	for _, name := range tests {
		if err := ValidateEnvironmentName(name); err == nil {
			t.Errorf("ValidateEnvironmentName(%q) should fail", name)
		}
	}
}

func TestSetDefault_InvalidName(t *testing.T) {
	cfg := Default("test")
	err := cfg.SetDefault("bad name!")
	if err == nil {
		t.Error("expected error for invalid env name")
	}
}

func TestSave_InvalidDir(t *testing.T) {
	cfg := Default("test")
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	err := cfg.Save(filepath.Join(blocker, "subdir", "config.toml"))
	if err == nil {
		t.Error("expected error saving through a file path")
	}
}

func TestSave_VerifyContent(t *testing.T) {
	dir := t.TempDir()
	path := ConfigPath(dir)
	key := testPubKey(t)
	cfg := Default("my-project")
	if err := cfg.AddRecipient("alice", key, false); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "my-project") {
		t.Error("saved config should contain project name")
	}
	if !strings.Contains(content, "alice") {
		t.Error("saved config should contain recipient name")
	}
	if !strings.Contains(content, key) {
		t.Error("saved config should contain recipient key")
	}
}

func TestAddEnvironment_InvalidName(t *testing.T) {
	cfg := Default("test")
	err := cfg.AddEnvironment("bad name!")
	if err == nil {
		t.Error("expected error for invalid environment name")
	}
}

func TestLoad_InvalidDefaultEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DirName, ConfigFile)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}

	tampered := `[project]
name = "test"
default_env = "../../escape"

[environments.dev]
vault = ".env.vault"
source = ".env"
`
	if err := os.WriteFile(path, []byte(tampered), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load should reject config with invalid default_env")
	}
	if !strings.Contains(err.Error(), "default_env") {
		t.Errorf("error should mention default_env, got: %v", err)
	}
}

func TestNewEnvironment(t *testing.T) {
	env := NewEnvironment("staging")
	if env.SourcePath != ".env.staging" {
		t.Errorf("SourcePath = %q, want %q", env.SourcePath, ".env.staging")
	}
	if !strings.Contains(env.VaultPath, "staging") {
		t.Errorf("VaultPath = %q, should contain staging", env.VaultPath)
	}
}
