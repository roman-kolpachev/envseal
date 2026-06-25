package keyring

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// privateKeyString extracts the AGE-SECRET-KEY-1… string from an Identity via
// type assertion. Used only in tests; production code must not expose raw key strings.
func privateKeyString(t *testing.T, id *Identity) string {
	t.Helper()
	x25519, ok := id.Identity.(*age.X25519Identity)
	if !ok {
		t.Fatal("identity is not an X25519 identity")
	}
	return x25519.String()
}

func TestGenerate(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id.PublicKey, "age1") {
		t.Errorf("public key should start with age1, got %s", id.PublicKey)
	}
	if !strings.HasPrefix(privateKeyString(t, id), "AGE-SECRET-KEY-") {
		t.Errorf("private key should start with AGE-SECRET-KEY-")
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.keys")

	original, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveToFile(original, path); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PublicKey != original.PublicKey {
		t.Error("public keys don't match")
	}
}

// TestSaveToFile_RefusesSymlinkedDirectory: a symlink planted at the key
// directory (e.g. .envseal → attacker-controlled path) must not silently
// redirect where the private key file and its keys.* temp file are written.
func TestSaveToFile_RefusesSymlinkedDirectory(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "real")
	if err := os.MkdirAll(realDir, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, ".envseal")
	if err := os.Symlink(realDir, link); err != nil {
		t.Skipf("cannot create symlink on this platform: %v", err)
	}

	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveToFile(id, filepath.Join(link, "keys")); err == nil {
		t.Fatal("SaveToFile should refuse to write a private key through a symlinked directory")
	}
}

func TestLoadFromEnv(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENVSEAL_KEY", privateKeyString(t, id))

	loaded, err := LoadFromEnv("ENVSEAL_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PublicKey != id.PublicKey {
		t.Error("loaded key doesn't match")
	}
}

func TestParseRecipient(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseRecipient(id.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Error("recipient should not be nil")
	}
}

func TestDiscoverPrefersEnvVar(t *testing.T) {
	envKey, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENVSEAL_KEY", privateKeyString(t, envKey))

	fileKey, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	envsealDir := filepath.Join(dir, ".envseal")
	if err := os.MkdirAll(envsealDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := SaveToFile(fileKey, filepath.Join(envsealDir, "keys")); err != nil {
		t.Fatal(err)
	}

	got, err := Discover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicKey != envKey.PublicKey {
		t.Error("Discover should prefer env var over file")
	}
}

func TestDiscoverFallsBackToFile(t *testing.T) {
	t.Setenv("ENVSEAL_KEY", "")

	fileKey, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	envsealDir := filepath.Join(dir, ".envseal")
	if err := os.MkdirAll(envsealDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := SaveToFile(fileKey, filepath.Join(envsealDir, "keys")); err != nil {
		t.Fatal(err)
	}

	got, err := Discover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicKey != fileKey.PublicKey {
		t.Error("Discover should fall back to file")
	}
}

func TestPrivateKeyFormat(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(privateKeyString(t, id), "AGE-SECRET-KEY-") {
		t.Errorf("private key should start with AGE-SECRET-KEY-")
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/keys")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadFromFile_InvalidContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys")
	if err := os.WriteFile(path, []byte("not-a-valid-key"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFromFile(path)
	if err == nil {
		t.Error("expected error for invalid key content")
	}
}

func TestLoadFromEnv_Empty(t *testing.T) {
	t.Setenv("ENVSEAL_TEST_EMPTY", "")
	_, err := LoadFromEnv("ENVSEAL_TEST_EMPTY")
	if err == nil {
		t.Error("expected error for empty env var")
	}
}

func TestParseRecipient_Invalid(t *testing.T) {
	_, err := ParseRecipient("not-valid")
	if err == nil {
		t.Error("expected error for invalid recipient")
	}
}

func TestDiscoverNoKeyError(t *testing.T) {
	t.Setenv("ENVSEAL_KEY", "")
	dir := t.TempDir()

	_, err := Discover(dir)
	if err == nil {
		t.Fatal("expected error when no key found")
	}
	if !strings.Contains(err.Error(), "ENVSEAL_KEY") {
		t.Errorf("error should mention ENVSEAL_KEY env var, got: %v", err)
	}
}

func TestDiscoverInvalidEnvKeyError(t *testing.T) {
	t.Setenv("ENVSEAL_KEY", "not-a-valid-age-key")
	dir := t.TempDir()

	_, err := Discover(dir)
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
	if !strings.Contains(err.Error(), "ENVSEAL_KEY") {
		t.Errorf("error should mention ENVSEAL_KEY, got: %v", err)
	}
}
