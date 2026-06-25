package vault

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGet_DetectsSwappedEntries verifies the core integrity property: an
// attacker with write access to the vault file cannot swap the encrypted
// payloads of two keys without detection, because each entry's plaintext
// carries its own key name inside the age ciphertext.
func TestGet_DetectsSwappedEntries(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "DB_URL_PROD", []byte("postgres://prod")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Set(ctx, "DB_URL_STAGING", []byte("postgres://staging")); err != nil {
		t.Fatal(err)
	}

	// Simulate the attack: swap the two entries wholesale (only the ciphertext
	// travels, exactly as an attacker editing the JSON would).
	a := svc.vault.Entries["DB_URL_PROD"]
	b := svc.vault.Entries["DB_URL_STAGING"]
	svc.vault.Entries["DB_URL_PROD"] = b
	svc.vault.Entries["DB_URL_STAGING"] = a

	if _, err := svc.Get(ctx, "DB_URL_PROD"); !errors.Is(err, ErrEntryIntegrity) {
		t.Errorf("Get after swap: want ErrEntryIntegrity, got %v", err)
	}
	if _, err := svc.Get(ctx, "DB_URL_STAGING"); !errors.Is(err, ErrEntryIntegrity) {
		t.Errorf("Get after swap: want ErrEntryIntegrity, got %v", err)
	}
}

// TestDecryptAll_DetectsSwappedEntries ensures the check also protects the
// runtime injection path (envseal run / export / pull go through DecryptAll).
func TestDecryptAll_DetectsSwappedEntries(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "A", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Set(ctx, "B", []byte("2")); err != nil {
		t.Fatal(err)
	}

	ea := svc.vault.Entries["A"]
	svc.vault.Entries["A"] = svc.vault.Entries["B"]
	svc.vault.Entries["B"] = ea

	if _, err := svc.DecryptAll(ctx); !errors.Is(err, ErrEntryIntegrity) {
		t.Errorf("DecryptAll after swap: want ErrEntryIntegrity, got %v", err)
	}
}

// TestSet_BindsKeyToPlaintext verifies that Set encrypts the key name together
// with the value, rather than storing a separate plaintext hash: the binding
// only exists inside the age ciphertext, so it cannot be checked without the
// private key.
func TestSet_BindsKeyToPlaintext(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "KEY", []byte("value")); err != nil {
		t.Fatal(err)
	}

	entry := svc.vault.Entries["KEY"]
	decrypted, err := svc.enc.Decrypt(entry.Encrypted)
	if err != nil {
		t.Fatal(err)
	}
	gotEnv, gotKey, value, err := decodeEntryPlaintext(decrypted)
	if err != nil {
		t.Fatalf("decodeEntryPlaintext: %v", err)
	}
	if gotEnv != "development" || gotKey != "KEY" || string(value) != "value" {
		t.Errorf("got env=%q key=%q value=%q, want env=%q key=%q value=%q",
			gotEnv, gotKey, value, "development", "KEY", "value")
	}
}

// TestGet_RejectsMalformedEntryPlaintext: a decrypted entry whose plaintext
// has no key separator (so it cannot have come from Set) must never be
// accepted silently.
func TestGet_RejectsMalformedEntryPlaintext(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	encrypted, err := svc.enc.Encrypt([]byte("no-separator-here"), []string{"age1testkey"})
	if err != nil {
		t.Fatal(err)
	}
	svc.vault.Entries["KEY"] = Entry{Encrypted: encrypted}

	if _, err := svc.Get(ctx, "KEY"); !errors.Is(err, ErrEntryIntegrity) {
		t.Errorf("Get with malformed plaintext: want ErrEntryIntegrity, got %v", err)
	}
}

func TestSave_WritesVersion4(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "KEY", []byte("val")); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "test.vault")
	if err := svc.Save(path, "development"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v Vault
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if v.Version != 4 {
		t.Errorf("saved vault version = %d, want 4", v.Version)
	}
}

// TestLoad_RejectsVersion1 ensures pre-release version-1 files are refused
// outright instead of being read with weaker guarantees.
func TestLoad_RejectsVersion1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.vault")
	content := `{"version":1,"environment":"development","entries":{}}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	svc := newTestService(t)
	err := svc.Load(path)
	if err == nil {
		t.Fatal("Load should reject a version-1 vault")
	}
	if !strings.Contains(err.Error(), "unsupported vault version") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestLoad_RejectsVersion2 ensures the old plaintext-HMAC format is refused
// rather than read with weaker guarantees — v2's hash+salt fields are no
// longer meaningful under the v4 encrypt(env||0||key||0||value) binding.
func TestLoad_RejectsVersion2(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v2.vault")
	content := `{"version":2,"environment":"development","entries":{}}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	svc := newTestService(t)
	err := svc.Load(path)
	if err == nil {
		t.Fatal("Load should reject a version-2 vault")
	}
	if !strings.Contains(err.Error(), "unsupported vault version") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestLoad_RejectsVersion3 ensures the pre-release v3 format (key binding
// only, no environment binding) is refused outright: its entries lack the
// embedded environment name, so reading them as v4 would fail every decrypt
// with a confusing integrity error instead of this clear version message.
func TestLoad_RejectsVersion3(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v3.vault")
	content := `{"version":3,"environment":"development","entries":{}}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	svc := newTestService(t)
	err := svc.Load(path)
	if err == nil {
		t.Fatal("Load should reject a version-3 vault")
	}
	if !strings.Contains(err.Error(), "unsupported vault version") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReEncryptAll_KeepsKeyBinding(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.Set(ctx, "KEY", []byte("val")); err != nil {
		t.Fatal(err)
	}

	if err := svc.ReEncryptAll(ctx, []string{"age1testkey"}); err != nil {
		t.Fatal(err)
	}

	entry := svc.vault.Entries["KEY"]
	decrypted, err := svc.enc.Decrypt(entry.Encrypted)
	if err != nil {
		t.Fatal(err)
	}
	gotEnv, gotKey, _, err := decodeEntryPlaintext(decrypted)
	if err != nil {
		t.Fatalf("ReEncryptAll should keep the binding, decode failed: %v", err)
	}
	if gotEnv != "development" || gotKey != "KEY" {
		t.Errorf("ReEncryptAll: embedded env=%q key=%q, want env=%q key=%q",
			gotEnv, gotKey, "development", "KEY")
	}
	got, err := svc.Get(ctx, "KEY")
	if err != nil {
		t.Fatalf("Get after ReEncryptAll: %v", err)
	}
	if string(got) != "val" {
		t.Errorf("got %q, want %q", got, "val")
	}
}

// TestEncodeDecodeEntryPlaintext_DiffersPerKey guards the framing primitive
// itself: identical values under different key names (or different
// environments) must decode back to their own distinct binding.
func TestEncodeDecodeEntryPlaintext_DiffersPerKey(t *testing.T) {
	p1 := encodeEntryPlaintext("development", "KEY_A", []byte("same"))
	p2 := encodeEntryPlaintext("development", "KEY_B", []byte("same"))
	if string(p1) == string(p2) {
		t.Error("encodeEntryPlaintext must bind the key name: identical plaintext for different keys")
	}

	e1, k1, v1, err := decodeEntryPlaintext(p1)
	if err != nil || e1 != "development" || k1 != "KEY_A" || string(v1) != "same" {
		t.Errorf("decodeEntryPlaintext(p1) = %q, %q, %q, %v", e1, k1, v1, err)
	}
	e2, k2, v2, err := decodeEntryPlaintext(p2)
	if err != nil || e2 != "development" || k2 != "KEY_B" || string(v2) != "same" {
		t.Errorf("decodeEntryPlaintext(p2) = %q, %q, %q, %v", e2, k2, v2, err)
	}
}

// TestEncodeDecodeEntryPlaintext_DiffersPerEnvironment: identical key/value
// pairs framed for different environments must produce distinct plaintexts —
// this is exactly what makes a cross-environment ciphertext copy detectable.
func TestEncodeDecodeEntryPlaintext_DiffersPerEnvironment(t *testing.T) {
	p1 := encodeEntryPlaintext("staging", "KEY", []byte("same"))
	p2 := encodeEntryPlaintext("production", "KEY", []byte("same"))
	if string(p1) == string(p2) {
		t.Error("encodeEntryPlaintext must bind the environment: identical plaintext for different environments")
	}

	e1, k1, v1, err := decodeEntryPlaintext(p1)
	if err != nil || e1 != "staging" || k1 != "KEY" || string(v1) != "same" {
		t.Errorf("decodeEntryPlaintext(p1) = %q, %q, %q, %v", e1, k1, v1, err)
	}
}
