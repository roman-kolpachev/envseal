package crypto

import (
	"bytes"
	"testing"

	"github.com/roman-kolpachev/envseal/internal/keyring"
)

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	id, _ := keyring.Generate()
	enc := NewAgeEncryptor(id)

	plaintext := []byte("super-secret-value")
	ciphertext, err := enc.Encrypt(plaintext, []string{id.PublicKey})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if ciphertext == string(plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("got %q, want %q", decrypted, plaintext)
	}
}

func TestEncrypt_MultipleRecipients(t *testing.T) {
	id1, _ := keyring.Generate()
	id2, _ := keyring.Generate()

	enc1 := NewAgeEncryptor(id1)
	enc2 := NewAgeEncryptor(id2)

	ciphertext, _ := enc1.Encrypt([]byte("shared-secret"), []string{
		id1.PublicKey,
		id2.PublicKey,
	})

	plain1, err := enc1.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("recipient 1 decrypt: %v", err)
	}

	plain2, err := enc2.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("recipient 2 decrypt: %v", err)
	}

	if string(plain1) != "shared-secret" || string(plain2) != "shared-secret" {
		t.Error("both recipients should get same plaintext")
	}
}

func TestDecrypt_WrongKey_Fails(t *testing.T) {
	id1, _ := keyring.Generate()
	id2, _ := keyring.Generate()

	enc1 := NewAgeEncryptor(id1)
	enc2 := NewAgeEncryptor(id2)

	ciphertext, _ := enc1.Encrypt([]byte("secret"), []string{id1.PublicKey})

	_, err := enc2.Decrypt(ciphertext)
	if err == nil {
		t.Error("wrong key should fail to decrypt")
	}
}

func TestEncrypt_EmptyRecipients_Fails(t *testing.T) {
	id, _ := keyring.Generate()
	enc := NewAgeEncryptor(id)

	_, err := enc.Encrypt([]byte("data"), []string{})
	if err == nil {
		t.Error("should fail with no recipients")
	}
}

func TestEncrypt_InvalidRecipient(t *testing.T) {
	id, _ := keyring.Generate()
	enc := NewAgeEncryptor(id)
	_, err := enc.Encrypt([]byte("data"), []string{"not-a-valid-recipient"})
	if err == nil {
		t.Error("should fail with invalid recipient")
	}
}

func TestDecrypt_InvalidBase64(t *testing.T) {
	id, _ := keyring.Generate()
	enc := NewAgeEncryptor(id)
	_, err := enc.Decrypt("!!!not-base64!!!")
	if err == nil {
		t.Error("should fail with invalid base64")
	}
}

func TestDecrypt_InvalidCiphertext(t *testing.T) {
	id, _ := keyring.Generate()
	enc := NewAgeEncryptor(id)
	_, err := enc.Decrypt("aGVsbG8=")
	if err == nil {
		t.Error("should fail with invalid ciphertext")
	}
}
