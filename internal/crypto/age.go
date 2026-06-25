package crypto

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"

	"filippo.io/age"
	"github.com/roman-kolpachev/envseal/internal/keyring"
)

var _ Encryptor = (*AgeEncryptor)(nil)

type Encryptor interface {
	Encrypt(plaintext []byte, recipients []string) (string, error)
	Decrypt(ciphertext string) ([]byte, error)
}

type AgeEncryptor struct {
	identity *keyring.Identity
}

func NewAgeEncryptor(id *keyring.Identity) *AgeEncryptor {
	return &AgeEncryptor{identity: id}
}

func (e *AgeEncryptor) Encrypt(plaintext []byte, recipients []string) (string, error) {
	if len(recipients) == 0 {
		return "", fmt.Errorf("no recipients provided")
	}

	var recs []age.Recipient
	for _, r := range recipients {
		parsed, err := age.ParseX25519Recipient(r)
		if err != nil {
			return "", fmt.Errorf("parse recipient %q: %w", r, err)
		}
		recs = append(recs, parsed)
	}

	var buf bytes.Buffer
	// buf receives only ciphertext (age encrypts through w before writing
	// here), so zeroing it is defence in depth — not a plaintext-hygiene
	// requirement. Do not rely on this clear to scrub secret material.
	defer func() { clear(buf.Bytes()) }()
	w, err := age.Encrypt(&buf, recs...)
	if err != nil {
		return "", fmt.Errorf("create encryptor: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return "", fmt.Errorf("write plaintext: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("finalize encryption: %w", err)
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}


const maxPlaintextSize = 10 * 1024 * 1024 // 10 MiB

func (e *AgeEncryptor) Decrypt(ciphertext string) ([]byte, error) {
	// Guard against a nil identity: constructing the encryptor with a nil
	// keyring must surface as an error, not a nil-pointer panic mid-decrypt.
	if e == nil || e.identity == nil || e.identity.Identity == nil {
		return nil, fmt.Errorf("decrypt: no private key identity configured")
	}
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	r, err := age.Decrypt(bytes.NewReader(raw), e.identity.Identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	limited := io.LimitReader(r, maxPlaintextSize+1)
	plaintext, err := io.ReadAll(limited)
	if err != nil {
		clear(plaintext)
		return nil, fmt.Errorf("read plaintext: %w", err)
	}
	if len(plaintext) > maxPlaintextSize {
		clear(plaintext)
		return nil, fmt.Errorf("decrypted plaintext exceeds maximum size of %d bytes", maxPlaintextSize)
	}

	return plaintext, nil
}
