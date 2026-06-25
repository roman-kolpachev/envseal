package vault

import (
	"errors"
	"strings"
)

type mockEncryptor struct {
	encryptFn func([]byte, []string) (string, error)
	decryptFn func(string) ([]byte, error)
}

func newMockEncryptor() *mockEncryptor {
	return &mockEncryptor{
		encryptFn: func(data []byte, _ []string) (string, error) {
			return "ENC:" + string(data), nil
		},
		decryptFn: func(data string) ([]byte, error) {
			if !strings.HasPrefix(data, "ENC:") {
				return nil, errors.New("cannot decrypt")
			}
			return []byte(data[4:]), nil
		},
	}
}

func (m *mockEncryptor) Encrypt(plaintext []byte, recipients []string) (string, error) {
	return m.encryptFn(plaintext, recipients)
}

func (m *mockEncryptor) Decrypt(ciphertext string) ([]byte, error) {
	return m.decryptFn(ciphertext)
}
