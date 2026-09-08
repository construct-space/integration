// Package crypto seals OAuth refresh tokens with AES-256-GCM under
// the service's encryption key. The key never leaves the integration
// service; rotating it means re-encrypting all existing tokens.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Sealer holds a ready GCM AEAD bound to the configured key.
type Sealer struct {
	gcm cipher.AEAD
}

// New parses a 64-char hex string (= 32 bytes / 256 bits) into a
// Sealer. Anything else is rejected so misconfiguration fails loud.
func New(hexKey string) (*Sealer, error) {
	if hexKey == "" {
		return nil, errors.New("INTEGRATION_ENCRYPTION_KEY is empty")
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes (64 hex chars), got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{gcm: gcm}, nil
}

// Seal returns nonce || ciphertext. Random nonce per call.
func (s *Sealer) Seal(plain []byte) ([]byte, error) {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return s.gcm.Seal(nonce, nonce, plain, nil), nil
}

// Open reverses Seal. Returns error on tamper / wrong key.
func (s *Sealer) Open(sealed []byte) ([]byte, error) {
	if len(sealed) < s.gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	n := s.gcm.NonceSize()
	return s.gcm.Open(nil, sealed[:n], sealed[n:], nil)
}
