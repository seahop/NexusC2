// server/docker/payloads/Windows/secure_comms.go

//go:build windows
// +build windows

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"sync"
)

type SecureComms struct {
	mu            sync.RWMutex
	secret1       string
	secret2       string
	initialSecret string
	seed          string
}

func NewSecureComms(initialSecret, seed string) *SecureComms {
	sc := &SecureComms{
		initialSecret: initialSecret,
		seed:          seed,
	}
	h1 := hmac.New(sha256.New, []byte(seed))
	h1.Write([]byte(initialSecret))
	sc.secret2 = fmt.Sprintf("%x", h1.Sum(nil))

	h2 := hmac.New(sha256.New, []byte(seed))
	h2.Write([]byte(sc.secret2))
	sc.secret1 = fmt.Sprintf("%x", h2.Sum(nil))

	fmt.Printf("[SecureComms Init] Initial Secret: %s\n", initialSecret)
	fmt.Printf("[SecureComms Init] Seed: %s\n", seed)
	fmt.Printf("[SecureComms Init] Generated secret2: %s\n", sc.secret2)
	fmt.Printf("[SecureComms Init] Generated secret1: %s\n", sc.secret1)
	return sc
}

func (sc *SecureComms) RotateSecret() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	fmt.Printf("[SecureComms Rotate] Current secret1: %s\n", sc.secret1)
	fmt.Printf("[SecureComms Rotate] Current secret2: %s\n", sc.secret2)

	h := hmac.New(sha256.New, []byte(sc.secret2))
	h.Write([]byte(sc.secret1))
	newSecret := fmt.Sprintf("%x", h.Sum(nil))

	sc.secret2 = sc.secret1
	sc.secret1 = newSecret

	fmt.Printf("[SecureComms Rotate] New secret1: %s\n", sc.secret1)
	fmt.Printf("[SecureComms Rotate] New secret2: %s\n", sc.secret2)
}

func (sc *SecureComms) GetDecryptionSecret() string {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.secret1
}

// DecryptMessage decrypts a message using the current secret
func (sc *SecureComms) DecryptMessage(encrypted string) (string, error) {
	// Convert current secret to 32-byte key via SHA-256
	secretHash := sha256.Sum256([]byte(sc.GetDecryptionSecret()))

	// Attempt decryption with current secret
	decrypted, err := DecryptAES(encrypted, secretHash[:])
	if err != nil {
		return "", fmt.Errorf("decryption failed: %v", err)
	}
	//print(decrypted)
	return decrypted, nil
}

func (sc *SecureComms) EncryptMessage(message string) (string, error) {
	// Get current secret for encryption
	sc.mu.RLock()
	currentSecret := sc.secret1
	sc.mu.RUnlock()

	// Convert current secret to 32-byte key via SHA-256 (matching decrypt)
	secretHash := sha256.Sum256([]byte(currentSecret))

	// Encrypt using the same pattern as decryption
	return EncryptAES([]byte(message), secretHash[:])
}
