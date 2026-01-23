// server/docker/payloads/TCP_Darwin/encryption.go
// Encryption utilities for TCP agent

//go:build darwin
// +build darwin

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
	"io"
)

// getKey hashes the input string using SHA-256 to get a 32-byte key
func getKey(input string) []byte {
	hash := sha256.Sum256([]byte(input))
	return hash[:]
}

// CreateHMAC generates an HMAC using SHA-256
func CreateHMAC(data, key string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// EncryptAES encrypts data using AES-256-GCM
func EncryptAES(data []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}
	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAES decrypts data using AES-256-GCM
func DecryptAES(combined string, key []byte) (string, error) {
	// Step 1: Base64 Decode
	allBytes, err := base64.StdEncoding.DecodeString(combined)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Step 2: Extract Nonce and Ciphertext
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	nonceSize := aesGCM.NonceSize()
	if len(allBytes) < nonceSize {
		return "", fmt.Errorf(Err(E2))
	}

	nonce := allBytes[:nonceSize]
	ciphertext := allBytes[nonceSize:]

	// Step 3: Decrypt
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	return string(plaintext), nil
}

// EncryptJSON encrypts a JSON string using AES with a SHA-256 derived key
func EncryptJSON(jsonStr string, secret string) (string, error) {
	key := getKey(secret)
	return EncryptAES([]byte(jsonStr), key)
}

// HybridEncryptedData represents our layered encryption structure
type HybridEncryptedData struct {
	// The AES key encrypted with RSA
	EncryptedKey string `json:"encrypted_key"`
	// The actual data encrypted with AES
	EncryptedData string `json:"encrypted_data"`
}

// xorDecrypt decrypts a base64-encoded XOR-encrypted string using the given key
// This matches the pattern used by HTTPS agents for runtime decryption
func xorDecrypt(encoded, key string) string {
	if encoded == "" || key == "" {
		return ""
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}

	result := make([]byte, len(decoded))
	keyBytes := []byte(key)
	for i := 0; i < len(decoded); i++ {
		result[i] = decoded[i] ^ keyBytes[i%len(keyBytes)]
	}

	return string(result)
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

func EncryptInitialHandshake(jsonData string, secret string, pubKeyStr string) (string, error) {
	// Generate a random AES key for this session
	aesKey := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(aesKey); err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Encrypt the actual data with the random AES key
	aesBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Encrypt the data
	encryptedData := gcm.Seal(nonce, nonce, []byte(jsonData), nil)
	encodedData := base64.StdEncoding.EncodeToString(encryptedData)

	// Parse the public key
	pemBlock, _ := pem.Decode([]byte(pubKeyStr))
	if pemBlock == nil {
		return "", fmt.Errorf(Err(E18))
	}

	// Parse PKCS1 format
	pub, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Encrypt the AES key with RSA
	encryptedKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		pub,
		aesKey,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Create the hybrid structure
	hybrid := HybridEncryptedData{
		EncryptedKey:  base64.StdEncoding.EncodeToString(encryptedKey),
		EncryptedData: encodedData,
	}

	// Convert to JSON
	hybridJson, err := json.Marshal(hybrid)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	return string(hybridJson), nil
}
