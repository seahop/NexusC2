// server/docker/payloads/Darwin/encryption.go

//go:build darwin
// +build darwin

package main

import (
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
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}
	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAES decrypts data using AES-256-GCM
func DecryptAES(combined string, key []byte) (string, error) {
	fmt.Println("Starting DecryptAES...")

	// Step 1: Base64 Decode
	allBytes, err := base64.StdEncoding.DecodeString(combined)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %v", err)
	}
	fmt.Printf("Decoded base64, length: %d\n", len(allBytes))

	// Step 2: Extract Nonce and Ciphertext
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(allBytes) < nonceSize {
		return "", fmt.Errorf("data too short")
	}

	nonce := allBytes[:nonceSize]
	ciphertext := allBytes[nonceSize:]
	fmt.Printf("Nonce: %x\n", nonce)
	fmt.Printf("Ciphertext length: %d\n", len(ciphertext))

	// Step 3: Decrypt
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %v", err)
	}

	fmt.Println("Decryption successful!")
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

func EncryptInitialHandshake(jsonData string, secret string, pubKeyStr string) (string, error) {
	// Generate a random AES key for this session
	aesKey := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(aesKey); err != nil {
		return "", fmt.Errorf("failed to generate random AES key: %v", err)
	}

	// Encrypt the actual data with the random AES key
	aesBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt the data
	encryptedData := gcm.Seal(nonce, nonce, []byte(jsonData), nil)
	encodedData := base64.StdEncoding.EncodeToString(encryptedData)

	// Parse the public key
	pemBlock, _ := pem.Decode([]byte(pubKeyStr))
	if pemBlock == nil {
		return "", fmt.Errorf("failed to parse PEM block containing public key")
	}

	// Parse PKCS1 format
	pub, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %v", err)
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
		return "", fmt.Errorf("RSA encryption of AES key failed: %v", err)
	}

	// Create the hybrid structure
	hybrid := HybridEncryptedData{
		EncryptedKey:  base64.StdEncoding.EncodeToString(encryptedKey),
		EncryptedData: encodedData,
	}

	// Convert to JSON
	hybridJson, err := json.Marshal(hybrid)
	if err != nil {
		return "", fmt.Errorf("failed to marshal hybrid data: %v", err)
	}

	return string(hybridJson), nil
}
