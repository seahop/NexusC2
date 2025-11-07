// internal/agent/listeners/encryption.go
package listeners

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
	"log"
)

// getKey hashes the input string using SHA-256 to get a 32-byte key
func getKey(input string) []byte {
	hash := sha256.Sum256([]byte(input))
	return hash[:]
}

// decryptAES decrypts data using AES-256-GCM
func decryptAES(encrypted string, key []byte) ([]byte, error) {
	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}

// DecryptJSON decrypts a JSON string using AES with a SHA-256 derived key
func DecryptJSON(encryptedStr string, secret string) (string, error) {
	key := getKey(secret)
	plaintext, err := decryptAES(encryptedStr, key)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func encryptAES(data []byte, key []byte) (string, error) {
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

func EncryptJSON(jsonStr string, secret string) (string, error) {
	key := getKey(secret)
	return encryptAES([]byte(jsonStr), key)
}

func generateInitialSecrets(secret, seed string) (string, string) {
	log.Printf("[Secrets] Initial secret: %s", secret)
	log.Printf("[Secrets] Seed: %s", seed)

	h1 := hmac.New(sha256.New, []byte(seed))
	h1.Write([]byte(secret))
	secret2 := fmt.Sprintf("%x", h1.Sum(nil))
	log.Printf("[Secrets] Generated secret2: %s", secret2)

	h2 := hmac.New(sha256.New, []byte(seed))
	h2.Write([]byte(secret2))
	secret1 := fmt.Sprintf("%x", h2.Sum(nil))
	log.Printf("[Secrets] Generated secret1: %s", secret1)

	return secret1, secret2
}

func encryptWithNonce(data string, key string) (string, error) {
	// Convert hex string key to bytes and hash to get 32 bytes
	keyBytes := sha256.Sum256([]byte(key))

	block, err := aes.NewCipher(keyBytes[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(data), nil)
	combined := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(combined), nil
}

type HybridEncryptedData struct {
	EncryptedKey  string `json:"encrypted_key"`
	EncryptedData string `json:"encrypted_data"`
}

func DecryptDoubleEncrypted(encryptedData string, privateKeyPEM string, secret string) (string, error) {
	// Parse the hybrid structure
	var hybrid HybridEncryptedData
	if err := json.Unmarshal([]byte(encryptedData), &hybrid); err != nil {
		return "", fmt.Errorf("failed to parse hybrid data: %v", err)
	}

	// Decode the base64 private key back into PEM format
	pemData, err := base64.StdEncoding.DecodeString(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 private key: %v", err)
	}

	// Parse the private key from PEM
	block, _ := pem.Decode(pemData)
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block containing private key")
	}

	// Parse the RSA private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	// Decode the encrypted AES key
	encryptedKey, err := base64.StdEncoding.DecodeString(hybrid.EncryptedKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted key: %v", err)
	}

	// Decrypt the AES key using RSA
	aesKey, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privateKey,
		encryptedKey,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt AES key: %v", err)
	}

	// Decode the encrypted data
	encryptedBytes, err := base64.StdEncoding.DecodeString(hybrid.EncryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted data: %v", err)
	}

	// Create AES cipher
	aesBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedBytes) < nonceSize {
		return "", fmt.Errorf("encrypted data too short")
	}

	nonce, ciphertext := encryptedBytes[:nonceSize], encryptedBytes[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data: %v", err)
	}

	return string(plaintext), nil
}
