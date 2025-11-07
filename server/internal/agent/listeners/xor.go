package listeners

import (
	"encoding/base64"
)

// xorEncryptString encrypts a string using XOR
func xorEncryptString(input, key string) string {
	var result []byte
	keyBytes := []byte(key)
	for i := 0; i < len(input); i++ {
		result = append(result, input[i]^keyBytes[i%len(keyBytes)])
	}
	return base64.StdEncoding.EncodeToString(result)
}

// xorDecryptString decrypts a string using XOR (same as encrypt)
func xorDecryptString(encoded, key string) (string, error) {
	encrypted, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	var result []byte
	keyBytes := []byte(key)
	for i := 0; i < len(encrypted); i++ {
		result = append(result, encrypted[i]^keyBytes[i%len(keyBytes)])
	}
	return string(result), nil
}
