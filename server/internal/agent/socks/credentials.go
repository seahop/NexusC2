// internal/agent/socks/credentials.go
package socks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// Credentials stores authentication information for the SOCKS proxy
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	SSHKey   []byte `json:"ssh_key"` // SSH private key in PEM format
}

// GenerateCredentials creates new random credentials
func GenerateCredentials() (*Credentials, error) {
	// Generate random username and password
	username := make([]byte, 12)
	if _, err := rand.Read(username); err != nil {
		return nil, fmt.Errorf("failed to generate username: %v", err)
	}

	password := make([]byte, 32)
	if _, err := rand.Read(password); err != nil {
		return nil, fmt.Errorf("failed to generate password: %v", err)
	}

	// Generate SSH key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SSH key: %v", err)
	}

	// Convert private key to PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Create credentials
	creds := &Credentials{
		Username: base64.RawURLEncoding.EncodeToString(username),
		Password: base64.RawURLEncoding.EncodeToString(password),
		SSHKey:   pem.EncodeToMemory(privateKeyPEM),
	}

	return creds, nil
}
