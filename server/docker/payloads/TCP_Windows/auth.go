// server/docker/payloads/TCP_Windows/auth.go
// Authentication and handshake for TCP agent

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

// performAuth performs simple challenge-response authentication with the connecting parent agent
// This mirrors the SMB agent authentication pattern for consistency
func performAuth(conn *TCPConnection) error {
	// Step 1: Generate 32-byte random challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Step 2: Send challenge
	if err := conn.WriteMessage(challenge); err != nil {
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	// Step 3: Read response - expect "AUTH:" + challenge
	response, err := conn.ReadMessage()
	if err != nil {
		return fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	// Step 4: Verify response format
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

	// Step 5: Send "OK" confirmation
	if err := conn.WriteMessage([]byte("OK")); err != nil {
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	return nil
}

// performHandshake performs the RSA+AES handshake with the server via the parent agent
// This is the same as SMB - the TCP agent sends system info encrypted with server's public key
func performHandshake(conn *TCPConnection, config map[string]string) error {
	// Collect system information
	sysInfo, err := CollectSystemInfo(clientID)
	if err != nil {
		return fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Encrypt system info with RSA+AES (same as HTTPS/SMB agent handshake)
	publicKey := config["Public Key"]
	initSecret := config["Secret"]

	encryptedPayload, err := encryptHandshakePayload(sysInfo, publicKey, initSecret)
	if err != nil {
		return fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Create handshake message to send through the parent agent
	handshakeMsg := map[string]string{
		"type":    "handshake",
		"payload": encryptedPayload,
	}

	msgJSON, err := json.Marshal(handshakeMsg)
	if err != nil {
		return fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Send handshake through the connection
	if err := conn.WriteMessage(msgJSON); err != nil {
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	// Wait for handshake response with timeout
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
					continue
				}
			}

			// Not a ping, send to response channel
			responseChan <- resp
			return
		}
	}()

	// Wait for response with timeout (5 minutes for slow polling)
	select {
	case response := <-responseChan:
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

		respBytes, err := base64.StdEncoding.DecodeString(respEnvelope.Payload)
		if err != nil {
			return fmt.Errorf(ErrCtx(E18, err.Error()))
		}

		var signedResp SignedResponse
		if err := json.Unmarshal(respBytes, &signedResp); err != nil {
			return fmt.Errorf(ErrCtx(E18, err.Error()))
		}

		if err := verifyServerSignature(&signedResp, publicKey); err != nil {
			return fmt.Errorf(ErrCtx(E3, err.Error()))
		}

		if signedResp.NewClientID == "" {
			return fmt.Errorf(Err(E4))
		}
		clientID = signedResp.NewClientID

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
