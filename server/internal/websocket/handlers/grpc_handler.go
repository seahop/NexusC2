// internal/websocket/handlers/grpc_handler.go
package handlers

import (
	"c2/internal/websocket/agent"
	"fmt"
	"log"
	"os"
	"time"
)

// ensureGRPCConnection ensures the gRPC connection to the agent service is established
func (h *WSHandler) ensureGRPCConnection() error {
	maxRetries := 10
	retryDelay := 5 * time.Second
	retries := 0

	clientID := "websocket_service"

	// Read gRPC address from environment, fall back to localhost for local dev
	grpcAddr := os.Getenv("GRPC_ADDRESS")
	if grpcAddr == "" {
		grpcAddr = "localhost:50051"
	}

	for {
		logMessage(LOG_NORMAL, "Attempting gRPC connection to agent service at %s (attempt %d)...", grpcAddr, retries+1)
		client, err := agent.NewClient(grpcAddr, clientID)
		if err == nil {
			h.agentClient = client
			log.Println("gRPC connection to agent service successful")
			return nil
		}

		logMessage(LOG_NORMAL, "gRPC connection attempt failed: %v", err)
		retries++

		if retries >= maxRetries {
			return fmt.Errorf("failed to connect to agent service after %d attempts: %v", retries, err)
		}

		logMessage(LOG_NORMAL, "Retrying gRPC connection in %v...", retryDelay)
		time.Sleep(retryDelay)
	}
}
