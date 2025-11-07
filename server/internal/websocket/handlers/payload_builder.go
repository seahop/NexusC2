// internal/websocket/handlers/payload_builder.go
package handlers

import (
	builder "c2/internal/builder/websocket"
	"c2/internal/websocket/hub"
	"context"
	"encoding/json"
)

// handleCreatePayload handles payload creation requests
func (h *WSHandler) handleCreatePayload(client *hub.Client, message []byte) error {
	var req builder.PayloadRequest
	if err := json.Unmarshal(message, &req); err != nil {
		logMessage(LOG_NORMAL, "Failed to unmarshal create payload message: %v", err)
		return err
	}

	// Send an acknowledgment to the client that the payload request has been received
	response := Response{
		Status:  "in_progress",
		Message: "Payload creation in progress",
	}
	responseJSON, err := json.Marshal(response)
	if err == nil {
		client.Send <- responseJSON
	} else {
		logMessage(LOG_NORMAL, "Failed to marshal in-progress response: %v", err)
	}

	// Pass the Hub and listener manager to the builder
	b, err := builder.NewBuilder(h.hub.ListenerManager, h.hub, h.db, h.agentClient)
	if err != nil {
		logMessage(LOG_NORMAL, "Failed to create builder: %v", err)
		return err
	}

	// Use the listener name provided in the request
	logMessage(LOG_MINIMAL, "Starting payload build for listener: %s", req.Data.Listener)
	if err := b.BuildPayload(context.Background(), req, client.Username); err != nil {
		logMessage(LOG_NORMAL, "Payload build failed for listener %s: %v", req.Data.Listener, err)
		return err
	}

	logMessage(LOG_MINIMAL, "Payload build completed successfully for listener: %s", req.Data.Listener)
	return nil
}
