// internal/websocket/handlers/listener_operations.go
package handlers

import (
	"c2/internal/websocket/agent"
	"c2/internal/websocket/hub"
	pb "c2/proto"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"time"
)

// StartExistingListeners checks the database for existing listeners and starts them via gRPC
func (h *WSHandler) StartExistingListeners() error {
	if h.agentClient == nil {
		return fmt.Errorf("agentClient is not initialized")
	}

	log.Println("Checking for existing listeners in the database...")
	rows, err := h.db.Query(`
		SELECT name, protocol, port, ip,
			COALESCE(get_profile, 'default-get'),
			COALESCE(post_profile, 'default-post'),
			COALESCE(server_response_profile, 'default-response')
		FROM listeners
	`)
	if err != nil {
		return fmt.Errorf("failed to query existing listeners: %v", err)
	}
	defer rows.Close()

	var listeners []struct {
		name                  string
		protocol              string
		port                  int
		bindIP                string
		getProfile            string
		postProfile           string
		serverResponseProfile string
	}

	// First collect all listeners
	for rows.Next() {
		var l struct {
			name                  string
			protocol              string
			port                  int
			bindIP                string
			getProfile            string
			postProfile           string
			serverResponseProfile string
		}
		if err := rows.Scan(&l.name, &l.protocol, &l.port, &l.bindIP,
			&l.getProfile, &l.postProfile, &l.serverResponseProfile); err != nil {
			logMessage(LOG_NORMAL, "Failed to scan listener row: %v", err)
			continue
		}
		listeners = append(listeners, l)
	}

	// Track results
	results := make(map[string]struct {
		success bool
		message string
	})

	// Try to start each listener
	maxRetries := 5
	for _, l := range listeners {
		listenerType, err := agent.ParseListenerType(l.protocol)
		if err != nil {
			logMessage(LOG_NORMAL, "Skipping listener '%s' due to unsupported protocol: %s", l.name, err)
			results[l.name] = struct {
				success bool
				message string
			}{false, fmt.Sprintf("unsupported protocol: %s", err)}
			continue
		}

		var lastResp *pb.ListenerResponse
		var lastErr error

		// Try with retries
		for attempt := 0; attempt < maxRetries; attempt++ {
			logMessage(LOG_NORMAL, "Attempting to start existing listener: %s on %s:%d (attempt %d/%d), profiles: GET=%s POST=%s Response=%s",
				l.name, l.bindIP, l.port, attempt+1, maxRetries, l.getProfile, l.postProfile, l.serverResponseProfile)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			resp, err := h.agentClient.StartListener(ctx, l.name, int32(l.port), listenerType, false,
				l.getProfile, l.postProfile, l.serverResponseProfile)
			cancel()

			if err == nil && resp.Success {
				logMessage(LOG_MINIMAL, "Listener %s started successfully", l.name)
				results[l.name] = struct {
					success bool
					message string
				}{true, resp.Message}
				break
			}

			lastResp = resp
			lastErr = err

			if attempt < maxRetries-1 {
				delay := time.Duration(math.Pow(2, float64(attempt))) * time.Second
				logMessage(LOG_NORMAL, "Failed to start listener %s: %v. Retrying in %v...", l.name, err, delay)
				time.Sleep(delay)
			}
		}

		// If all retries failed, store the last failure
		if _, ok := results[l.name]; !ok {
			failMsg := "unknown error"
			if lastErr != nil {
				failMsg = lastErr.Error()
			} else if lastResp != nil {
				failMsg = lastResp.Message
			}
			results[l.name] = struct {
				success bool
				message string
			}{false, failMsg}
		}
	}

	// Broadcast results to all connected clients
	for name, result := range results {
		msg := struct {
			Type string `json:"type"`
			Data struct {
				Name    string `json:"name"`
				Success bool   `json:"success"`
				Message string `json:"message"`
			} `json:"data"`
		}{
			Type: "listener_status",
			Data: struct {
				Name    string `json:"name"`
				Success bool   `json:"success"`
				Message string `json:"message"`
			}{
				Name:    name,
				Success: result.success,
				Message: result.message,
			},
		}

		if jsonData, err := json.Marshal(msg); err == nil {
			if err := h.hub.BroadcastToAll(context.Background(), jsonData); err != nil {
				logMessage(LOG_NORMAL, "Failed to broadcast listener status: %v", err)
			}
		}
	}

	// Return error if any listeners failed
	for name, result := range results {
		if !result.success {
			return fmt.Errorf("failed to start listener %s: %s", name, result.message)
		}
	}

	return nil
}

// handleDeleteListener handles listener deletion requests
func (h *WSHandler) handleDeleteListener(client *hub.Client, message []byte) error {
	var msg struct {
		Type string `json:"type"`
		Data struct {
			Name string `json:"name"`
		} `json:"data"`
	}

	if err := json.Unmarshal(message, &msg); err != nil {
		logMessage(LOG_NORMAL, "Failed to unmarshal delete listener message: %v", err)
		return err
	}

	listenerName := msg.Data.Name
	logMessage(LOG_MINIMAL, "Attempting to delete listener: %s", listenerName)

	// Ensure gRPC connection is active before attempting the delete
	if h.agentClient == nil {
		log.Println("gRPC client is not connected. Attempting to reconnect...")
		if err := h.ensureGRPCConnection(); err != nil {
			logMessage(LOG_NORMAL, "Failed to reconnect to gRPC service: %v", err)
			return err
		}
	}

	// Delete listener from the agent service using gRPC
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := h.agentClient.StopListener(ctx, listenerName)
	if err != nil {
		logMessage(LOG_NORMAL, "Failed to stop listener via gRPC: %v", err)
		return err
	}

	logMessage(LOG_MINIMAL, "gRPC StopListener successfully stopped listener: %s", listenerName)

	// Continue with local deletion if gRPC request was successful
	if err := h.hub.ListenerManager.DeleteByName(listenerName); err != nil {
		logMessage(LOG_NORMAL, "Failed to delete listener: %v", err)
		response := Response{
			Type:    "listener_delete",
			Status:  "error",
			Message: err.Error(),
		}
		responseJSON, _ := json.Marshal(response)
		client.Send <- responseJSON
		return err
	}

	// Send success response to requesting client
	response := Response{
		Type:    "listener_delete",
		Status:  "success",
		Message: "Listener deleted successfully",
	}
	responseJSON, _ := json.Marshal(response)
	client.Send <- responseJSON

	// Prepare broadcast message
	broadcast := struct {
		Type string `json:"type"`
		Data struct {
			Event string `json:"event"`
			Name  string `json:"name"`
		} `json:"data"`
	}{
		Type: "listener_update",
		Data: struct {
			Event string `json:"event"`
			Name  string `json:"name"`
		}{
			Event: "deleted",
			Name:  listenerName,
		},
	}

	broadcastJSON, _ := json.Marshal(broadcast)
	ctx = context.Background()
	logMessage(LOG_MINIMAL, "Broadcasting listener deletion: %s", listenerName)

	if err := h.hub.BroadcastToAll(ctx, broadcastJSON); err != nil {
		if errors.Is(err, hub.ErrPartialBroadcast) {
			logMessage(LOG_NORMAL, "Warning: Partial broadcast failure occurred while deleting listener %s", listenerName)
		} else {
			logMessage(LOG_NORMAL, "Error broadcasting listener deletion: %v", err)
		}
	}

	logMessage(LOG_MINIMAL, "Listener %s deleted successfully and broadcast complete", listenerName)
	return nil
}
