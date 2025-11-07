// internal/websocket/handlers/agent_operations.go
package handlers

import (
	"c2/internal/websocket/hub"
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// handleRemoveAgent handles agent removal requests
func (h *WSHandler) handleRemoveAgent(_ *hub.Client, message []byte) error {
	var msg struct {
		Type string `json:"type"`
		Data struct {
			AgentID  string `json:"agent_id"`
			Username string `json:"username"`
		} `json:"data"`
	}

	if err := json.Unmarshal(message, &msg); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	query := `UPDATE connections SET deleted_at = CURRENT_TIMESTAMP WHERE newclientid = $1`
	if _, err := tx.ExecContext(ctx, query, msg.Data.AgentID); err != nil {
		return fmt.Errorf("failed to update connection: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	broadcastMsg := struct {
		Type string `json:"type"`
		Data struct {
			Event    string `json:"event"`
			AgentID  string `json:"agent_id"`
			Username string `json:"username"`
		} `json:"data"`
	}{
		Type: "agent_update",
		Data: struct {
			Event    string `json:"event"`
			AgentID  string `json:"agent_id"`
			Username string `json:"username"`
		}{
			Event:    "removed",
			AgentID:  msg.Data.AgentID,
			Username: msg.Data.Username,
		},
	}

	broadcastJSON, _ := json.Marshal(broadcastMsg)
	return h.hub.BroadcastToAll(ctx, broadcastJSON)
}

// handleRenameAgent handles agent rename requests
func (h *WSHandler) handleRenameAgent(client *hub.Client, message []byte) error {
	var msg struct {
		Type string `json:"type"`
		Data struct {
			AgentID string `json:"agent_id"`
			NewName string `json:"new_name"`
		} `json:"data"`
	}

	if err := json.Unmarshal(message, &msg); err != nil {
		return fmt.Errorf("failed to unmarshal rename request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Store alias in database (using PostgreSQL syntax)
	_, err := h.db.ExecContext(ctx, `
		UPDATE connections 
		SET alias = $2
		WHERE newclientID = $1
	`, msg.Data.AgentID, msg.Data.NewName)

	if err != nil {
		return fmt.Errorf("failed to save alias: %v", err)
	}

	// Broadcast rename to all connected clients
	broadcastMsg := struct {
		Type string `json:"type"`
		Data struct {
			AgentID string `json:"agent_id"`
			NewName string `json:"new_name"`
		} `json:"data"`
	}{
		Type: "agent_renamed",
		Data: struct {
			AgentID string `json:"agent_id"`
			NewName string `json:"new_name"`
		}{
			AgentID: msg.Data.AgentID,
			NewName: msg.Data.NewName,
		},
	}

	broadcastJSON, _ := json.Marshal(broadcastMsg)
	return h.hub.BroadcastToAll(ctx, broadcastJSON)
}
