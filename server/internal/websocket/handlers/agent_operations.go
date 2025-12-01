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

// Tag represents an agent tag
type Tag struct {
	Name  string `json:"name"`
	Color string `json:"color"`
}

// handleAddTag handles adding a tag to an agent
func (h *WSHandler) handleAddTag(client *hub.Client, message []byte) error {
	var msg struct {
		Type string `json:"type"`
		Data struct {
			AgentID  string `json:"agent_id"`
			TagName  string `json:"tag_name"`
			TagColor string `json:"tag_color"`
		} `json:"data"`
	}

	if err := json.Unmarshal(message, &msg); err != nil {
		return fmt.Errorf("failed to unmarshal add tag request: %v", err)
	}

	// Default color if not provided
	if msg.Data.TagColor == "" {
		msg.Data.TagColor = "#4A90E2"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Insert tag into database (ignore if already exists due to UNIQUE constraint)
	_, err := h.db.ExecContext(ctx, `
		INSERT INTO agent_tags (agent_guid, tag_name, tag_color)
		VALUES ($1, $2, $3)
		ON CONFLICT (agent_guid, tag_name)
		DO UPDATE SET tag_color = EXCLUDED.tag_color
	`, msg.Data.AgentID, msg.Data.TagName, msg.Data.TagColor)

	if err != nil {
		return fmt.Errorf("failed to add tag: %v", err)
	}

	// Fetch all tags for this agent to broadcast
	tags, err := h.getAgentTags(ctx, msg.Data.AgentID)
	if err != nil {
		return fmt.Errorf("failed to fetch agent tags: %v", err)
	}

	// Broadcast tag update to all connected clients
	return h.broadcastTagUpdate(ctx, msg.Data.AgentID, tags)
}

// handleRemoveTag handles removing a tag from an agent
func (h *WSHandler) handleRemoveTag(client *hub.Client, message []byte) error {
	var msg struct {
		Type string `json:"type"`
		Data struct {
			AgentID string `json:"agent_id"`
			TagName string `json:"tag_name"`
		} `json:"data"`
	}

	if err := json.Unmarshal(message, &msg); err != nil {
		return fmt.Errorf("failed to unmarshal remove tag request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Delete tag from database
	_, err := h.db.ExecContext(ctx, `
		DELETE FROM agent_tags
		WHERE agent_guid = $1 AND tag_name = $2
	`, msg.Data.AgentID, msg.Data.TagName)

	if err != nil {
		return fmt.Errorf("failed to remove tag: %v", err)
	}

	// Fetch remaining tags for this agent to broadcast
	tags, err := h.getAgentTags(ctx, msg.Data.AgentID)
	if err != nil {
		return fmt.Errorf("failed to fetch agent tags: %v", err)
	}

	// Broadcast tag update to all connected clients
	return h.broadcastTagUpdate(ctx, msg.Data.AgentID, tags)
}

// getAgentTags retrieves all tags for a specific agent
func (h *WSHandler) getAgentTags(ctx context.Context, agentID string) ([]Tag, error) {
	rows, err := h.db.QueryContext(ctx, `
		SELECT tag_name, tag_color
		FROM agent_tags
		WHERE agent_guid = $1
		ORDER BY tag_name ASC
	`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tags []Tag
	for rows.Next() {
		var tag Tag
		if err := rows.Scan(&tag.Name, &tag.Color); err != nil {
			return nil, err
		}
		tags = append(tags, tag)
	}

	return tags, rows.Err()
}

// broadcastTagUpdate broadcasts tag changes to all connected clients
func (h *WSHandler) broadcastTagUpdate(ctx context.Context, agentID string, tags []Tag) error {
	broadcastMsg := struct {
		Type string `json:"type"`
		Data struct {
			AgentID string `json:"agent_id"`
			Tags    []Tag  `json:"tags"`
		} `json:"data"`
	}{
		Type: "agent_tags_updated",
		Data: struct {
			AgentID string `json:"agent_id"`
			Tags    []Tag  `json:"tags"`
		}{
			AgentID: agentID,
			Tags:    tags,
		},
	}

	broadcastJSON, err := json.Marshal(broadcastMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal tag broadcast: %v", err)
	}

	return h.hub.BroadcastToAll(ctx, broadcastJSON)
}
