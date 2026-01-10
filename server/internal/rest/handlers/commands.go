// internal/rest/handlers/commands.go
package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"c2/internal/websocket/agent"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type CommandHandler struct {
	db          *sql.DB
	agentClient *agent.Client
}

func NewCommandHandler(db *sql.DB, agentClient *agent.Client) *CommandHandler {
	return &CommandHandler{
		db:          db,
		agentClient: agentClient,
	}
}

// SetAgentClient updates the gRPC client (for reconnection handling)
func (h *CommandHandler) SetAgentClient(client *agent.Client) {
	h.agentClient = client
}

type SendCommandRequest struct {
	Command string `json:"command" binding:"required"`
	Data    string `json:"data,omitempty"`
}

type Command struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	GUID      string    `json:"guid"`
	Command   string    `json:"command"`
	Timestamp time.Time `json:"timestamp"`
	Output    *string   `json:"output,omitempty"`
}

// SendCommand sends a command to an agent
// POST /api/v1/agents/:id/commands
func (h *CommandHandler) SendCommand(c *gin.Context) {
	agentID := c.Param("id")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var req SendCommandRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Get username from auth context
	username, _ := c.Get("username")
	usernameStr, _ := username.(string)
	if usernameStr == "" {
		usernameStr = "api"
	}

	// Verify agent exists
	var exists bool
	err := h.db.QueryRowContext(ctx, `
		SELECT EXISTS(SELECT 1 FROM connections WHERE newclientID = $1 AND deleted_at IS NULL)
	`, agentID).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	// Generate command ID
	commandID := uuid.New().String()
	timestamp := time.Now()

	// Store command in database
	var dbCommandID int
	err = h.db.QueryRowContext(ctx, `
		INSERT INTO commands (username, guid, command, timestamp)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`, usernameStr, agentID, req.Command, timestamp).Scan(&dbCommandID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store command"})
		return
	}

	// Send command via gRPC
	if h.agentClient != nil {
		payload := map[string]interface{}{
			"command":      req.Command,
			"agent_id":     agentID,
			"command_id":   commandID,
			"data":         req.Data,
			"timestamp":    timestamp.Format(time.RFC3339),
			"username":     usernameStr,
			"db_id":        dbCommandID,
		}

		if err := h.agentClient.SendToStream("agent_command", payload); err != nil {
			// Command stored but couldn't send - agent will pick it up on next check-in
			c.JSON(http.StatusAccepted, gin.H{
				"command_id": commandID,
				"db_id":      dbCommandID,
				"status":     "queued",
				"message":    "command queued, agent will receive on next check-in",
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"command_id": commandID,
		"db_id":      dbCommandID,
		"status":     "sent",
		"timestamp":  timestamp,
	})
}

// GetCommandHistory returns command history for an agent
// GET /api/v1/agents/:id/commands
func (h *CommandHandler) GetCommandHistory(c *gin.Context) {
	agentID := c.Param("id")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	// Pagination
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 50
	}
	offset := (page - 1) * limit

	rows, err := h.db.QueryContext(ctx, `
		SELECT c.id, c.username, c.guid, c.command, c.timestamp,
		       (SELECT output FROM command_outputs WHERE command_id = c.id ORDER BY timestamp DESC LIMIT 1)
		FROM commands c
		WHERE c.guid = $1
		ORDER BY c.timestamp DESC
		LIMIT $2 OFFSET $3
	`, agentID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query commands"})
		return
	}
	defer rows.Close()

	commands := make([]Command, 0)
	for rows.Next() {
		var cmd Command
		if err := rows.Scan(&cmd.ID, &cmd.Username, &cmd.GUID, &cmd.Command, &cmd.Timestamp, &cmd.Output); err == nil {
			commands = append(commands, cmd)
		}
	}

	// Get total count
	var total int
	h.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM commands WHERE guid = $1", agentID).Scan(&total)

	c.JSON(http.StatusOK, gin.H{
		"commands": commands,
		"pagination": gin.H{
			"page":  page,
			"limit": limit,
			"total": total,
		},
	})
}

// GetCommand returns a specific command with its output
// GET /api/v1/commands/:id
func (h *CommandHandler) GetCommand(c *gin.Context) {
	commandID := c.Param("id")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	id, err := strconv.Atoi(commandID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid command ID"})
		return
	}

	var cmd Command
	err = h.db.QueryRowContext(ctx, `
		SELECT id, username, guid, command, timestamp
		FROM commands WHERE id = $1
	`, id).Scan(&cmd.ID, &cmd.Username, &cmd.GUID, &cmd.Command, &cmd.Timestamp)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "command not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get command"})
		return
	}

	// Get all outputs for this command
	rows, err := h.db.QueryContext(ctx, `
		SELECT output, timestamp FROM command_outputs WHERE command_id = $1 ORDER BY timestamp ASC
	`, id)
	if err == nil {
		defer rows.Close()
		var outputs []struct {
			Output    string    `json:"output"`
			Timestamp time.Time `json:"timestamp"`
		}
		for rows.Next() {
			var o struct {
				Output    string    `json:"output"`
				Timestamp time.Time `json:"timestamp"`
			}
			if rows.Scan(&o.Output, &o.Timestamp) == nil {
				outputs = append(outputs, o)
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"command": cmd,
			"outputs": outputs,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"command": cmd,
		"outputs": []interface{}{},
	})
}

// GetLatestCommand returns the most recent command for an agent with its output
// GET /api/v1/agents/:id/commands/latest
func (h *CommandHandler) GetLatestCommand(c *gin.Context) {
	agentID := c.Param("id")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var cmd Command
	err := h.db.QueryRowContext(ctx, `
		SELECT id, username, guid, command, timestamp
		FROM commands WHERE guid = $1
		ORDER BY timestamp DESC
		LIMIT 1
	`, agentID).Scan(&cmd.ID, &cmd.Username, &cmd.GUID, &cmd.Command, &cmd.Timestamp)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "no commands found for agent"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get command"})
		return
	}

	// Get all outputs for this command
	rows, err := h.db.QueryContext(ctx, `
		SELECT output, timestamp FROM command_outputs WHERE command_id = $1 ORDER BY timestamp ASC
	`, cmd.ID)

	var outputs []struct {
		Output    string    `json:"output"`
		Timestamp time.Time `json:"timestamp"`
	}

	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var o struct {
				Output    string    `json:"output"`
				Timestamp time.Time `json:"timestamp"`
			}
			if rows.Scan(&o.Output, &o.Timestamp) == nil {
				outputs = append(outputs, o)
			}
		}
	}

	hasOutput := len(outputs) > 0
	status := "pending"
	if hasOutput {
		status = "completed"
	}

	c.JSON(http.StatusOK, gin.H{
		"command":    cmd,
		"outputs":    outputs,
		"has_output": hasOutput,
		"status":     status,
	})
}

// ClearQueue clears pending commands for an agent
// DELETE /api/v1/agents/:id/commands/queue
func (h *CommandHandler) ClearQueue(c *gin.Context) {
	agentID := c.Param("id")
	_, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	// Get username from auth context
	username, _ := c.Get("username")
	usernameStr, _ := username.(string)
	if usernameStr == "" {
		usernameStr = "api"
	}

	// Send clear command via gRPC
	if h.agentClient != nil {
		payload := map[string]interface{}{
			"command":    "clear",
			"agent_id":   agentID,
			"command_id": uuid.New().String(),
			"timestamp":  time.Now().Format(time.RFC3339),
			"username":   usernameStr,
		}

		if err := h.agentClient.SendToStream("agent_command", payload); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to clear queue"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "queue cleared"})
}

// Helper to parse command payload
func parsePayload(data interface{}) string {
	if data == nil {
		return ""
	}
	if s, ok := data.(string); ok {
		return s
	}
	b, _ := json.Marshal(data)
	return string(b)
}
