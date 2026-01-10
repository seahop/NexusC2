// internal/rest/handlers/agents.go
package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

type AgentHandler struct {
	db *sql.DB
}

func NewAgentHandler(db *sql.DB) *AgentHandler {
	return &AgentHandler{db: db}
}

type Agent struct {
	ID             string     `json:"id"`             // Alias for NewClientID (standard REST convention)
	NewClientID    string     `json:"new_client_id"`  // Original GUID
	ClientID       string     `json:"client_id"`
	Protocol       string     `json:"protocol"`
	ExtIP          *string    `json:"ext_ip"`
	IntIP          *string    `json:"int_ip"`
	Username       *string    `json:"username"`
	Hostname       *string    `json:"hostname"`
	Process        *string    `json:"process"`
	PID            *string    `json:"pid"`
	Arch           string     `json:"arch"`
	OS             *string    `json:"os"`
	LastSeen       time.Time  `json:"last_seen"`
	Alias          *string    `json:"alias,omitempty"`
	ParentClientID *string    `json:"parent_client_id,omitempty"`
	LinkType       *string    `json:"link_type,omitempty"`
	Tags           []AgentTag `json:"tags,omitempty"`
}

type AgentTag struct {
	Name  string `json:"name"`
	Color string `json:"color"`
}

type UpdateAgentRequest struct {
	Alias string `json:"alias"`
}

type AddTagRequest struct {
	TagName  string `json:"tag_name" binding:"required"`
	TagColor string `json:"tag_color"`
}

// ListAgents returns all active agents
// GET /api/v1/agents
func (h *AgentHandler) ListAgents(c *gin.Context) {
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

	// Filter by active/all
	includeDeleted := c.Query("include_deleted") == "true"

	var query string
	var args []interface{}

	if includeDeleted {
		query = `
			SELECT newclientID, clientID, protocol, extIP, intIP, username,
			       hostname, process, pid, arch, os, lastSEEN, alias,
			       parent_clientID, link_type
			FROM connections
			ORDER BY lastSEEN DESC
			LIMIT $1 OFFSET $2
		`
		args = []interface{}{limit, offset}
	} else {
		query = `
			SELECT newclientID, clientID, protocol, extIP, intIP, username,
			       hostname, process, pid, arch, os, lastSEEN, alias,
			       parent_clientID, link_type
			FROM connections
			WHERE deleted_at IS NULL
			ORDER BY lastSEEN DESC
			LIMIT $1 OFFSET $2
		`
		args = []interface{}{limit, offset}
	}

	rows, err := h.db.QueryContext(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query agents"})
		return
	}
	defer rows.Close()

	agents := make([]Agent, 0)
	for rows.Next() {
		var a Agent
		err := rows.Scan(
			&a.NewClientID, &a.ClientID, &a.Protocol, &a.ExtIP, &a.IntIP,
			&a.Username, &a.Hostname, &a.Process, &a.PID, &a.Arch,
			&a.OS, &a.LastSeen, &a.Alias, &a.ParentClientID, &a.LinkType,
		)
		if err != nil {
			continue
		}

		// Set ID to NewClientID for standard REST convention
		a.ID = a.NewClientID

		// Load tags for this agent
		a.Tags = h.getAgentTags(ctx, a.NewClientID)
		agents = append(agents, a)
	}

	// Get total count
	var total int
	countQuery := "SELECT COUNT(*) FROM connections"
	if !includeDeleted {
		countQuery += " WHERE deleted_at IS NULL"
	}
	h.db.QueryRowContext(ctx, countQuery).Scan(&total)

	c.JSON(http.StatusOK, gin.H{
		"agents": agents,
		"pagination": gin.H{
			"page":  page,
			"limit": limit,
			"total": total,
		},
	})
}

// GetAgent returns a single agent by ID
// GET /api/v1/agents/:id
func (h *AgentHandler) GetAgent(c *gin.Context) {
	agentID := c.Param("id")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var a Agent
	err := h.db.QueryRowContext(ctx, `
		SELECT newclientID, clientID, protocol, extIP, intIP, username,
		       hostname, process, pid, arch, os, lastSEEN, alias,
		       parent_clientID, link_type
		FROM connections
		WHERE newclientID = $1
	`, agentID).Scan(
		&a.NewClientID, &a.ClientID, &a.Protocol, &a.ExtIP, &a.IntIP,
		&a.Username, &a.Hostname, &a.Process, &a.PID, &a.Arch,
		&a.OS, &a.LastSeen, &a.Alias, &a.ParentClientID, &a.LinkType,
	)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get agent"})
		return
	}

	// Set ID to NewClientID for standard REST convention
	a.ID = a.NewClientID
	a.Tags = h.getAgentTags(ctx, a.NewClientID)
	c.JSON(http.StatusOK, a)
}

// DeleteAgent soft deletes an agent
// DELETE /api/v1/agents/:id
func (h *AgentHandler) DeleteAgent(c *gin.Context) {
	agentID := c.Param("id")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	result, err := h.db.ExecContext(ctx, `
		UPDATE connections SET deleted_at = CURRENT_TIMESTAMP WHERE newclientID = $1
	`, agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete agent"})
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "agent deleted successfully"})
}

// UpdateAgent updates an agent's alias
// PATCH /api/v1/agents/:id
func (h *AgentHandler) UpdateAgent(c *gin.Context) {
	agentID := c.Param("id")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var req UpdateAgentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	result, err := h.db.ExecContext(ctx, `
		UPDATE connections SET alias = $2 WHERE newclientID = $1
	`, agentID, req.Alias)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update agent"})
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "agent updated successfully"})
}

// AddTag adds a tag to an agent
// POST /api/v1/agents/:id/tags
func (h *AgentHandler) AddTag(c *gin.Context) {
	agentID := c.Param("id")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var req AddTagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if req.TagColor == "" {
		req.TagColor = "#4A90E2"
	}

	_, err := h.db.ExecContext(ctx, `
		INSERT INTO agent_tags (agent_guid, tag_name, tag_color)
		VALUES ($1, $2, $3)
		ON CONFLICT (agent_guid, tag_name)
		DO UPDATE SET tag_color = EXCLUDED.tag_color
	`, agentID, req.TagName, req.TagColor)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add tag"})
		return
	}

	tags := h.getAgentTags(ctx, agentID)
	c.JSON(http.StatusOK, gin.H{
		"message": "tag added successfully",
		"tags":    tags,
	})
}

// RemoveTag removes a tag from an agent
// DELETE /api/v1/agents/:id/tags/:tag
func (h *AgentHandler) RemoveTag(c *gin.Context) {
	agentID := c.Param("id")
	tagName := c.Param("tag")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	_, err := h.db.ExecContext(ctx, `
		DELETE FROM agent_tags WHERE agent_guid = $1 AND tag_name = $2
	`, agentID, tagName)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove tag"})
		return
	}

	tags := h.getAgentTags(ctx, agentID)
	c.JSON(http.StatusOK, gin.H{
		"message": "tag removed successfully",
		"tags":    tags,
	})
}

func (h *AgentHandler) getAgentTags(ctx context.Context, agentID string) []AgentTag {
	rows, err := h.db.QueryContext(ctx, `
		SELECT tag_name, tag_color FROM agent_tags WHERE agent_guid = $1 ORDER BY tag_name
	`, agentID)
	if err != nil {
		return []AgentTag{}
	}
	defer rows.Close()

	tags := make([]AgentTag, 0)
	for rows.Next() {
		var t AgentTag
		if err := rows.Scan(&t.Name, &t.Color); err == nil {
			tags = append(tags, t)
		}
	}
	return tags
}
